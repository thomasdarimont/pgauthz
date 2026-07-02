// Package server is the playground BFF HTTP layer: OIDC login, server-side
// sessions, query forwarding to OPA, and read-only engine metadata for the SPA.
package server

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/playground-bff/internal/config"
	"thomasdarimont.de/authz/playground-bff/internal/oidc"
)

// Server holds the BFF dependencies shared by all handlers.
type Server struct {
	cfg       config.Config
	db        *pgxpool.Pool
	engineDB  *pgxpool.Pool // read-only; nil if ENGINE_DSN unset (autocomplete off)
	http      *http.Client
	oidc      *oidc.Client  // confidential-client token exchange
	endpoints oidc.Metadata // discovered authorize/token/logout URLs
}

// New wires up a Server. engineDB may be nil (metadata/explore then disabled).
func New(cfg config.Config, db, engineDB *pgxpool.Pool, hc *http.Client, oc *oidc.Client, ep oidc.Metadata) *Server {
	return &Server{cfg: cfg, db: db, engineDB: engineDB, http: hc, oidc: oc, endpoints: ep}
}

// Routes builds the HTTP handler, registering every route under the configured
// base path (e.g. /playground) so the app can sit alongside others on one host.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	bp := s.cfg.BasePath
	h := func(pattern string, fn http.HandlerFunc) {
		if i := strings.IndexByte(pattern, ' '); i >= 0 { // "GET /x" → "GET <bp>/x"
			mux.HandleFunc(pattern[:i+1]+bp+pattern[i+1:], fn)
		} else {
			mux.HandleFunc(bp+pattern, fn)
		}
	}
	h("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	h("GET /auth/login", s.handleLogin)
	h("GET /auth/callback", s.handleCallback)
	h("GET /auth/logout", s.handleLogout)
	h("GET /api/me", s.handleMe)
	h("GET /api/meta/stores", s.metaRoute(false,
		`SELECT name FROM authz.stores WHERE deleted_at IS NULL ORDER BY name`))
	h("GET /api/meta/relations", s.metaRoute(true,
		`SELECT r.name FROM authz.relations r JOIN authz.stores s ON s.id=r.store_id WHERE s.name=$1 ORDER BY r.name`))
	h("GET /api/meta/subjects", s.metaRoute(true,
		`SELECT DISTINCT ut.name FROM authz.tuples t JOIN authz.stores s ON s.id=t.store_id
		 JOIN authz.types ut ON ut.id=t.user_type AND ut.store_id=s.id WHERE s.name=$1 ORDER BY ut.name`))
	h("GET /api/meta/objects", s.metaRoute(true,
		`SELECT DISTINCT ot.name FROM authz.tuples t JOIN authz.stores s ON s.id=t.store_id
		 JOIN authz.types ot ON ot.id=t.object_type AND ot.store_id=s.id WHERE s.name=$1 ORDER BY ot.name`))
	h("GET /api/model", s.handleModel)
	h("GET /api/tuples", s.handleTuples)
	h("GET /api/conditions", s.handleConditions)
	h("GET /api/meta/types", s.handleTypes)
	h("POST /api/explore/check", s.handleExploreCheck)
	h("POST /api/explore/explain", s.handleExploreExplain)
	h("POST /api/q", s.handleQuery)
	// AuthZEN console: proxy to the authzen-opa service with the session token.
	h("GET /api/authzen/config", s.authzenProxy("GET", "/.well-known/authzen-configuration"))
	h("POST /api/authzen/evaluation", s.authzenProxy("POST", "/access/v1/evaluation"))
	h("POST /api/authzen/evaluations", s.authzenProxy("POST", "/access/v1/evaluations"))
	h("POST /api/authzen/search/subject", s.authzenProxy("POST", "/access/v1/search/subject"))
	h("POST /api/authzen/search/resource", s.authzenProxy("POST", "/access/v1/search/resource"))
	h("POST /api/authzen/search/action", s.authzenProxy("POST", "/access/v1/search/action"))
	mux.HandleFunc(bp+"/", s.handleStatic)
	if bp != "" { // bare root → the app's base path
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, bp+"/", http.StatusFound)
		})
	}
	return mux
}
