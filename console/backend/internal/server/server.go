// Package server is the console BFF's HTTP layer: OIDC login, server-side
// sessions, the console-store authorization gate, and the store management
// API the Lit SPA calls.
package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"thomasdarimont.de/authz/console-bff/internal/config"
	"thomasdarimont.de/authz/console-bff/internal/oidc"
)

// Version identifies the running console build (shown in the UI footer).
type Version struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	BuiltAt  string `json:"built_at,omitempty"`
	Go       string `json:"go"`
}

// Server holds the BFF dependencies shared by all handlers.
type Server struct {
	version   Version
	cfg       config.Config
	db        *pgxpool.Pool // sessions
	engine    *pgxpool.Pool // pgauthz, as authz_console
	http      *http.Client
	oidc      *oidc.Client
	endpoints oidc.Metadata
}

// New wires up a Server.
func New(cfg config.Config, db, engine *pgxpool.Pool, hc *http.Client, oc *oidc.Client, ep oidc.Metadata) *Server {
	return &Server{cfg: cfg, db: db, engine: engine, http: hc, oidc: oc, endpoints: ep}
}

// SetVersion records the build identity served at /api/version.
func (s *Server) SetVersion(v Version) { s.version = v }

// AwaitEngine waits until the engine answers and the console store exists —
// the BFF may start before init.sh ran, and nothing works without its own
// authorization store.
func AwaitEngine(ctx context.Context, engine *pgxpool.Pool, store string) error {
	var lastErr error
	for attempt := 1; attempt <= 60; attempt++ {
		var n int
		err := engine.QueryRow(ctx, `SELECT count(*) FROM authz.stores WHERE name = $1`, store).Scan(&n)
		switch {
		case err != nil:
			lastErr = err
		case n == 0:
			lastErr = fmt.Errorf("console store %q does not exist (load examples/models/console/model.sql + seed.sql)", store)
		default:
			return nil
		}
		log.Printf("engine not ready (attempt %d): %v", attempt, lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("engine: %w", lastErr)
}

// Routes builds the HTTP handler; every route sits under the base path.
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
	h("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	h("GET /auth/login", s.handleLogin)
	h("GET /auth/callback", s.handleCallback)
	h("GET /auth/logout", s.handleLogout)
	h("GET /api/me", s.handleMe)
	// Build identity, public: the footer shows it on the login page too.
	h("GET /api/version", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.version) })
	// Translation overrides, public like the SPA that needs them before login.
	h("GET /api/i18n", s.handleI18nList)
	h("GET /api/i18n/{lang}", s.handleI18n)

	// Stores home
	h("GET /api/stores", s.handleStores)
	h("POST /api/stores", s.handleCreateStore)
	h("POST /api/stores/{store}/adopt", s.handleAdoptStore)
	h("GET /api/stores/{store}", s.handleStore)
	h("POST /api/stores/{store}/delete", s.handleDeleteStore)
	h("POST /api/stores/{store}/settings", s.handleStoreSettings)

	// Model
	h("GET /api/stores/{store}/model", s.handleModel)
	h("POST /api/stores/{store}/model/batch", s.handleModelBatch)
	h("POST /api/stores/{store}/model/dsl", s.handleModelDSL)
	h("POST /api/stores/{store}/model/{op}", s.handleModelEdit)

	// Data
	h("GET /api/stores/{store}/tuples", s.handleTuples)
	h("GET /api/stores/{store}/tuples/stats", s.handleTupleStats)
	h("POST /api/stores/{store}/tuples", s.handleWriteTuple)
	h("POST /api/stores/{store}/tuples/delete", s.handleDeleteTuple)

	// Test
	h("GET /api/stores/{store}/meta", s.handleMeta)
	h("POST /api/stores/{store}/check", s.handleCheck)
	h("POST /api/stores/{store}/explain", s.handleExplain)
	h("POST /api/stores/{store}/check/batch", s.handleCheckBatch)
	h("POST /api/stores/{store}/search", s.handleSearch)
	h("POST /api/stores/{store}/decide", s.handleDecide)
	h("POST /api/stores/{store}/conditions/{name}/evaluate", s.handleEvaluateCondition)

	// Rollout
	h("GET /api/stores/{store}/rollout", s.handleRollout)
	h("POST /api/stores/{store}/publish", s.handlePublish)
	h("POST /api/stores/{store}/plan", s.handlePlan)
	h("POST /api/stores/{store}/apply", s.handleApply)

	// Activity
	h("GET /api/stores/{store}/activity", s.handleActivity)

	// Access (who may manage this store in the console)
	h("GET /api/stores/{store}/access", s.handleAccess)
	h("POST /api/stores/{store}/access", s.handleAccessAdd)
	h("POST /api/stores/{store}/access/remove", s.handleAccessRemove)
	h("GET /api/stores/{store}/policies", s.handlePolicies)
	h("GET /api/stores/{store}/namespaces", s.handleNamespaces)
	h("POST /api/stores/{store}/namespaces/{ns}/access", s.handleNamespaceAccessAdd)
	h("POST /api/stores/{store}/namespaces/{ns}/access/remove", s.handleNamespaceAccessRemove)
	h("POST /api/stores/{store}/namespaces/{ns}/rename", s.handleNamespaceRename)

	// Platform areas
	h("GET /api/registry", s.handleRegistry)
	h("GET /api/platform", s.handlePlatform)
	h("GET /api/platform/access", s.handlePlatformAccess)
	h("POST /api/platform/access", s.handlePlatformAccessAdd)
	h("POST /api/platform/access/remove", s.handlePlatformAccessRemove)

	mux.HandleFunc(bp+"/", s.handleStatic)
	if bp != "" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, bp+"/", http.StatusFound)
		})
	}
	return mux
}
