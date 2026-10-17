package server

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"thomasdarimont.de/authz/pgauthzadm"
)

// handleRegistry — every model name with its versions and fleet view.
func (s *Server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_view", "registry", s.cfg.RegistryID)
	if p == nil {
		return
	}
	ctx := r.Context()
	versions, err := pgauthzadm.ListVersions(ctx, s.engine, "")
	if err != nil {
		writeEngineError(w, err)
		return
	}
	type model struct {
		Name     string                  `json:"name"`
		Versions []pgauthzadm.Version    `json:"versions"`
		Fleet    []pgauthzadm.RolloutRow `json:"fleet"`
	}
	byName := map[string]*model{}
	order := []string{}
	for _, v := range versions {
		m, ok := byName[v.Name]
		if !ok {
			m = &model{Name: v.Name}
			byName[v.Name] = m
			order = append(order, v.Name)
		}
		m.Versions = append(m.Versions, v)
	}
	models := []model{}
	for _, name := range order {
		m := byName[name]
		if fleet, err := pgauthzadm.RolloutStatus(ctx, s.engine, name); err == nil {
			m.Fleet = fleet
		}
		models = append(models, *m)
	}
	canPublish, _ := s.can(ctx, p, "can_publish", "registry", s.cfg.RegistryID)
	writeJSON(w, http.StatusOK, map[string]any{"models": models, "can_publish": canPublish})
}

// handlePlatform — the Settings page: how this console is wired and whether
// the engine (and, if configured, a pgauthzd) answer.
func (s *Server) handlePlatform(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_view_health", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	engine := map[string]any{"ok": false}
	var version, role string
	var stores int
	if err := s.engine.QueryRow(ctx, `SELECT version(), current_user, (SELECT count(*) FROM authz.stores)`).Scan(&version, &role, &stores); err == nil {
		engine = map[string]any{"ok": true, "version": version, "role": role, "stores": stores}
	} else {
		engine["error"] = err.Error()
	}
	var pgauthzd map[string]any
	if s.cfg.PgauthzdURL != "" {
		pgauthzd = map[string]any{"url": s.cfg.PgauthzdURL, "ok": false}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.PgauthzdURL+"/readyz", nil)
		if resp, err := s.http.Do(req); err == nil {
			resp.Body.Close()
			pgauthzd["ok"] = resp.StatusCode == http.StatusOK
			pgauthzd["status"] = resp.StatusCode
		} else {
			pgauthzd["error"] = err.Error()
		}
	}
	claims := []map[string]string{}
	for _, tc := range s.cfg.TeamClaims {
		claims = append(claims, map[string]string{"prefix": tc.Prefix, "claim": tc.Path})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"environment":   s.cfg.DeploymentEnvironment,
		"issuer":        s.cfg.Issuer,
		"client_id":     s.cfg.ClientID,
		"console_store": s.cfg.ConsoleStore,
		"platform_id":   s.cfg.PlatformID,
		"registry_id":   s.cfg.RegistryID,
		"subject_type":  s.cfg.SubjectType,
		"team_claims":   claims,
		"engine":        engine,
		"pgauthzd":      pgauthzd,
	})
}

func (s *Server) handlePlatformAccess(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_view_health", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	list, err := s.accessList(r.Context(), "platform", s.cfg.PlatformID, platformRoles)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	manage, _ := s.can(r.Context(), p, "can_manage_access", "platform", s.cfg.PlatformID)
	writeJSON(w, http.StatusOK, map[string]any{"access": list, "roles": platformRoles, "can_manage": manage, "teams": p.teams})
}

func (s *Server) handlePlatformAccessAdd(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	req, ok := s.accessInput(w, r, platformRoles)
	if !ok {
		return
	}
	err := s.asPerson(r.Context(), p, "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "add", "access": req}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `SELECT authz.write_tuple($1, $2, $3, $4, 'platform', $5, $6)`,
			s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, s.cfg.PlatformID, nullable(req.SubjectRelation))
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformAccessRemove(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	items, ok := s.accessRemoveInput(w, r, platformRoles)
	if !ok {
		return
	}
	ctx := r.Context()
	err := s.asPerson(ctx, p, "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "remove", "items": items}, func(tx pgx.Tx) error {
		for _, req := range items {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple($1, $2, $3, $4, 'platform', $5, $6)`,
				s.cfg.ConsoleStore, req.SubjectType, req.SubjectID, req.Role, s.cfg.PlatformID, nullable(req.SubjectRelation)); err != nil {
				return err
			}
		}
		return s.ensureOwner(ctx, tx, "platform", s.cfg.PlatformID)
	})
	if err != nil {
		if err == errLastOwner {
			writeError(w, http.StatusConflict, "the platform needs at least one admin — add another admin first")
			return
		}
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
