package server

import (
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"thomasdarimont.de/authz/pgauthzadm"
)

// handleRollout — the store's managed-model state, the registry versions of
// its model (or all models, for an unmanaged store), and the fleet view.
func (s *Server) handleRollout(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	ctx := r.Context()
	st, err := pgauthzadm.ModelStatus(ctx, s.engine, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	name := ""
	if st.ModelName != nil {
		name = *st.ModelName
	}
	// Whoever may roll out sees the registry's models to pick from on an
	// unmanaged store; everyone else sees the versions of the store's own
	// model only (nothing on an unmanaged store).
	canRollout, err := s.can(ctx, p, "can_rollout", "store", store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	versions := []pgauthzadm.Version{}
	if name != "" || canRollout {
		if versions, err = pgauthzadm.ListVersions(ctx, s.engine, name); err != nil {
			writeEngineError(w, err)
			return
		}
	}
	var fleet []pgauthzadm.RolloutRow
	if name != "" {
		if fleet, err = pgauthzadm.RolloutStatus(ctx, s.engine, name); err != nil {
			writeEngineError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": st, "versions": versions, "fleet": fleet, "can_rollout": canRollout})
}

type publishReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handlePublish — snapshot the store's live model as the next registry
// version. Needs the store's can_publish AND the registry's can_publish.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_publish")
	if p == nil {
		return
	}
	if s.require(w, r, "can_publish", "registry", s.cfg.RegistryID) == nil {
		return
	}
	var req publishReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validName.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "model name must match ^[a-zA-Z_][a-zA-Z0-9_]*$")
		return
	}
	var version int
	err := s.asPerson(r.Context(), p, "can_publish", "store", store, map[string]any{"model": req.Name, "description": req.Description}, func(tx pgx.Tx) error {
		var err error
		version, err = pgauthzadm.Publish(r.Context(), tx, req.Name, store, req.Description)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "version": version})
}

type applyReq struct {
	Name    string `json:"name"`
	Version int    `json:"version"` // 0 = latest
}

// handlePlan — dry run: what applying a registry version would change. A
// plan reads the version's definition, so it needs the right to roll out.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_rollout")
	if p == nil {
		return
	}
	var req applyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	plan, err := pgauthzadm.PlanApply(r.Context(), s.engine, store, req.Name, req.Version)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	// Besides "what applying changes in the live model", say what the version
	// itself changes against the version the store runs (or the live model when
	// unmanaged): after publishing from this store the plan is a no-op, and the
	// person still wants to see what @N+1 contains.
	var since []pgauthzadm.Change
	var sinceLabel string
	target, terr := pgauthzadm.GetModelVersion(r.Context(), s.engine, req.Name, req.Version)
	if terr == nil {
		st, serr := pgauthzadm.ModelStatus(r.Context(), s.engine, store)
		switch {
		case serr == nil && st.ModelName != nil && *st.ModelName == req.Name && st.ModelVersion != nil && *st.ModelVersion != req.Version:
			if base, err := pgauthzadm.GetModelVersion(r.Context(), s.engine, req.Name, *st.ModelVersion); err == nil {
				since = pgauthzadm.DiffModels(base, target)
				sinceLabel = fmt.Sprintf("%s@%d", req.Name, *st.ModelVersion)
			}
		case serr == nil && st.ModelName != nil && *st.ModelName == req.Name:
			// same version as applied: the plan already says it all
		default:
			if live, err := pgauthzadm.ExportModel(r.Context(), s.engine, store); err == nil {
				since = pgauthzadm.DiffModels(live, target)
				sinceLabel = "live"
			}
		}
	}
	if since == nil {
		since = []pgauthzadm.Change{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "changes": plan.Changes(), "blockers": plan.Blockers(), "can_apply": plan.CanApply(),
		"since": since, "since_label": sinceLabel})
}

// handleApply — make the store match a registry version (the rollout step).
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_rollout")
	if p == nil {
		return
	}
	var req applyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	var applied int
	err := s.asPerson(r.Context(), p, "can_rollout", "store", store, map[string]any{"model": req.Name, "version": req.Version}, func(tx pgx.Tx) error {
		var err error
		applied, err = pgauthzadm.Apply(r.Context(), tx, store, req.Name, req.Version)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": req.Name, "version": applied})
}
