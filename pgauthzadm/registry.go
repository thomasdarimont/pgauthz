package pgauthzadm

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ParseModelRef splits "name" or "name@version" (version 0 = latest).
func ParseModelRef(s string) (name string, version int, err error) {
	if i := strings.Index(s, "@"); i >= 0 {
		name = s[:i]
		if _, e := fmt.Sscanf(s[i+1:], "%d", &version); e != nil || version <= 0 {
			return "", 0, fmt.Errorf("bad model reference %q (want name or name@version)", s)
		}
		return name, version, nil
	}
	if s == "" {
		return "", 0, fmt.Errorf("empty model reference")
	}
	return s, 0, nil
}

// VersionArg maps "latest" (0) to SQL NULL for the registry functions.
func VersionArg(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

// Status is a store's managed-model state (authz.model_status). ModelName is
// nil for an unmanaged store (never had a registry version applied).
type Status struct {
	Store            string     `json:"store"`
	ModelName        *string    `json:"model_name"`
	ModelVersion     *int       `json:"model_version"`
	AppliedAt        *time.Time `json:"applied_at"`
	AppliedBy        *string    `json:"applied_by"`
	InSync           *bool      `json:"in_sync"`
	LiveChecksum     string     `json:"live_checksum"`
	ExpectedChecksum *string    `json:"expected_checksum"`
}

// Managed reports whether the store runs a registry version.
func (s Status) Managed() bool { return s.ModelName != nil }

func ModelStatus(ctx context.Context, db DB, store string) (*Status, error) {
	st := Status{Store: store}
	var live *string
	err := db.QueryRow(ctx, `SELECT model_name, model_version, applied_at, applied_by, in_sync, live_checksum, expected_checksum
	                           FROM authz.model_status($1)`, store).
		Scan(&st.ModelName, &st.ModelVersion, &st.AppliedAt, &st.AppliedBy, &st.InSync, &live, &st.ExpectedChecksum)
	if err != nil {
		return nil, err
	}
	if live != nil {
		st.LiveChecksum = *live
	}
	return &st, nil
}

// Version is one immutable registry entry (authz.list_model_versions).
type Version struct {
	Name        string    `json:"name"`
	Version     int       `json:"version"`
	Checksum    string    `json:"checksum"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// ListVersions lists registry versions, all models when name is empty.
func ListVersions(ctx context.Context, db DB, name string) ([]Version, error) {
	var arg any
	if name != "" {
		arg = name
	}
	rows, err := db.Query(ctx, `SELECT name, version, checksum, COALESCE(description,''), created_at, COALESCE(created_by,'')
	                              FROM authz.list_model_versions($1)`, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		var v Version
		if err := rows.Scan(&v.Name, &v.Version, &v.Checksum, &v.Description, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Plan is the dry-run verdict of applying a registry version to a store
// (authz.plan_model_apply), kept as the engine's JSON document; Changes and
// Blockers flatten it for display.
type Plan map[string]any

func PlanApply(ctx context.Context, db DB, store, name string, version int) (Plan, error) {
	var plan Plan
	err := QueryJSON(ctx, db, &plan, "SELECT authz.plan_model_apply($1, $2, $3)", store, name, VersionArg(version))
	return plan, err
}

// CanApply reports the plan's verdict.
func (p Plan) CanApply() bool { return p["can_apply"] == true }

// NoOp reports whether the live model already matches the target.
func (p Plan) NoOp() bool { return p["no_op"] == true }

// Change is one planned difference: Op is add, update or remove; Section is
// types, relations, rules, type_restrictions or conditions.
type Change struct {
	Op      string `json:"op"`
	Section string `json:"section"`
	Item    any    `json:"item"`
}

// Changes flattens the plan's per-section add/update/remove lists, in the
// order the engine would apply them.
func (p Plan) Changes() []Change {
	changes, _ := p["changes"].(map[string]any)
	var out []Change
	for _, section := range []string{"types", "relations", "rules", "type_restrictions", "conditions", "gates", "grant_rules", "relation_constraints"} {
		sec, _ := changes[section].(map[string]any)
		for _, op := range []string{"add", "update", "remove"} {
			items, _ := sec[op].([]any)
			for _, it := range items {
				out = append(out, Change{Op: op, Section: section, Item: it})
			}
		}
	}
	return out
}

// Blockers lists why the apply would be refused (empty when it can run).
func (p Plan) Blockers() []any {
	b, _ := p["blockers"].([]any)
	return b
}

// Publish snapshots a store's live model as the next version of name
// (authz.publish_model). Idempotent: an unchanged model returns the existing
// latest version.
func Publish(ctx context.Context, db DB, name, fromStore, description string) (int, error) {
	var desc any
	if description != "" {
		desc = description
	}
	var v int
	err := db.QueryRow(ctx, "SELECT authz.publish_model($1, $2, $3)", name, fromStore, desc).Scan(&v)
	return v, err
}

// Apply makes one store match a registry version (0 = latest); returns the
// version applied.
func Apply(ctx context.Context, db DB, store, name string, version int) (int, error) {
	var applied int
	err := db.QueryRow(ctx, "SELECT authz.apply_model($1, $2, $3)", store, name, VersionArg(version)).Scan(&applied)
	return applied, err
}

// Applied is one store of a fleet apply.
type Applied struct {
	Store   string `json:"store"`
	Version int    `json:"version"`
}

// ApplyMany applies a registry version to several stores in one transaction.
func ApplyMany(ctx context.Context, db DB, stores []string, name string, version int) ([]Applied, error) {
	rows, err := db.Query(ctx, "SELECT store, version FROM authz.apply_model($1::text[], $2, $3)", stores, name, VersionArg(version))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Applied
	for rows.Next() {
		var a Applied
		if err := rows.Scan(&a.Store, &a.Version); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RolloutRow is one store in a model's fleet view (authz.model_rollout_status).
type RolloutRow struct {
	Store         string     `json:"store"`
	ModelVersion  int        `json:"model_version"`
	LatestVersion int        `json:"latest_version"`
	InSync        bool       `json:"in_sync"`
	AppliedAt     *time.Time `json:"applied_at"`
}

// Outdated reports whether a newer version exists than the one applied.
func (r RolloutRow) Outdated() bool { return r.ModelVersion < r.LatestVersion }

func RolloutStatus(ctx context.Context, db DB, name string) ([]RolloutRow, error) {
	rows, err := db.Query(ctx, `SELECT store, model_version, latest_version, in_sync, applied_at
	                              FROM authz.model_rollout_status($1)`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RolloutRow{}
	for rows.Next() {
		var r RolloutRow
		if err := rows.Scan(&r.Store, &r.ModelVersion, &r.LatestVersion, &r.InSync, &r.AppliedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
