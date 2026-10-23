package pgauthzadm

// Test fixtures (tests.authz.yaml): the format, the runner and the JUnit
// report — the shared part of `pgauthzctl model test` and the console's
// saved scenarios. The runner creates an ephemeral store, imports the
// model, seeds the tuples, runs the assertions and drops the store, so a
// fixture is hermetic and repeatable wherever it runs.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

// Fixture is a tests.authz.yaml file — a superset of OpenFGA's store-test
// YAML, so existing OpenFGA tests port by renaming. pgauthz extensions are
// additive: per-check `context` (condition input), `contextual_tuples`, and
// `explain` golden reason paths. Exactly one of ModelFile / Model / Store
// names the model: a DSL or JSON file relative to the fixture (the caller
// resolves it into RunOptions.ModelJSON), a registry ref name[@version], or
// a live store whose CURRENT model is copied loss-free into the ephemeral
// store (conditions, gates and grant rules included — what the console's
// Scenarios and `pgauthzctl model test --store` do).
type Fixture struct {
	ModelFile string         `yaml:"model_file" json:"model_file,omitempty"`
	Model     string         `yaml:"model" json:"model,omitempty"`
	Store     string         `yaml:"store" json:"store,omitempty"`
	Tuples    []FixtureTuple `yaml:"tuples" json:"tuples"`
	Tests     []FixtureTest  `yaml:"tests" json:"tests"`
}

// FixtureTuple is a seeded or contextual tuple in OpenFGA notation.
type FixtureTuple struct {
	User      string         `yaml:"user" json:"user"`
	Relation  string         `yaml:"relation" json:"relation"`
	Object    string         `yaml:"object" json:"object"`
	Condition string         `yaml:"condition,omitempty" json:"condition,omitempty"`
	Context   map[string]any `yaml:"context,omitempty" json:"context,omitempty"`       // stored condition context
	ExpiresAt string         `yaml:"expires_at,omitempty" json:"expires_at,omitempty"` // server-time expiry (RFC3339)
}

// FixtureTest is one named scenario: checks, searches and explains. The
// description (and a case's) is free text for people — the reasoning, a
// requirement, a ticket — carried through unchanged, shown with a failure.
type FixtureTest struct {
	Name         string             `yaml:"name" json:"name"`
	Description  string             `yaml:"description,omitempty" json:"description,omitempty"`
	Check        []CheckCase        `yaml:"check,omitempty" json:"check,omitempty"`
	ListObjects  []ListCase         `yaml:"list_objects,omitempty" json:"list_objects,omitempty"`
	ListSubjects []ListSubjectsCase `yaml:"list_subjects,omitempty" json:"list_subjects,omitempty"`
	ListActions  []ListActionsCase  `yaml:"list_actions,omitempty" json:"list_actions,omitempty"`
	Explain      []ExplainCase      `yaml:"explain,omitempty" json:"explain,omitempty"`
}

// CheckCase asserts relations of one subject on one object. Notes are
// per assertion (relation → text): why this outcome is expected.
type CheckCase struct {
	User             string            `yaml:"user" json:"user"`
	Object           string            `yaml:"object" json:"object"`
	Assertions       map[string]bool   `yaml:"assertions" json:"assertions"`
	Notes            map[string]string `yaml:"notes,omitempty" json:"notes,omitempty"`
	Description      string            `yaml:"description,omitempty" json:"description,omitempty"`
	Context          map[string]any    `yaml:"context,omitempty" json:"context,omitempty"`
	ContextualTuples []FixtureTuple    `yaml:"contextual_tuples,omitempty" json:"contextual_tuples,omitempty"`
}

// ListCase asserts the objects of a type a subject reaches per relation.
// Contextual tuples take part in the search like stored ones (they seed
// and extend paths and the final decision sees them).
type ListCase struct {
	User             string              `yaml:"user" json:"user"`
	Type             string              `yaml:"type" json:"type"`
	Assertions       map[string][]string `yaml:"assertions" json:"assertions"` // relation → expected object refs
	Notes            map[string]string   `yaml:"notes,omitempty" json:"notes,omitempty"`
	Description      string              `yaml:"description,omitempty" json:"description,omitempty"`
	Context          map[string]any      `yaml:"context,omitempty" json:"context,omitempty"`
	ContextualTuples []FixtureTuple      `yaml:"contextual_tuples,omitempty" json:"contextual_tuples,omitempty"`
}

// ListSubjectsCase asserts the subjects of a type that reach an object per
// relation (the reverse search); a wildcard grant lists as type:*.
type ListSubjectsCase struct {
	Object           string              `yaml:"object" json:"object"`
	Type             string              `yaml:"type" json:"type"`             // the subject type to list
	Assertions       map[string][]string `yaml:"assertions" json:"assertions"` // relation → expected subject refs
	Notes            map[string]string   `yaml:"notes,omitempty" json:"notes,omitempty"`
	Description      string              `yaml:"description,omitempty" json:"description,omitempty"`
	Context          map[string]any      `yaml:"context,omitempty" json:"context,omitempty"`
	ContextualTuples []FixtureTuple      `yaml:"contextual_tuples,omitempty" json:"contextual_tuples,omitempty"`
}

// ListActionsCase asserts the full set of actions (the declared
// permissions) a subject may perform on an object — what authz.list_actions
// answers, so the assertion is "exactly these, nothing more".
type ListActionsCase struct {
	User             string         `yaml:"user" json:"user"`
	Object           string         `yaml:"object" json:"object"`
	Expect           []string       `yaml:"expect" json:"expect"` // the expected actions, as a set
	Description      string         `yaml:"description,omitempty" json:"description,omitempty"`
	Context          map[string]any `yaml:"context,omitempty" json:"context,omitempty"`
	ContextualTuples []FixtureTuple `yaml:"contextual_tuples,omitempty" json:"contextual_tuples,omitempty"`
}

// ExplainCase asserts the ordered reason codes of a resolution trace.
type ExplainCase struct {
	User          string   `yaml:"user" json:"user"`
	Relation      string   `yaml:"relation" json:"relation"`
	Object        string   `yaml:"object" json:"object"`
	ExpectReasons []string `yaml:"expect_reasons" json:"expect_reasons"`
	Description   string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// Result is one assertion's outcome; Test is the index of the FixtureTest
// it belongs to (the n-th entry under tests:), for callers that point back
// at the fixture.
type Result struct {
	Name   string `json:"name"`
	Failed bool   `json:"failed"`
	Detail string `json:"detail,omitempty"`
	Test   int    `json:"test"`
	Note   string `json:"note,omitempty"` // the assertion's note, else the case's or the test's description
	// What was asserted, structurally (the name is for people): the case
	// kind — check, list_objects, explain — and its subject, relation and
	// object (the object TYPE for list_objects), so a caller can point back
	// at the assertion in the fixture.
	Kind     string `json:"kind"`
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
	// Expected and Actual, structurally: ["true"]/["false"] for a check, the
	// sets for the list kinds, the reason codes for explain — for exports
	// that want columns rather than the name's text.
	Expected []string `json:"expected"`
	Actual   []string `json:"actual,omitempty"`
}

// RunReport is a fixture run: every assertion, the store it ran in (kept
// only when RunOptions.KeepStore), and how long it took.
type RunReport struct {
	Store    string        `json:"store"`
	Results  []Result      `json:"results"`
	Failed   int           `json:"failed"`
	Duration time.Duration `json:"duration"`
}

// RunOptions configures a fixture run.
type RunOptions struct {
	// ModelJSON is the model to import when the fixture names a model_file —
	// the caller resolves the file (ParseDSL for .fga, the bytes for .json);
	// ignored for a registry ref. One of ModelJSON / Model is required iff
	// Fixture.ModelFile is set.
	ModelJSON []byte
	// Model is the alternative to ModelJSON: a canonical model (ExportModel
	// of a store), rebuilt in the ephemeral store through RenderSQL — the
	// loss-free copy of a live store's model, conditions, gates and grant
	// rules included, which the OpenFGA JSON import cannot carry. For a
	// fixture naming a Store it is exported from that store when nil.
	Model *Model
	// Store is the ephemeral store's name; empty generates pgauthzadm_test_<hex>.
	Store string
	// KeepStore leaves the store in place for debugging.
	KeepStore bool
	// PurgeAudit drops the ephemeral store's audit rows with it (a run
	// leaves no trace in the audit tables); off, the rows stay as for any
	// deleted store.
	PurgeAudit bool
}

// ParseFixture parses a tests.authz.yaml and validates that exactly one of
// model_file / model is set.
func ParseFixture(raw []byte) (*Fixture, error) {
	var fix Fixture
	if err := UnmarshalFixture(raw, &fix); err != nil {
		return nil, err
	}
	if err := fix.Validate(); err != nil {
		return nil, err
	}
	return &fix, nil
}

// UnmarshalFixture parses the YAML without validating it — for callers that
// fill in a model of their own before Validate (the console tests a store's
// current model when the fixture names none).
func UnmarshalFixture(raw []byte, fix *Fixture) error {
	if err := yaml.Unmarshal(raw, fix); err != nil {
		return fmt.Errorf("parsing fixture: %w", err)
	}
	return nil
}

// Validate checks what the runner needs before touching the database.
func (f *Fixture) Validate() error {
	named := 0
	for _, v := range []string{f.ModelFile, f.Model, f.Store} {
		if v != "" {
			named++
		}
	}
	if named != 1 {
		return fmt.Errorf("exactly one of model_file / model (registry ref) / store (a live store's model) is required")
	}
	if f.Model != "" {
		if _, _, err := ParseModelRef(f.Model); err != nil {
			return err
		}
	}
	for i, t := range f.Tuples {
		if _, err := ParseRef(t.User); err != nil {
			return fmt.Errorf("tuples[%d]: %w", i, err)
		}
		if _, err := ParseRef(t.Object); err != nil {
			return fmt.Errorf("tuples[%d]: %w", i, err)
		}
		if t.Relation == "" {
			return fmt.Errorf("tuples[%d]: relation is required", i)
		}
	}
	for i, tc := range f.Tests {
		if tc.Name == "" {
			return fmt.Errorf("tests[%d]: name is required", i)
		}
	}
	return nil
}

// YAML renders the fixture as tests.authz.yaml.
func (f *Fixture) YAML() ([]byte, error) { return yaml.Marshal(f) }

// Ref is a parsed OpenFGA-notation entity reference:
//
//	"user:alice"        → {Type: user, ID: alice}
//	"user:*"            → {Type: user, ID: *}
//	"group:eng#member"  → {Type: group, ID: eng, Relation: member}  (userset)
type Ref struct {
	Type, ID, Relation string
}

// ParseRef parses type:id or type:id#relation.
func ParseRef(s string) (Ref, error) {
	var r Ref
	rest := s
	if i := strings.Index(rest, "#"); i >= 0 {
		r.Relation = rest[i+1:]
		rest = rest[:i]
	}
	i := strings.Index(rest, ":")
	if i <= 0 || i == len(rest)-1 {
		return r, fmt.Errorf("bad entity reference %q (want type:id or type:id#relation)", s)
	}
	r.Type, r.ID = rest[:i], rest[i+1:]
	return r, nil
}

// RunFixture runs the fixture in an ephemeral store on db and drops the
// store afterwards (unless opts.KeepStore). An error is returned only when
// the run itself could not proceed (store, model, seed); failed assertions
// are Results with Failed set, counted in RunReport.Failed. Checks with
// contextual_tuples need a connection role holding authz_contextual_reader
// (the injection API is deliberately gated).
func RunFixture(ctx context.Context, db DB, fix *Fixture, opts RunOptions) (*RunReport, error) {
	var report *RunReport
	err := WithFixture(ctx, db, fix, opts, func(store string) error {
		start := time.Now()
		report = &RunReport{Store: store, Results: []Result{}}
		for i, tc := range fix.Tests {
			for _, r := range runFixtureCase(ctx, db, store, tc) {
				r.Test = i
				report.Results = append(report.Results, r)
			}
		}
		for _, r := range report.Results {
			if r.Failed {
				report.Failed++
			}
		}
		report.Duration = time.Since(start)
		return nil
	})
	return report, err
}

// ExplainFixtureCheck sets the fixture up like RunFixture and, instead of
// the assertions, explains ONE check — the resolution tree of
// authz.explain_access for the case's subject and object and the relation,
// with the case's request context and contextual tuples — inside the
// fixture's world (its model, its tuples, nothing else). successfulOnly and
// redact are passed through.
func ExplainFixtureCheck(ctx context.Context, db DB, fix *Fixture, opts RunOptions, c CheckCase, relation string, successfulOnly, redact bool) (json.RawMessage, error) {
	u, err := ParseRef(c.User)
	if err != nil {
		return nil, err
	}
	o, err := ParseRef(c.Object)
	if err != nil {
		return nil, err
	}
	var ctxJSON []byte
	if c.Context != nil {
		ctxJSON, _ = json.Marshal(c.Context)
	}
	ctJSON, err := ContextualTuplesJSON(c.ContextualTuples)
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = WithFixture(ctx, db, fix, opts, func(store string) error {
		if ctJSON != nil {
			return db.QueryRow(ctx, "SELECT authz.explain_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)",
				store, u.Type, u.ID, relation, o.Type, o.ID, ctxJSON, ctJSON, successfulOnly, redact).Scan(&raw)
		}
		return db.QueryRow(ctx, "SELECT authz.explain_access($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)",
			store, u.Type, u.ID, relation, o.Type, o.ID, ctxJSON, successfulOnly, redact).Scan(&raw)
	})
	return raw, err
}

// ContextualTuplesJSON renders contextual tuples (OpenFGA notation) as the
// JSONB array the engine's *_with_contextual_tuples_jsonb functions take:
// [{"user_type","user_id","user_relation"?,"relation","object_type","object_id"}].
// nil for none, so a caller can branch on it.
func ContextualTuplesJSON(ts []FixtureTuple) ([]byte, error) {
	if len(ts) == 0 {
		return nil, nil
	}
	cts := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		tu, err := ParseRef(t.User)
		if err != nil {
			return nil, fmt.Errorf("contextual tuple user %q: %w", t.User, err)
		}
		to, err := ParseRef(t.Object)
		if err != nil {
			return nil, fmt.Errorf("contextual tuple object %q: %w", t.Object, err)
		}
		if t.Relation == "" {
			return nil, fmt.Errorf("contextual tuple %s → %s: relation is required", t.User, t.Object)
		}
		ct := map[string]any{
			"user_type": tu.Type, "user_id": tu.ID, "relation": t.Relation,
			"object_type": to.Type, "object_id": to.ID,
		}
		if tu.Relation != "" {
			ct["user_relation"] = tu.Relation
		}
		cts = append(cts, ct)
	}
	return json.Marshal(cts)
}

// WithFixture creates the ephemeral store, rebuilds the model in it and
// writes the fixture's tuples, then calls fn with the store's name; the
// store is dropped afterwards unless opts.KeepStore. RunFixture and
// ExplainFixtureCheck are built on it. Call it with a TRANSACTION (pgx.Tx):
// the run marks its store ephemeral through a transaction-local setting,
// and the whole run then commits or rolls back as one — the store never
// appears in the committed state (unless kept).
func WithFixture(ctx context.Context, db DB, fix *Fixture, opts RunOptions, fn func(store string) error) error {
	if err := fix.Validate(); err != nil {
		return err
	}
	if fix.ModelFile != "" && len(opts.ModelJSON) == 0 && opts.Model == nil {
		return fmt.Errorf("fixture names model_file %q: RunOptions.ModelJSON or Model is required", fix.ModelFile)
	}
	store := opts.Store
	if store == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		store = "pgauthzadm_test_" + hex.EncodeToString(b)
	}
	// Ephemeral: the store's types get no dedicated tuples partitions, so a
	// run is DML only — no DDL on the shared parent, no ACCESS EXCLUSIVE
	// lock that would stall every check in every store for the run's
	// duration, no catalog churn (model.sql, model_register_type). The
	// setting is transaction-local: db must be a transaction (the console
	// runs in one; the CLI opens one) for it to take effect.
	if _, err := db.Exec(ctx, "SELECT set_config('authz.ephemeral_store', 'on', true)"); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, "SELECT authz.create_store($1, 'fixture run')", store); err != nil {
		return err
	}
	if !opts.KeepStore {
		defer func() {
			_, _ = db.Exec(context.Background(), "SELECT authz.delete_store($1, p_purge_audit => $2)", store, opts.PurgeAudit)
		}()
	}

	model := opts.Model
	if fix.Store != "" && model == nil {
		m, err := ExportModel(ctx, db, fix.Store)
		if err != nil {
			return fmt.Errorf("model of store %s: %w", fix.Store, err)
		}
		model = m
	}
	switch {
	case model != nil && fix.Model == "":
		// no arguments: pgx sends the script in one simple-protocol round
		// trip, statement by statement, as psql would
		if _, err := db.Exec(ctx, RenderSQL(store, model)); err != nil {
			return err
		}
	case fix.ModelFile != "":
		if _, err := ImportModel(ctx, db, store, opts.ModelJSON); err != nil {
			return err
		}
	default:
		name, version, _ := ParseModelRef(fix.Model)
		if _, err := db.Exec(ctx, "SELECT authz.apply_model($1, $2, $3)", store, name, VersionArg(version)); err != nil {
			return err
		}
	}
	for _, t := range fix.Tuples {
		if err := writeFixtureTuple(ctx, db, store, t); err != nil {
			return fmt.Errorf("fixture tuple %s %s %s: %w", t.User, t.Relation, t.Object, err)
		}
	}
	return fn(store)
}

func writeFixtureTuple(ctx context.Context, db DB, store string, t FixtureTuple) error {
	u, err := ParseRef(t.User)
	if err != nil {
		return err
	}
	o, err := ParseRef(t.Object)
	if err != nil {
		return err
	}
	var condCtx []byte
	if t.Context != nil {
		condCtx, _ = json.Marshal(t.Context)
	}
	_, err = db.Exec(ctx, `SELECT authz.write_tuple($1,$2,$3,$4,$5,$6,
	                           p_user_relation := nullif($7,''),
	                           p_condition := nullif($8,''),
	                           p_condition_context := $9,
	                           p_expires_at := nullif($10,'')::timestamptz)`,
		store, u.Type, u.ID, t.Relation, o.Type, o.ID, u.Relation, t.Condition, condCtx, t.ExpiresAt)
	return err
}

func runFixtureCase(ctx context.Context, db DB, store string, tc FixtureTest) []Result {
	var out []Result
	note := tc.Description
	var at Result // the current assertion's kind/user/relation/object
	fail := func(name, detail string) {
		out = append(out, Result{Name: name, Failed: true, Detail: detail, Note: note, Kind: at.Kind, User: at.User, Relation: at.Relation, Object: at.Object, Expected: at.Expected, Actual: at.Actual})
	}
	pass := func(name string) {
		out = append(out, Result{Name: name, Note: note, Kind: at.Kind, User: at.User, Relation: at.Relation, Object: at.Object, Expected: at.Expected, Actual: at.Actual})
	}
	first := func(ss ...string) string {
		for _, s := range ss {
			if s != "" {
				return s
			}
		}
		return ""
	}

	for _, c := range tc.Check {
		at = Result{Kind: "check", User: c.User, Object: c.Object}
		u, err := ParseRef(c.User)
		if err != nil {
			fail(tc.Name+"/check", err.Error())
			continue
		}
		o, err := ParseRef(c.Object)
		if err != nil {
			fail(tc.Name+"/check", err.Error())
			continue
		}
		for _, rel := range sortedKeys(c.Assertions) {
			want := c.Assertions[rel]
			name := fmt.Sprintf("%s: %s %s %s = %v", tc.Name, c.User, rel, c.Object, want)
			at.Relation = rel
			note = first(c.Notes[rel], c.Description, tc.Description)
			got, err := runFixtureCheck(ctx, db, store, u, rel, o, c)
			at.Expected, at.Actual = []string{fmt.Sprint(want)}, nil
			if err != nil {
				fail(name, err.Error())
				continue
			}
			at.Actual = []string{fmt.Sprint(got)}
			if got != want {
				fail(name, fmt.Sprintf("got %v", got))
			} else {
				pass(name)
			}
		}
	}

	for _, l := range tc.ListObjects {
		at = Result{Kind: "list_objects", User: l.User, Object: l.Type}
		u, err := ParseRef(l.User)
		if err != nil {
			fail(tc.Name+"/list_objects", err.Error())
			continue
		}
		for _, rel := range sortedKeys(l.Assertions) {
			want := l.Assertions[rel]
			name := fmt.Sprintf("%s: list %s %s for %s = %s", tc.Name, l.Type, rel, l.User, setText(want))
			at.Relation = rel
			note = first(l.Notes[rel], l.Description, tc.Description)
			var ctxJSON []byte
			if l.Context != nil {
				ctxJSON, _ = json.Marshal(l.Context)
			}
			ctJSON, err := ContextualTuplesJSON(l.ContextualTuples)
			if err != nil {
				fail(name, err.Error())
				continue
			}
			var rows pgx.Rows
			if ctJSON != nil {
				rows, err = db.Query(ctx,
					"SELECT object_id FROM authz.list_objects_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7)",
					store, u.Type, u.ID, rel, l.Type, ctxJSON, ctJSON)
			} else {
				rows, err = db.Query(ctx,
					"SELECT object_id FROM authz.list_objects($1,$2,$3,$4,$5,$6)",
					store, u.Type, u.ID, rel, l.Type, ctxJSON)
			}
			if err != nil {
				fail(name, err.Error())
				continue
			}
			got := map[string]bool{}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err == nil {
					got[l.Type+":"+id] = true
				}
			}
			rows.Close()
			at.Expected, at.Actual = sortedCopy(want), keysOf(got)
			if !sameSet(got, want) {
				fail(name, fmt.Sprintf("expected %s, got %s", setText(want), setText(keysOf(got))))
			} else {
				pass(name)
			}
		}
	}

	for _, l := range tc.ListSubjects {
		at = Result{Kind: "list_subjects", User: l.Type, Object: l.Object}
		o, err := ParseRef(l.Object)
		if err != nil {
			fail(tc.Name+"/list_subjects", err.Error())
			continue
		}
		for _, rel := range sortedKeys(l.Assertions) {
			want := l.Assertions[rel]
			name := fmt.Sprintf("%s: subjects %s %s on %s = %s", tc.Name, l.Type, rel, l.Object, setText(want))
			at.Relation = rel
			note = first(l.Notes[rel], l.Description, tc.Description)
			var ctxJSON []byte
			if l.Context != nil {
				ctxJSON, _ = json.Marshal(l.Context)
			}
			ctJSON, err := ContextualTuplesJSON(l.ContextualTuples)
			if err != nil {
				fail(name, err.Error())
				continue
			}
			var rows pgx.Rows
			if ctJSON != nil {
				rows, err = db.Query(ctx,
					"SELECT subject_id, is_wildcard FROM authz.list_subjects_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7)",
					store, l.Type, rel, o.Type, o.ID, ctxJSON, ctJSON)
			} else {
				rows, err = db.Query(ctx,
					"SELECT subject_id, is_wildcard FROM authz.list_subjects($1,$2,$3,$4,$5,$6)",
					store, l.Type, rel, o.Type, o.ID, ctxJSON)
			}
			if err != nil {
				fail(name, err.Error())
				continue
			}
			got := map[string]bool{}
			for rows.Next() {
				var id string
				var wild bool
				if err := rows.Scan(&id, &wild); err == nil {
					got[l.Type+":"+id] = true
				}
			}
			rows.Close()
			at.Expected, at.Actual = sortedCopy(want), keysOf(got)
			if !sameSet(got, want) {
				fail(name, fmt.Sprintf("expected %s, got %s", setText(want), setText(keysOf(got))))
			} else {
				pass(name)
			}
		}
	}

	var perms map[string]bool // the model's declared permissions, loaded once a list_actions case needs them
	for _, a := range tc.ListActions {
		at = Result{Kind: "list_actions", User: a.User, Object: a.Object}
		if perms == nil {
			p, err := permissionNames(ctx, db, store)
			if err != nil {
				fail(fmt.Sprintf("%s: actions of %s on %s", tc.Name, a.User, a.Object), "relation kinds: "+err.Error())
				continue
			}
			perms = p
		}
		name := fmt.Sprintf("%s: actions of %s on %s = %s", tc.Name, a.User, a.Object, actionsText(a.Expect, perms))
		note = first(a.Description, tc.Description)
		u, err1 := ParseRef(a.User)
		o, err2 := ParseRef(a.Object)
		if err1 != nil || err2 != nil {
			fail(name, "bad reference")
			continue
		}
		var ctxJSON []byte
		if a.Context != nil {
			ctxJSON, _ = json.Marshal(a.Context)
		}
		ctJSON, err := ContextualTuplesJSON(a.ContextualTuples)
		if err != nil {
			fail(name, err.Error())
			continue
		}
		var rows pgx.Rows
		if ctJSON != nil {
			rows, err = db.Query(ctx,
				"SELECT action FROM authz.list_actions_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7)",
				store, u.Type, u.ID, o.Type, o.ID, ctxJSON, ctJSON)
		} else {
			rows, err = db.Query(ctx,
				"SELECT action FROM authz.list_actions($1,$2,$3,$4,$5,$6)",
				store, u.Type, u.ID, o.Type, o.ID, ctxJSON)
		}
		if err != nil {
			fail(name, err.Error())
			continue
		}
		got := map[string]bool{}
		for rows.Next() {
			var action string
			if err := rows.Scan(&action); err == nil {
				got[action] = true
			}
		}
		rows.Close()
		at.Expected, at.Actual = sortedCopy(a.Expect), keysOf(got)
		if !sameSet(got, a.Expect) {
			fail(name, fmt.Sprintf("expected %s, got %s", actionsText(a.Expect, perms), actionsText(keysOf(got), perms)))
		} else {
			pass(name)
		}
	}

	for _, e := range tc.Explain {
		at = Result{Kind: "explain", User: e.User, Relation: e.Relation, Object: e.Object}
		u, err1 := ParseRef(e.User)
		o, err2 := ParseRef(e.Object)
		name := fmt.Sprintf("%s: explain %s %s %s", tc.Name, e.User, e.Relation, e.Object)
		note = first(e.Description, tc.Description)
		if err1 != nil || err2 != nil {
			fail(name, "bad reference")
			continue
		}
		var explain struct {
			Trace []struct {
				Reason string `json:"reason"`
			} `json:"trace"`
		}
		if err := QueryJSON(ctx, db, &explain,
			"SELECT authz.explain_access($1,$2,$3,$4,$5,$6)",
			store, u.Type, u.ID, e.Relation, o.Type, o.ID); err != nil {
			fail(name, err.Error())
			continue
		}
		var reasons []string
		for _, t := range explain.Trace {
			reasons = append(reasons, t.Reason)
		}
		at.Expected, at.Actual = e.ExpectReasons, reasons
		if fmt.Sprint(reasons) != fmt.Sprint(e.ExpectReasons) {
			fail(name, fmt.Sprintf("expected reasons %v, got %v", e.ExpectReasons, reasons))
		} else {
			pass(name)
		}
	}
	return out
}

// setText — a set as "[a, b, c]", sorted, for result names and details.
func setText(items []string) string {
	s := append([]string(nil), items...)
	sort.Strings(s)
	return "[" + strings.Join(s, ", ") + "]"
}

// permissionNames — the relations the model declares as permissions
// (metadata kind), so an action set can be read as "may …" (what the
// subject can do) next to "is …" (the relations it holds). Empty when the
// model declares no kinds (an OpenFGA-style model), and the set stays flat.
//
// Plain table reads through the public stores table (no internal helper
// such as authz._s, which a service role may not execute); an error is
// returned, never swallowed — inside a transaction a failed statement
// aborts it, and a silent one would surface as "commit unexpectedly
// resulted in rollback" much later.
func permissionNames(ctx context.Context, db DB, store string) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := db.Query(ctx, `SELECT r.name FROM authz.relations r JOIN authz.stores s ON s.id = r.store_id
	                             WHERE s.name = $1 AND r.metadata->>'kind' = 'permission'`, store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// actionsText — an action set as "may [perms] · is [relations]" when the
// model declares kinds, else "[all]".
func actionsText(items []string, perms map[string]bool) string {
	if len(perms) == 0 {
		return setText(items)
	}
	var may, is []string
	for _, x := range items {
		if perms[x] {
			may = append(may, x)
		} else {
			is = append(is, x)
		}
	}
	return "may " + setText(may) + " · is " + setText(is)
}

func sortedCopy(items []string) []string {
	s := append([]string(nil), items...)
	sort.Strings(s)
	return s
}

// sameSet — got (a set) equals want (a list, duplicates ignored).
func sameSet(got map[string]bool, want []string) bool {
	w := map[string]bool{}
	for _, x := range want {
		w[x] = true
	}
	if len(w) != len(got) {
		return false
	}
	for k := range w {
		if !got[k] {
			return false
		}
	}
	return true
}

func keysOf(m map[string]bool) []string { return sortedKeys(m) }

// sortedKeys — the assertions of a case in a stable order (a map has none),
// so results, their ids and the CLI's lines come out the same every run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func runFixtureCheck(ctx context.Context, db DB, store string, u Ref, rel string, o Ref, c CheckCase) (bool, error) {
	var ctxJSON []byte
	if c.Context != nil {
		ctxJSON, _ = json.Marshal(c.Context)
	}
	var allowed bool
	ctJSON, err := ContextualTuplesJSON(c.ContextualTuples)
	if err != nil {
		return false, err
	}
	if ctJSON != nil {
		err := db.QueryRow(ctx,
			"SELECT authz.check_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7,$8)",
			store, u.Type, u.ID, rel, o.Type, o.ID, ctxJSON, ctJSON).Scan(&allowed)
		return allowed, err
	}
	if c.Context != nil {
		err := db.QueryRow(ctx,
			"SELECT authz.check_access_with_context($1,$2,$3,$4,$5,$6,$7)",
			store, u.Type, u.ID, rel, o.Type, o.ID, ctxJSON).Scan(&allowed)
		return allowed, err
	}
	err = db.QueryRow(ctx,
		"SELECT authz.check_access($1,$2,$3,$4,$5,$6)",
		store, u.Type, u.ID, rel, o.Type, o.ID).Scan(&allowed)
	return allowed, err
}

// --- JUnit ---

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Time     float64     `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
}

// JUnit renders a run as a JUnit XML testsuite named suiteName, for CI.
func JUnit(suiteName string, report *RunReport) ([]byte, error) {
	s := junitSuite{Name: suiteName, Tests: len(report.Results), Time: report.Duration.Seconds()}
	for _, r := range report.Results {
		c := junitCase{Name: r.Name}
		if r.Failed {
			s.Failures++
			c.Failure = &junitFailure{Message: r.Detail}
		}
		s.Cases = append(s.Cases, c)
	}
	out, err := xml.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}
