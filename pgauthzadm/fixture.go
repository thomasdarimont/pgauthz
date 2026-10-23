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
	"strings"
	"time"

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

// FixtureTest is one named scenario: checks, searches and explains.
type FixtureTest struct {
	Name        string        `yaml:"name" json:"name"`
	Check       []CheckCase   `yaml:"check,omitempty" json:"check,omitempty"`
	ListObjects []ListCase    `yaml:"list_objects,omitempty" json:"list_objects,omitempty"`
	Explain     []ExplainCase `yaml:"explain,omitempty" json:"explain,omitempty"`
}

// CheckCase asserts relations of one subject on one object.
type CheckCase struct {
	User             string          `yaml:"user" json:"user"`
	Object           string          `yaml:"object" json:"object"`
	Assertions       map[string]bool `yaml:"assertions" json:"assertions"`
	Context          map[string]any  `yaml:"context,omitempty" json:"context,omitempty"`
	ContextualTuples []FixtureTuple  `yaml:"contextual_tuples,omitempty" json:"contextual_tuples,omitempty"`
}

// ListCase asserts the objects of a type a subject reaches per relation.
type ListCase struct {
	User       string              `yaml:"user" json:"user"`
	Type       string              `yaml:"type" json:"type"`
	Assertions map[string][]string `yaml:"assertions" json:"assertions"` // relation → expected object refs
	Context    map[string]any      `yaml:"context,omitempty" json:"context,omitempty"`
}

// ExplainCase asserts the ordered reason codes of a resolution trace.
type ExplainCase struct {
	User          string   `yaml:"user" json:"user"`
	Relation      string   `yaml:"relation" json:"relation"`
	Object        string   `yaml:"object" json:"object"`
	ExpectReasons []string `yaml:"expect_reasons" json:"expect_reasons"`
}

// Result is one assertion's outcome.
type Result struct {
	Name   string `json:"name"`
	Failed bool   `json:"failed"`
	Detail string `json:"detail,omitempty"`
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
	if err := fix.Validate(); err != nil {
		return nil, err
	}
	if fix.ModelFile != "" && len(opts.ModelJSON) == 0 && opts.Model == nil {
		return nil, fmt.Errorf("fixture names model_file %q: RunOptions.ModelJSON or Model is required", fix.ModelFile)
	}
	store := opts.Store
	if store == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		store = "pgauthzadm_test_" + hex.EncodeToString(b)
	}
	if _, err := db.Exec(ctx, "SELECT authz.create_store($1, 'fixture run')", store); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("model of store %s: %w", fix.Store, err)
		}
		model = m
	}
	switch {
	case model != nil && fix.Model == "":
		// no arguments: pgx sends the script in one simple-protocol round
		// trip, statement by statement, as psql would
		if _, err := db.Exec(ctx, RenderSQL(store, model)); err != nil {
			return nil, err
		}
	case fix.ModelFile != "":
		if _, err := ImportModel(ctx, db, store, opts.ModelJSON); err != nil {
			return nil, err
		}
	default:
		name, version, _ := ParseModelRef(fix.Model)
		if _, err := db.Exec(ctx, "SELECT authz.apply_model($1, $2, $3)", store, name, VersionArg(version)); err != nil {
			return nil, err
		}
	}
	for _, t := range fix.Tuples {
		if err := writeFixtureTuple(ctx, db, store, t); err != nil {
			return nil, fmt.Errorf("fixture tuple %s %s %s: %w", t.User, t.Relation, t.Object, err)
		}
	}

	start := time.Now()
	report := &RunReport{Store: store, Results: []Result{}}
	for _, tc := range fix.Tests {
		report.Results = append(report.Results, runFixtureCase(ctx, db, store, tc)...)
	}
	for _, r := range report.Results {
		if r.Failed {
			report.Failed++
		}
	}
	report.Duration = time.Since(start)
	return report, nil
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
	fail := func(name, detail string) { out = append(out, Result{name, true, detail}) }
	pass := func(name string) { out = append(out, Result{name, false, ""}) }

	for _, c := range tc.Check {
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
		for rel, want := range c.Assertions {
			name := fmt.Sprintf("%s: %s %s %s = %v", tc.Name, c.User, rel, c.Object, want)
			got, err := runFixtureCheck(ctx, db, store, u, rel, o, c)
			if err != nil {
				fail(name, err.Error())
			} else if got != want {
				fail(name, fmt.Sprintf("got %v", got))
			} else {
				pass(name)
			}
		}
	}

	for _, l := range tc.ListObjects {
		u, err := ParseRef(l.User)
		if err != nil {
			fail(tc.Name+"/list_objects", err.Error())
			continue
		}
		for rel, want := range l.Assertions {
			name := fmt.Sprintf("%s: list %s %s for %s", tc.Name, l.Type, rel, l.User)
			var ctxJSON []byte
			if l.Context != nil {
				ctxJSON, _ = json.Marshal(l.Context)
			}
			rows, err := db.Query(ctx,
				"SELECT object_id FROM authz.list_objects($1,$2,$3,$4,$5,$6)",
				store, u.Type, u.ID, rel, l.Type, ctxJSON)
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
			ok := len(got) == len(want)
			for _, w := range want {
				if !got[w] {
					ok = false
				}
			}
			if !ok {
				gotList := make([]string, 0, len(got))
				for k := range got {
					gotList = append(gotList, k)
				}
				fail(name, fmt.Sprintf("expected %v, got %v", want, gotList))
			} else {
				pass(name)
			}
		}
	}

	for _, e := range tc.Explain {
		u, err1 := ParseRef(e.User)
		o, err2 := ParseRef(e.Object)
		name := fmt.Sprintf("%s: explain %s %s %s", tc.Name, e.User, e.Relation, e.Object)
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
		if fmt.Sprint(reasons) != fmt.Sprint(e.ExpectReasons) {
			fail(name, fmt.Sprintf("expected reasons %v, got %v", e.ExpectReasons, reasons))
		} else {
			pass(name)
		}
	}
	return out
}

func runFixtureCheck(ctx context.Context, db DB, store string, u Ref, rel string, o Ref, c CheckCase) (bool, error) {
	var ctxJSON []byte
	if c.Context != nil {
		ctxJSON, _ = json.Marshal(c.Context)
	}
	var allowed bool
	if len(c.ContextualTuples) > 0 {
		cts := make([]map[string]any, 0, len(c.ContextualTuples))
		for _, t := range c.ContextualTuples {
			tu, err := ParseRef(t.User)
			if err != nil {
				return false, err
			}
			to, err := ParseRef(t.Object)
			if err != nil {
				return false, err
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
		ctJSON, _ := json.Marshal(cts)
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
	err := db.QueryRow(ctx,
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
