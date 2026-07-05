package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

// Fixture file format — a superset of OpenFGA's store-test YAML, so existing
// OpenFGA tests port by renaming. pgauthz extensions are additive: per-check
// `context` (condition input), `contextual_tuples`, and `explain` golden
// reason paths.
type fixture struct {
	ModelFile string      `yaml:"model_file"` // .fga / .json, relative to the fixture
	Model     string      `yaml:"model"`      // or a registry ref: name[@version]
	Tuples    []tupleYAML `yaml:"tuples"`
	Tests     []testCase  `yaml:"tests"`
}

type tupleYAML struct {
	User      string         `yaml:"user"`
	Relation  string         `yaml:"relation"`
	Object    string         `yaml:"object"`
	Condition string         `yaml:"condition"`
	Context   map[string]any `yaml:"context"`    // stored condition context
	ExpiresAt string         `yaml:"expires_at"` // server-time expiry (RFC3339)
}

type testCase struct {
	Name        string        `yaml:"name"`
	Check       []checkCase   `yaml:"check"`
	ListObjects []listCase    `yaml:"list_objects"`
	Explain     []explainCase `yaml:"explain"`
}

type checkCase struct {
	User             string          `yaml:"user"`
	Object           string          `yaml:"object"`
	Assertions       map[string]bool `yaml:"assertions"`
	Context          map[string]any  `yaml:"context"`
	ContextualTuples []tupleYAML     `yaml:"contextual_tuples"`
}

type listCase struct {
	User       string              `yaml:"user"`
	Type       string              `yaml:"type"`
	Assertions map[string][]string `yaml:"assertions"` // relation → expected object refs
	Context    map[string]any      `yaml:"context"`
}

type explainCase struct {
	User          string   `yaml:"user"`
	Relation      string   `yaml:"relation"`
	Object        string   `yaml:"object"`
	ExpectReasons []string `yaml:"expect_reasons"` // ordered trace reason codes
}

type result struct {
	Name   string
	Failed bool
	Detail string
}

func cmdTest(args []string) error {
	fs, dsn := newFlags("model test")
	junit := fs.String("junit", "", "write JUnit XML to this path")
	keep := fs.Bool("keep-store", false, "keep the ephemeral store for debugging")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: authzctl model test <tests.authz.yaml> [--junit out.xml]")
	}
	fixPath := pos[0]

	raw, err := os.ReadFile(fixPath)
	if err != nil {
		return err
	}
	var fix fixture
	if err := yaml.Unmarshal(raw, &fix); err != nil {
		return fmt.Errorf("parsing %s: %w", fixPath, err)
	}
	if (fix.ModelFile == "") == (fix.Model == "") {
		return fmt.Errorf("%s: exactly one of model_file / model (registry ref) is required", fixPath)
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	// Ephemeral store per run: fixtures are hermetic and repeatable.
	b := make([]byte, 4)
	rand.Read(b)
	store := "authzctl_test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "SELECT authz.create_store($1, 'authzctl model test')", store); err != nil {
		return err
	}
	if !*keep {
		defer conn.Exec(context.Background(), "SELECT authz.delete_store($1)", store)
	} else {
		defer fmt.Println("kept store:", store)
	}

	if fix.ModelFile != "" {
		modelJSON, warnings, err := loadModelJSON(filepath.Join(filepath.Dir(fixPath), fix.ModelFile))
		if err != nil {
			return err
		}
		for _, w := range warnings {
			fmt.Println("WARN:", w)
		}
		var report map[string]any
		if err := queryJSON(ctx, conn, &report,
			"SELECT authz.import_openfga_model($1, $2::jsonb)", store, modelJSON); err != nil {
			return err
		}
	} else {
		name, version, err := parseModelRef(fix.Model)
		if err != nil {
			return err
		}
		if _, err := conn.Exec(ctx,
			"SELECT authz.apply_model($1, $2, $3)", store, name, versionArg(version)); err != nil {
			return err
		}
	}

	for _, t := range fix.Tuples {
		if err := writeTuple(ctx, conn, store, t); err != nil {
			return fmt.Errorf("fixture tuple %v: %w", t, err)
		}
	}

	var results []result
	start := time.Now()
	for _, tc := range fix.Tests {
		results = append(results, runCase(ctx, conn, store, tc)...)
	}

	failed := 0
	for _, r := range results {
		if r.Failed {
			failed++
			fmt.Printf("    FAIL  %s  (%s)\n", r.Name, r.Detail)
		} else {
			fmt.Printf("    PASS  %s\n", r.Name)
		}
	}
	fmt.Printf("\n==> %d passed, %d failed (of %d checks)\n", len(results)-failed, failed, len(results))

	if *junit != "" {
		if err := writeJUnit(*junit, fixPath, results, time.Since(start)); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d fixture checks failed", failed)
	}
	return nil
}

func writeTuple(ctx context.Context, conn *pgx.Conn, store string, t tupleYAML) error {
	u, err := parseRef(t.User)
	if err != nil {
		return err
	}
	o, err := parseRef(t.Object)
	if err != nil {
		return err
	}
	var condCtx []byte
	if t.Context != nil {
		condCtx, _ = json.Marshal(t.Context)
	}
	_, err = conn.Exec(ctx, `SELECT authz.write_tuple($1,$2,$3,$4,$5,$6,
	                             p_user_relation := nullif($7,''),
	                             p_condition := nullif($8,''),
	                             p_condition_context := $9,
	                             p_expires_at := nullif($10,'')::timestamptz)`,
		store, u.Type, u.ID, t.Relation, o.Type, o.ID, u.Relation, t.Condition, condCtx, t.ExpiresAt)
	return err
}

func runCase(ctx context.Context, conn *pgx.Conn, store string, tc testCase) []result {
	var out []result
	fail := func(name, detail string) { out = append(out, result{name, true, detail}) }
	pass := func(name string) { out = append(out, result{name, false, ""}) }

	for _, c := range tc.Check {
		u, err := parseRef(c.User)
		if err != nil {
			fail(tc.Name+"/check", err.Error())
			continue
		}
		o, err := parseRef(c.Object)
		if err != nil {
			fail(tc.Name+"/check", err.Error())
			continue
		}
		for rel, want := range c.Assertions {
			name := fmt.Sprintf("%s: %s %s %s = %v", tc.Name, c.User, rel, c.Object, want)
			got, err := runCheck(ctx, conn, store, u, rel, o, c)
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
		u, err := parseRef(l.User)
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
			rows, err := conn.Query(ctx,
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
		u, err1 := parseRef(e.User)
		o, err2 := parseRef(e.Object)
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
		if err := queryJSON(ctx, conn, &explain,
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

func runCheck(ctx context.Context, conn *pgx.Conn, store string, u ref, rel string, o ref, c checkCase) (bool, error) {
	var ctxJSON []byte
	if c.Context != nil {
		ctxJSON, _ = json.Marshal(c.Context)
	}

	if len(c.ContextualTuples) > 0 {
		// NOTE: needs a DSN whose role holds authz_contextual_reader (or a
		// superuser test database) — the injection API is deliberately gated.
		cts := make([]map[string]any, 0, len(c.ContextualTuples))
		for _, t := range c.ContextualTuples {
			tu, err := parseRef(t.User)
			if err != nil {
				return false, err
			}
			to, err := parseRef(t.Object)
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
		var allowed bool
		err := conn.QueryRow(ctx,
			"SELECT authz.check_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7,$8)",
			store, u.Type, u.ID, rel, o.Type, o.ID, ctxJSON, ctJSON).Scan(&allowed)
		return allowed, err
	}

	if c.Context != nil {
		var allowed bool
		err := conn.QueryRow(ctx,
			"SELECT authz.check_access_with_context($1,$2,$3,$4,$5,$6,$7)",
			store, u.Type, u.ID, rel, o.Type, o.ID, ctxJSON).Scan(&allowed)
		return allowed, err
	}

	var allowed bool
	err := conn.QueryRow(ctx,
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

func writeJUnit(path, suiteName string, results []result, dur time.Duration) error {
	s := junitSuite{Name: suiteName, Tests: len(results), Time: dur.Seconds()}
	for _, r := range results {
		c := junitCase{Name: r.Name}
		if r.Failed {
			s.Failures++
			c.Failure = &junitFailure{Message: r.Detail}
		}
		s.Cases = append(s.Cases, c)
	}
	out, err := xml.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(xml.Header), out...), 0o644)
}
