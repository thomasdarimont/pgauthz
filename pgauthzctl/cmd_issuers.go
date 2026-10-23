package main

// Issuer bindings as code (scratch design option C, ADR 0016): what each
// trusted identity provider's tokens may do — stores, DB roles, client
// roles, PEP clients, enabled — lives in authz.issuer_bindings and is
// applied by every pgauthzd running ISSUERS_SOURCE=env+db. Trust itself
// (issuer, audience, keys) stays in JWT_ISSUERS. These verbs keep the rows
// in git: export them, review the diff, import them back (an upsert per
// issuer; --prune removes rows the file no longer names). Validation is the
// engine's; a row the environment does not trust or that widens a binding
// is reported by the instances, not applied.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// issuerStore is what the verbs need: the rows and their revision, an
// upsert, a delete — over the admin API (the long-run transport) or the
// database (installation-time, break-glass).
type issuerStore interface {
	list(ctx context.Context) ([]issuerBinding, int64, error)
	set(ctx context.Context, b issuerBinding, performedBy string) (int64, error)
	delete(ctx context.Context, issuer, performedBy string) (bool, error)
	close(ctx context.Context)
}

// openIssuerStore picks the transport: --server wins; else --dsn.
func openIssuerStore(ctx context.Context, sf serverFlags, dsn string) (issuerStore, error) {
	if sf.set() {
		c, err := newAdminClient(sf)
		if err != nil {
			return nil, err
		}
		return &apiIssuerStore{c: c}, nil
	}
	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("%w — or use the admin API: --server (PGAUTHZ_SERVER) with --token or --cert/--key", err)
	}
	return &dbIssuerStore{conn: conn}, nil
}

// dbIssuerStore runs the engine's functions on a connection (or, inside an
// import, on its transaction: q is the executor).
type dbIssuerStore struct {
	conn *pgx.Conn
	q    interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}
}

func (s *dbIssuerStore) exec() interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
} {
	if s.q != nil {
		return s.q
	}
	return s.conn
}

func (s *dbIssuerStore) list(ctx context.Context) ([]issuerBinding, int64, error) {
	rows, err := readIssuerBindings(ctx, s.conn)
	if err != nil {
		return nil, 0, err
	}
	var rev int64
	if err := s.conn.QueryRow(ctx, `SELECT authz.issuer_bindings_revision()`).Scan(&rev); err != nil {
		return nil, 0, err
	}
	return rows, rev, nil
}

func (s *dbIssuerStore) set(ctx context.Context, b issuerBinding, by string) (int64, error) {
	cdr, _ := json.Marshal(b.ClientDBRoles)
	pep, _ := json.Marshal(b.PEPClients)
	var desc any
	if b.Description != "" {
		desc = b.Description
	}
	var rev int64
	err := s.exec().QueryRow(ctx, `SELECT authz.set_issuer_binding($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
		b.Issuer, b.Stores, b.DBRoles, string(cdr), string(pep), b.Enabled, desc, by).Scan(&rev)
	return rev, err
}

func (s *dbIssuerStore) delete(ctx context.Context, issuer, by string) (bool, error) {
	var existed bool
	err := s.exec().QueryRow(ctx, `SELECT authz.delete_issuer_binding($1, $2)`, issuer, by).Scan(&existed)
	return existed, err
}

func (s *dbIssuerStore) close(ctx context.Context) { s.conn.Close(ctx) }

// apiIssuerStore: the admin API's issuer-bindings resource. The actor is the
// credential's; performedBy is not sent.
type apiIssuerStore struct{ c *adminClient }

func (s *apiIssuerStore) list(ctx context.Context) ([]issuerBinding, int64, error) {
	var rows struct {
		Bindings []issuerBinding `json:"bindings"`
	}
	if err := s.c.do(ctx, "GET", "/pgauthz/v1/admin/issuer-bindings", nil, &rows); err != nil {
		return nil, 0, err
	}
	var eff struct {
		Revision int64 `json:"revision"`
	}
	if err := s.c.do(ctx, "GET", "/pgauthz/v1/admin/issuers", nil, &eff); err != nil {
		return nil, 0, err
	}
	out := make([]issuerBinding, 0, len(rows.Bindings))
	for _, b := range rows.Bindings {
		out = append(out, normalizeBinding(b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issuer < out[j].Issuer })
	return out, eff.Revision, nil
}

func (s *apiIssuerStore) set(ctx context.Context, b issuerBinding, _ string) (int64, error) {
	var res struct {
		Revision int64 `json:"revision"`
	}
	b.CreatedAt, b.CreatedBy, b.UpdatedAt, b.UpdatedBy = nil, "", nil, ""
	if err := s.c.do(ctx, "PUT", "/pgauthz/v1/admin/issuer-bindings", b, &res); err != nil {
		return 0, err
	}
	return res.Revision, nil
}

func (s *apiIssuerStore) delete(ctx context.Context, issuer, _ string) (bool, error) {
	err := s.c.do(ctx, "DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer="+url.QueryEscape(issuer), nil, nil)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == 404 {
		return false, nil
	}
	return err == nil, err
}

func (s *apiIssuerStore) close(context.Context) {}

// issuerBinding is one row, the JSON shape of the export file (the same
// fields the admin API and the console use).
type issuerBinding struct {
	Issuer        string              `json:"issuer"`
	Stores        []string            `json:"stores"`
	DBRoles       []string            `json:"db_roles"`
	ClientDBRoles map[string]string   `json:"client_db_roles"`
	PEPClients    map[string][]string `json:"pep_clients"`
	Enabled       bool                `json:"enabled"`
	Description   string              `json:"description,omitempty"`
	CreatedAt     *time.Time          `json:"created_at,omitempty"`
	CreatedBy     string              `json:"created_by,omitempty"`
	UpdatedAt     *time.Time          `json:"updated_at,omitempty"`
	UpdatedBy     string              `json:"updated_by,omitempty"`
}

func readIssuerBindings(ctx context.Context, conn *pgx.Conn) ([]issuerBinding, error) {
	rows, err := conn.Query(ctx, `
		SELECT issuer, stores, db_roles, client_db_roles, pep_clients, enabled, coalesce(description, ''),
		       created_at, coalesce(created_by, ''), updated_at, coalesce(updated_by, '')
		  FROM authz.list_issuer_bindings()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []issuerBinding{}
	for rows.Next() {
		var b issuerBinding
		if err := rows.Scan(&b.Issuer, &b.Stores, &b.DBRoles, &b.ClientDBRoles, &b.PEPClients, &b.Enabled, &b.Description,
			&b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, normalizeBinding(b))
	}
	return out, rows.Err()
}

func normalizeBinding(b issuerBinding) issuerBinding {
	if b.Stores == nil {
		b.Stores = []string{}
	}
	if b.DBRoles == nil {
		b.DBRoles = []string{}
	}
	if b.ClientDBRoles == nil {
		b.ClientDBRoles = map[string]string{}
	}
	if b.PEPClients == nil {
		b.PEPClients = map[string][]string{}
	}
	return b
}

// same reports whether a row and a file entry bind the same (the audit
// columns do not count).
func sameBinding(a, b issuerBinding) bool {
	ja, _ := json.Marshal(issuerBinding{Issuer: a.Issuer, Stores: a.Stores, DBRoles: a.DBRoles, ClientDBRoles: a.ClientDBRoles, PEPClients: a.PEPClients, Enabled: a.Enabled, Description: a.Description})
	jb, _ := json.Marshal(issuerBinding{Issuer: b.Issuer, Stores: b.Stores, DBRoles: b.DBRoles, ClientDBRoles: b.ClientDBRoles, PEPClients: b.PEPClients, Enabled: b.Enabled, Description: b.Description})
	return string(ja) == string(jb)
}

func cmdIssuersList(args []string) error {
	fs, dsn := newFlags("issuers list")
	sf := newServerFlags(fs)
	asJSON := fs.Bool("json", false, "print the rows as JSON (the export shape)")
	parseAll(fs, args)
	ctx := context.Background()
	st, err := openIssuerStore(ctx, sf, *dsn)
	if err != nil {
		return err
	}
	defer st.close(ctx)
	rows, rev, err := st.list(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Println(prettyJSON(map[string]any{"revision": rev, "bindings": rows}))
		return nil
	}
	fmt.Printf("revision %d — %d binding(s)\n", rev, len(rows))
	for _, b := range rows {
		state := "enabled"
		if !b.Enabled {
			state = "DISABLED"
		}
		stores := "as the environment"
		if len(b.Stores) > 0 {
			stores = strings.Join(b.Stores, ",")
		}
		fmt.Printf("  %-50s %-9s stores=%s db_roles=%s clients=%d pep_clients=%d  (updated %s by %s)\n",
			b.Issuer, state, stores, orDash(strings.Join(b.DBRoles, ",")), len(b.ClientDBRoles), len(b.PEPClients),
			fmtTime(b.UpdatedAt), b.UpdatedBy)
		if b.Description != "" {
			fmt.Printf("  %-50s %s\n", "", b.Description)
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// cmdIssuersExport — the rows as a JSON file: the thing to keep in git.
func cmdIssuersExport(args []string) error {
	fs, dsn := newFlags("issuers export")
	sf := newServerFlags(fs)
	out := fs.String("out", "", "write to this file instead of stdout")
	parseAll(fs, args)
	ctx := context.Background()
	st, err := openIssuerStore(ctx, sf, *dsn)
	if err != nil {
		return err
	}
	defer st.close(ctx)
	rows, _, err := st.list(ctx)
	if err != nil {
		return err
	}
	// the audit columns are the database's, not the file's
	for i := range rows {
		rows[i].CreatedAt, rows[i].CreatedBy, rows[i].UpdatedAt, rows[i].UpdatedBy = nil, "", nil, ""
	}
	text := prettyJSON(map[string]any{"bindings": rows}) + "\n"
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(*out, []byte(text), 0o644)
}

// cmdIssuersImport — upsert every binding of the file; --prune deletes the
// rows the file does not name; --dry-run only says what would change.
func cmdIssuersImport(args []string) error {
	fs, dsn := newFlags("issuers import")
	sf := newServerFlags(fs)
	prune := fs.Bool("prune", false, "delete the bindings the file does not name")
	dryRun := fs.Bool("dry-run", false, "report the changes without applying them")
	by := fs.String("performed-by", "pgauthzctl", "recorded as the actor in the audit trail (--dsn only; over the admin API the actor is the credential's)")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl issuers import <bindings.json> [--prune] [--dry-run] [--performed-by <who>]")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var file struct {
		Bindings []issuerBinding `json:"bindings"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return fmt.Errorf("%s: %w (expected {\"bindings\": [{issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description}, …]})", pos[0], err)
	}
	want := map[string]issuerBinding{}
	var order []string
	for _, b := range file.Bindings {
		b.Issuer = strings.TrimSpace(b.Issuer)
		if b.Issuer == "" {
			return fmt.Errorf("%s: a binding without an issuer", pos[0])
		}
		if _, dup := want[b.Issuer]; dup {
			return fmt.Errorf("%s: issuer %s listed twice", pos[0], b.Issuer)
		}
		want[b.Issuer] = normalizeBinding(b)
		order = append(order, b.Issuer)
	}

	ctx := context.Background()
	st, err := openIssuerStore(ctx, sf, *dsn)
	if err != nil {
		return err
	}
	defer st.close(ctx)
	have, _, err := st.list(ctx)
	if err != nil {
		return err
	}
	haveBy := map[string]issuerBinding{}
	for _, b := range have {
		haveBy[b.Issuer] = b
	}

	var creates, updates, deletes []string
	for _, iss := range order {
		cur, ok := haveBy[iss]
		switch {
		case !ok:
			creates = append(creates, iss)
		case !sameBinding(cur, want[iss]):
			updates = append(updates, iss)
		}
	}
	if *prune {
		for _, b := range have {
			if _, ok := want[b.Issuer]; !ok {
				deletes = append(deletes, b.Issuer)
			}
		}
		sort.Strings(deletes)
	}
	for _, iss := range creates {
		fmt.Printf("+ create %s\n", iss)
	}
	for _, iss := range updates {
		fmt.Printf("~ update %s\n", iss)
	}
	for _, iss := range deletes {
		fmt.Printf("- delete %s\n", iss)
	}
	unchanged := len(order) - len(creates) - len(updates)
	if len(creates)+len(updates)+len(deletes) == 0 {
		fmt.Printf("no changes (%d binding(s) as in the file)\n", unchanged)
		return nil
	}
	if *dryRun {
		fmt.Printf("dry run: %d to create, %d to update, %d to delete, %d unchanged\n", len(creates), len(updates), len(deletes), unchanged)
		return nil
	}

	// over the database: one transaction, the fleet sees the whole file or
	// nothing; over the admin API: one PUT / DELETE per issuer, in order,
	// stopping at the first refusal (what was applied before it stays)
	writer := st
	var commit func() error
	if db, ok := st.(*dbIssuerStore); ok {
		tx, err := db.conn.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		writer = &dbIssuerStore{conn: db.conn, q: tx}
		commit = func() error { return tx.Commit(ctx) }
	}
	var rev int64
	done := 0
	for _, iss := range append(append([]string{}, creates...), updates...) {
		r, err := writer.set(ctx, want[iss], *by)
		if err != nil {
			return fmt.Errorf("%s: %w (%d change(s) before it: %s)", iss, err, done, map[bool]string{true: "rolled back", false: "applied"}[commit != nil])
		}
		rev, done = r, done+1
	}
	for _, iss := range deletes {
		if _, err := writer.delete(ctx, iss, *by); err != nil {
			return fmt.Errorf("%s: %w (%d change(s) before it: %s)", iss, err, done, map[bool]string{true: "rolled back", false: "applied"}[commit != nil])
		}
		done++
	}
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}
	if rev == 0 {
		_, rev, _ = st.list(ctx)
	}
	how := "over the admin API"
	if commit != nil {
		how = "in one transaction"
	}
	fmt.Printf("applied %s: %d created, %d updated, %d deleted, %d unchanged — revision %d (every ISSUERS_SOURCE=env+db instance applies it within its poll interval)\n",
		how, len(creates), len(updates), len(deletes), unchanged, rev)
	return nil
}

// cmdIssuersDelete — drop one binding: the issuer falls back to its
// environment bindings.
func cmdIssuersDelete(args []string) error {
	fs, dsn := newFlags("issuers delete")
	sf := newServerFlags(fs)
	by := fs.String("performed-by", "pgauthzctl", "recorded as the actor in the audit trail (--dsn only)")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl issuers delete <issuer> [--server … | --dsn …] [--performed-by <who>]")
	}
	ctx := context.Background()
	st, err := openIssuerStore(ctx, sf, *dsn)
	if err != nil {
		return err
	}
	defer st.close(ctx)
	existed, err := st.delete(ctx, pos[0], *by)
	if err != nil {
		return err
	}
	if !existed {
		return fmt.Errorf("no binding for issuer %s", pos[0])
	}
	fmt.Printf("deleted the binding of %s: the issuer is back to its environment bindings\n", pos[0])
	return nil
}
