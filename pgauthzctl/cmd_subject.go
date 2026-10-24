package main

// The subject verbs — data subject requests (GDPR) over the admin API:
// the takeout as rows or CSV for the application teams and the export as
// one JSON document. No erasure here (PRODUCTION.md → Data subject
// requests: it comes last, after the applications, from the console or
// SQL — not from a script that may run it first).

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const subjectUsage = `pgauthzctl subject <verb> <store> <type:id> [flags] — the admin API only (--server / PGAUTHZ_SERVER)

  objects <store> <type:id> [--relations a,b] [--object-types x,y] [--limit N] [--csv] [--out file]
                                              every object the subject reaches, one row per
                                              object and relation (the takeout for the app teams)
  export  <store> <type:id> [--relations a,b] [--limit N] [--out file]
                                              the export document (JSON): tuples both sides,
                                              effective objects, events, audit rows
`

func cmdSubject(verb string, args []string) error {
	fs := flag.NewFlagSet("subject "+verb, flag.ExitOnError)
	sf := newServerFlags(fs)
	relations := fs.String("relations", "", "comma-separated relations to restrict to")
	objectTypes := fs.String("object-types", "", "objects: comma-separated object types to restrict to")
	limit := fs.Int("limit", 0, "cap per (type, relation) pair / per list (default: the API's 10000)")
	asCSV := fs.Bool("csv", false, "objects: CSV instead of a table (the hand-over file)")
	out := fs.String("out", "", "write the answer to this file instead of stdout")
	asJSON := fs.Bool("json", false, "print the API's answer as JSON")
	pos := parseAll(fs, args)
	if !sf.set() {
		return fmt.Errorf("the subject verbs run over the admin API only: --server (PGAUTHZ_SERVER) with --token or --cert/--key\n\n%s", subjectUsage)
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: pgauthzctl subject %s <store> <type:id>\n\n%s", verb, subjectUsage)
	}
	store, subject := pos[0], pos[1]
	typ, id, ok := strings.Cut(subject, ":")
	if !ok || typ == "" || id == "" {
		return fmt.Errorf("the subject is type:id, got %q", subject)
	}
	c, err := newAdminClient(sf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	base := "/pgauthz/v1/admin/stores/" + url.PathEscape(store) + "/subjects/" + url.PathEscape(typ) + "/" + url.PathEscape(id)
	q := url.Values{}
	if *relations != "" {
		q.Set("relations", *relations)
	}
	if *limit > 0 {
		q.Set("limit", fmt.Sprint(*limit))
	}
	dest := func() (io.Writer, func() error, error) {
		if *out == "" {
			return os.Stdout, func() error { return nil }, nil
		}
		f, err := os.Create(*out)
		if err != nil {
			return nil, nil, err
		}
		return f, f.Close, nil
	}

	switch verb {
	case "objects":
		if *objectTypes != "" {
			q.Set("object_types", *objectTypes)
		}
		w, closeFn, err := dest()
		if err != nil {
			return err
		}
		defer closeFn() //nolint:errcheck
		if *asCSV {
			q.Set("format", "csv")
			return c.doStream(ctx, "GET", base+"/objects?"+q.Encode(), w)
		}
		var res struct {
			Objects []struct {
				ObjectType string `json:"object_type"`
				Relation   string `json:"relation"`
				ObjectID   string `json:"object_id"`
				IsWildcard bool   `json:"is_wildcard"`
				Direct     bool   `json:"direct"`
				Truncated  bool   `json:"truncated"`
			} `json:"objects"`
			Truncated bool `json:"truncated"`
		}
		if err := c.do(ctx, "GET", base+"/objects?"+q.Encode(), nil, &res); err != nil {
			return err
		}
		if *asJSON {
			fmt.Fprintln(w, prettyJSON(res))
			return nil
		}
		if len(res.Objects) == 0 {
			fmt.Fprintf(w, "%s reaches no object in %s\n", subject, store)
			return nil
		}
		fmt.Fprintf(w, "%-24s %-24s %s\n", "OBJECT_TYPE", "RELATION", "OBJECT_ID")
		for _, o := range res.Objects {
			flags := ""
			if o.Direct {
				flags += "  (direct)"
			}
			if o.IsWildcard {
				flags += "  (wildcard: every object)"
			}
			if o.Truncated {
				flags += "  (truncated)"
			}
			fmt.Fprintf(w, "%-24s %-24s %s%s\n", o.ObjectType, o.Relation, o.ObjectID, flags)
		}
		if res.Truncated {
			fmt.Fprintln(w, "some pair hit the limit — raise --limit or narrow with --relations/--object-types")
		}
		return nil
	case "export":
		w, closeFn, err := dest()
		if err != nil {
			return err
		}
		defer closeFn() //nolint:errcheck
		var doc json.RawMessage
		if err := c.do(ctx, "GET", base+"?"+q.Encode(), nil, &doc); err != nil {
			return err
		}
		var v any
		_ = json.Unmarshal(doc, &v)
		fmt.Fprintln(w, prettyJSON(v))
		return nil
	default:
		return fmt.Errorf("unknown subject verb %q\n\n%s", verb, subjectUsage)
	}
}
