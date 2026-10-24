package main

// The store verbs — the admin API only (no --dsn): the first command group
// born on the long-run transport. Stores as upserts, their recorder
// allowlists and namespace grants, in the shapes the API defines.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const storeUsage = `pgauthzctl store <verb> [flags] — the admin API only (--server / PGAUTHZ_SERVER)

  list                                        the stores in scope, with their model state
  get <store>                                 one store (JSON)
  set <store> [--description d] [--docs-url u] [--retired]
                                              create or update (an upsert); --retired retires
  delete <store> [--purge-audit]              remove the store (the erasure path)
  recorders <store>                           the recorder allowlists
  recorder-set <store> <db_role> <action,...> make a role's allowlist exactly these actions
  recorder-lift <store> <db_role>             lift a role's allowlist
  namespaces <store>                          the namespaces, their types and role grants
  namespace-grant <store> <ns> <db_role> [--read] [--write]
                                              make a role's access to a namespace exactly these flags
  namespace-revoke <store> <ns> <db_role>     remove a role's access
`

func cmdStore(verb string, args []string) error {
	fs := flag.NewFlagSet("store "+verb, flag.ExitOnError)
	sf := newServerFlags(fs)
	desc := fs.String("description", "", "set: the description")
	docs := fs.String("docs-url", "", "set: the documentation link (http(s))")
	retired := fs.Bool("retired", false, "set: retire the store")
	purge := fs.Bool("purge-audit", false, "delete: remove the audit rows too")
	read := fs.Bool("read", false, "namespace-grant: read access")
	write := fs.Bool("write", false, "namespace-grant: write access")
	asJSON := fs.Bool("json", false, "print the API's answer as JSON")
	pos := parseAll(fs, args)
	if !sf.set() {
		return fmt.Errorf("the store verbs run over the admin API only: --server (PGAUTHZ_SERVER) with --token or --cert/--key\n\n%s", storeUsage)
	}
	c, err := newAdminClient(sf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	need := func(n int, usage string) error {
		if len(pos) != n {
			return fmt.Errorf("usage: pgauthzctl store %s", usage)
		}
		return nil
	}
	storePath := func(s string) string { return "/pgauthz/v1/admin/stores/" + url.PathEscape(s) }
	print := func(v any, line string) {
		if *asJSON {
			fmt.Println(prettyJSON(v))
		} else if line != "" {
			fmt.Println(line)
		}
	}

	switch verb {
	case "list":
		var res struct {
			Stores []map[string]any `json:"stores"`
		}
		if err := c.do(ctx, "GET", "/pgauthz/v1/admin/stores", nil, &res); err != nil {
			return err
		}
		if *asJSON {
			fmt.Println(prettyJSON(res))
			return nil
		}
		for _, s := range res.Stores {
			state := "live"
			if s["retired_at"] != nil {
				state = "RETIRED"
			}
			model := "unmanaged"
			if m, ok := s["model"].(map[string]any); ok && m["model_name"] != nil {
				model = fmt.Sprintf("%v@%v", m["model_name"], m["model_version"])
				if m["in_sync"] == false {
					model += " (DRIFTED)"
				}
			}
			fmt.Printf("%-40s %-8s %-28s %v\n", s["name"], state, model, s["description"])
		}
		return nil
	case "get":
		if err := need(1, "get <store>"); err != nil {
			return err
		}
		var res map[string]any
		if err := c.do(ctx, "GET", storePath(pos[0]), nil, &res); err != nil {
			return err
		}
		fmt.Println(prettyJSON(res))
		return nil
	case "set":
		if err := need(1, "set <store> [--description d] [--docs-url u] [--retired]"); err != nil {
			return err
		}
		body := map[string]any{}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "description":
				body["description"] = *desc
			case "docs-url":
				body["docs_url"] = *docs
			case "retired":
				body["retired"] = *retired
			}
		})
		var res struct {
			Store   map[string]any `json:"store"`
			Created bool           `json:"created"`
		}
		if err := c.do(ctx, "PUT", storePath(pos[0]), body, &res); err != nil {
			return err
		}
		what := "updated"
		if res.Created {
			what = "created"
		}
		print(res, fmt.Sprintf("%s store %s", what, pos[0]))
		return nil
	case "delete":
		if err := need(1, "delete <store> [--purge-audit]"); err != nil {
			return err
		}
		q := ""
		if *purge {
			q = "?purge_audit=true"
		}
		var res map[string]any
		if err := c.do(ctx, "DELETE", storePath(pos[0])+q, nil, &res); err != nil {
			return err
		}
		print(res, fmt.Sprintf("deleted store %s", pos[0]))
		return nil
	case "recorders":
		if err := need(1, "recorders <store>"); err != nil {
			return err
		}
		var res struct {
			Recorders []struct {
				DBRole  string   `json:"db_role"`
				Actions []string `json:"actions"`
			} `json:"recorders"`
		}
		if err := c.do(ctx, "GET", storePath(pos[0])+"/recorders", nil, &res); err != nil {
			return err
		}
		if *asJSON {
			fmt.Println(prettyJSON(res))
			return nil
		}
		if len(res.Recorders) == 0 {
			fmt.Println("no allowlists: every recorder role may record any declared action")
		}
		for _, r := range res.Recorders {
			fmt.Printf("%-32s %s\n", r.DBRole, strings.Join(r.Actions, ","))
		}
		return nil
	case "recorder-set":
		if err := need(3, "recorder-set <store> <db_role> <action,...>"); err != nil {
			return err
		}
		var actions []string
		for a := range strings.SplitSeq(pos[2], ",") {
			if a = strings.TrimSpace(a); a != "" {
				actions = append(actions, a)
			}
		}
		var res map[string]any
		if err := c.do(ctx, "PUT", storePath(pos[0])+"/recorders/"+url.PathEscape(pos[1]), map[string]any{"actions": actions}, &res); err != nil {
			return err
		}
		print(res, fmt.Sprintf("%s may record %s in %s", pos[1], strings.Join(actions, ","), pos[0]))
		return nil
	case "recorder-lift":
		if err := need(2, "recorder-lift <store> <db_role>"); err != nil {
			return err
		}
		var res map[string]any
		if err := c.do(ctx, "DELETE", storePath(pos[0])+"/recorders/"+url.PathEscape(pos[1]), nil, &res); err != nil {
			return err
		}
		print(res, fmt.Sprintf("lifted the allowlist of %s in %s", pos[1], pos[0]))
		return nil
	case "namespaces":
		if err := need(1, "namespaces <store>"); err != nil {
			return err
		}
		var res struct {
			Namespaces []struct {
				Name   string            `json:"name"`
				Types  []string          `json:"types"`
				Access []json.RawMessage `json:"access"`
			} `json:"namespaces"`
		}
		if err := c.do(ctx, "GET", storePath(pos[0])+"/namespaces", nil, &res); err != nil {
			return err
		}
		if *asJSON {
			fmt.Println(prettyJSON(res))
			return nil
		}
		for _, n := range res.Namespaces {
			var grants []string
			for _, g := range n.Access {
				var a struct {
					DBRole   string `json:"db_role"`
					CanRead  bool   `json:"can_read"`
					CanWrite bool   `json:"can_write"`
				}
				_ = json.Unmarshal(g, &a)
				flags := map[bool]string{true: "r", false: "-"}[a.CanRead] + map[bool]string{true: "w", false: "-"}[a.CanWrite]
				grants = append(grants, a.DBRole+":"+flags)
			}
			fmt.Printf("%-24s types=%s  access=%s\n", n.Name, strings.Join(n.Types, ","), strings.Join(grants, ","))
		}
		return nil
	case "namespace-grant":
		if err := need(3, "namespace-grant <store> <ns> <db_role> [--read] [--write]"); err != nil {
			return err
		}
		var res map[string]any
		if err := c.do(ctx, "PUT", storePath(pos[0])+"/namespaces/"+url.PathEscape(pos[1])+"/access/"+url.PathEscape(pos[2]),
			map[string]any{"can_read": *read, "can_write": *write}, &res); err != nil {
			return err
		}
		print(res, fmt.Sprintf("%s on namespace %s of %s: read=%v write=%v", pos[2], pos[1], pos[0], *read, *write))
		return nil
	case "namespace-revoke":
		if err := need(3, "namespace-revoke <store> <ns> <db_role>"); err != nil {
			return err
		}
		var res map[string]any
		if err := c.do(ctx, "DELETE", storePath(pos[0])+"/namespaces/"+url.PathEscape(pos[1])+"/access/"+url.PathEscape(pos[2]), nil, &res); err != nil {
			return err
		}
		print(res, fmt.Sprintf("removed %s from namespace %s of %s", pos[2], pos[1], pos[0]))
		return nil
	default:
		fmt.Fprint(os.Stderr, storeUsage)
		os.Exit(2)
		return nil
	}
}
