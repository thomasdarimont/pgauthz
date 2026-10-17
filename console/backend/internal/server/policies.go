package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Policies tab: which Rego applies to a store, read from the OPA sidecar
// (ADR 0008 opt-in). Hooks follow ADR 0011's package layout:
//   authz.hooks.v1.global.<name>          every store
//   authz.hooks.v1.stores.<store>.<name>  this store
// Shared libraries live under authz.hooks_lib*; everything else is platform
// policy. Read-only: policies are authored in git and shipped as validated
// bundles; the console shows what is live. See scratch/notes/in-process-policy-hooks.md.

type policyInfo struct {
	ID      string `json:"id"`      // OPA policy id (the file path as loaded)
	Package string `json:"package"` // dotted package path
	Name    string `json:"name"`    // hook name (last segment) or the package for libs
	Raw     string `json:"raw"`     // source
}

type policiesResp struct {
	Configured bool         `json:"configured"`
	Error      string       `json:"error,omitempty"`
	OPA        any          `json:"opa,omitempty"` // provenance: version, build, bundles
	Global     []policyInfo `json:"global"`
	Store      []policyInfo `json:"store"`
	Libs       []policyInfo `json:"libs"`
	Platform   []policyInfo `json:"platform"`
	Contract   string       `json:"contract"` // hooks contract version in use (v1)
}

func (s *Server) opaGet(ctx context.Context, path string, body any) ([]byte, error) {
	method := http.MethodGet
	var rd io.Reader
	if body != nil {
		method = http.MethodPost
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.cfg.OPAURL, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if s.cfg.OPAToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.OPAToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := s.http
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA %s: %s", path, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// handlePolicies — GET /api/stores/{store}/policies.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	out := policiesResp{Global: []policyInfo{}, Store: []policyInfo{}, Libs: []policyInfo{}, Platform: []policyInfo{}, Contract: "v1"}
	if s.cfg.OPAURL == "" {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Configured = true
	ctx := r.Context()
	// Provenance (public query with ?provenance=true): OPA version and bundles.
	if raw, err := s.opaGet(ctx, "/v1/data/authz/pgauthz/callback_healthy?provenance=true", map[string]any{"input": map[string]any{}}); err == nil {
		var v struct {
			Provenance any `json:"provenance"`
		}
		if json.Unmarshal(raw, &v) == nil {
			out.OPA = v.Provenance
		}
	}
	raw, err := s.opaGet(ctx, "/v1/policies", nil)
	if err != nil {
		out.Error = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	var list struct {
		Result []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
			AST struct {
				Package struct {
					Path []struct {
						Value string `json:"value"`
					} `json:"path"`
				} `json:"package"`
			} `json:"ast"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		out.Error = "unexpected OPA response: " + err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	storePrefix := "authz.hooks.v1.stores." + store + "."
	for _, pol := range list.Result {
		segs := make([]string, 0, len(pol.AST.Package.Path))
		for i, x := range pol.AST.Package.Path {
			if i == 0 && x.Value == "data" {
				continue
			}
			segs = append(segs, x.Value)
		}
		pkg := strings.Join(segs, ".")
		info := policyInfo{ID: pol.ID, Package: pkg, Name: pkg, Raw: pol.Raw}
		if i := strings.LastIndex(pkg, "."); i >= 0 {
			info.Name = pkg[i+1:]
		}
		switch {
		case strings.HasSuffix(pol.ID, "_test.rego"):
			continue // OPA unit tests, not policy
		case strings.HasPrefix(pkg, "authz.hooks.v1.global."):
			out.Global = append(out.Global, info)
		case strings.HasPrefix(pkg, storePrefix):
			out.Store = append(out.Store, info)
		case strings.HasPrefix(pkg, "authz.hooks.v1.stores."):
			continue // another store's hooks: never shown here
		case strings.HasPrefix(pkg, "authz.hooks.lib.") || strings.HasPrefix(pkg, "authz.hooks_lib") || strings.Contains(pol.ID, "hooks-lib"):
			info.Name = pkg
			out.Libs = append(out.Libs, info)
		default:
			// several platform files share a package (hooks.rego, write.rego and
			// policy.rego are all `authz`): the file name tells them apart
			info.Name = strings.TrimSuffix(pol.ID[strings.LastIndex(pol.ID, "/")+1:], ".rego")
			out.Platform = append(out.Platform, info)
		}
	}
	for _, l := range [][]policyInfo{out.Global, out.Store, out.Libs, out.Platform} {
		sort.Slice(l, func(i, j int) bool { return l[i].Package < l[j].Package })
	}
	writeJSON(w, http.StatusOK, out)
}
