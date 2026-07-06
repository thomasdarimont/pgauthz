package main

import (
	"fmt"
	"strings"
)

// ref is a parsed OpenFGA-notation entity reference:
//
//	"user:alice"        → {Type: user, ID: alice}
//	"user:*"            → {Type: user, ID: *}
//	"group:eng#member"  → {Type: group, ID: eng, Relation: member}  (userset)
type ref struct {
	Type, ID, Relation string
}

func parseRef(s string) (ref, error) {
	var r ref
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

// parseModelRef splits "name@version" (version optional → 0 = latest).
func parseModelRef(s string) (name string, version int, err error) {
	if i := strings.Index(s, "@"); i >= 0 {
		name = s[:i]
		if _, e := fmt.Sscanf(s[i+1:], "%d", &version); e != nil {
			return "", 0, fmt.Errorf("bad model reference %q (want name or name@version)", s)
		}
		return name, version, nil
	}
	return s, 0, nil
}

// versionArg maps 0 → nil so SQL defaults resolve "latest".
func versionArg(v int) any {
	if v == 0 {
		return nil
	}
	return v
}
