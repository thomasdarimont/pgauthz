package pgauthzadm

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// GetModelVersion loads one registry version's definition as a Model.
// version 0 means the latest.
func GetModelVersion(ctx context.Context, db DB, name string, version int) (*Model, error) {
	var raw json.RawMessage
	err := db.QueryRow(ctx, `
		SELECT definition FROM authz.model_registry
		 WHERE name = $1 AND ($2::int IS NULL OR version = $2)
		 ORDER BY version DESC LIMIT 1`, name, VersionArg(version)).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("registry version %s@%d: %w", name, version, err)
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DiffModels — what changes from a to b, per section, in the shape of a
// plan's changes (op add | update | remove, section, item). Items are keyed
// by what identifies them in the engine: a type or relation or condition by
// name, a rule by (type, relation, kind, source, group), a type restriction
// by (type, relation, subject), a gate by (type, relation, name), a grant
// rule by (type, relation). An item whose key exists on both sides but whose
// body differs is an update.
func DiffModels(a, b *Model) []Change {
	var out []Change
	section := func(name string, left, right map[string]any, label func(k string) any) {
		keys := map[string]bool{}
		for k := range left {
			keys[k] = true
		}
		for k := range right {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			l, inL := left[k]
			r, inR := right[k]
			switch {
			case inL && !inR:
				out = append(out, Change{Op: "remove", Section: name, Item: label(k)})
			case !inL && inR:
				out = append(out, Change{Op: "add", Section: name, Item: label(k)})
			default:
				lj, _ := json.Marshal(l)
				rj, _ := json.Marshal(r)
				if string(lj) != string(rj) {
					out = append(out, Change{Op: "update", Section: name, Item: label(k)})
				}
			}
		}
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	plain := func(k string) any { return k }

	types := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, t := range m.Types {
			o[t.Name] = t
		}
		return o
	}
	section("types", types(a), types(b), plain)

	relations := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, r := range m.Relations {
			o[r.Name] = r
		}
		return o
	}
	section("relations", relations(a), relations(b), plain)

	rules := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, r := range m.Rules {
			src := r.RuleType
			switch r.RuleType {
			case "computed":
				src = str(r.ComputedRelation)
			case "ttu":
				src = str(r.TuplesetComputed) + " from " + str(r.TuplesetRelation)
			}
			neg := ""
			if r.Negated {
				neg = " (but not)"
			}
			group := ""
			if r.GroupID != 0 || (r.GroupOp != "" && r.GroupOp != "or") {
				group = fmt.Sprintf(" [group %d %s]", r.GroupID, r.GroupOp)
			}
			o[fmt.Sprintf("%s.%s ← %s%s%s", r.ObjectType, r.Relation, src, neg, group)] = r
		}
		return o
	}
	section("rules", rules(a), rules(b), plain)

	restrictions := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, x := range m.TypeRestrictions {
			subj := x.AllowedUserType
			if x.AllowedUserRelation != nil {
				subj += "#" + *x.AllowedUserRelation
			}
			if x.AllowWildcard {
				subj += ":*"
			}
			o[fmt.Sprintf("%s.%s accepts %s", x.ObjectType, x.Relation, subj)] = x
		}
		return o
	}
	section("type_restrictions", restrictions(a), restrictions(b), plain)

	conditions := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, c := range m.Conditions {
			o[c.Name] = c
		}
		return o
	}
	section("conditions", conditions(a), conditions(b), plain)

	gates := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, g := range m.Gates {
			o[fmt.Sprintf("%s.%s / %s", g.ObjectType, g.Relation, g.Name)] = g
		}
		return o
	}
	section("gates", gates(a), gates(b), plain)

	grants := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, g := range m.GrantRules {
			o[fmt.Sprintf("%s.%s", g.ObjectType, g.Relation)] = g
		}
		return o
	}
	section("grant_rules", grants(a), grants(b), plain)

	constraints := func(m *Model) map[string]any {
		o := map[string]any{}
		for _, c := range m.RelationConstraints {
			o[fmt.Sprintf("%s.%s", c.ObjectType, c.Relation)] = c
		}
		return o
	}
	section("relation_constraints", constraints(a), constraints(b), plain)
	return out
}

// RenderDiff — the changes as text, one line each, for the CLI.
func RenderDiff(changes []Change) string {
	if len(changes) == 0 {
		return "no differences\n"
	}
	var b strings.Builder
	for _, c := range changes {
		sign := map[string]string{"add": "+", "update": "~", "remove": "-"}[c.Op]
		fmt.Fprintf(&b, "%s %-17s %v\n", sign, c.Section, c.Item)
	}
	return b.String()
}
