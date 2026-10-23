package pgauthzadm

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Model is the engine's canonical model definition — the shape of
// authz.export_model(store), which publish_model snapshots into the registry.
// Field order follows the export; unknown keys survive a round trip in Extra.
type Model struct {
	Format           int               `json:"format"`
	Types            []ModelType       `json:"types"`
	Relations        []ModelRelation   `json:"relations"`
	Rules            []ModelRule       `json:"rules"`
	TypeRestrictions []TypeRestriction `json:"type_restrictions"`
	Conditions       []Condition       `json:"conditions"`
	Gates            []Gate            `json:"gates"`
	GrantRules       []GrantRule       `json:"grant_rules"`
}

type ModelType struct {
	Name        string   `json:"name"`
	Namespace   *string  `json:"namespace"`
	Description *string  `json:"description"`
	Labels      []string `json:"labels"`
	HashModulus int      `json:"hash_modulus"`
}

type ModelRelation struct {
	Name          string          `json:"name"`
	Description   *string         `json:"description"`
	PayloadSchema json.RawMessage `json:"payload_schema,omitempty"`
	// Metadata carries the relation's kind — "relation" (what a subject IS,
	// assignable by a tuple) or "permission" (what it CAN DO, derived only) —
	// plus any tooling keys (label, docs_url).
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Kind returns the declared kind, "relation" when none is declared.
func (r ModelRelation) Kind() string {
	var m struct {
		Kind string `json:"kind"`
	}
	if len(r.Metadata) > 0 && json.Unmarshal(r.Metadata, &m) == nil && m.Kind != "" {
		return m.Kind
	}
	return "relation"
}

type ModelRule struct {
	ObjectType          string  `json:"object_type"`
	Relation            string  `json:"relation"`
	RuleType            string  `json:"rule_type"` // direct | computed | ttu
	ComputedRelation    *string `json:"computed_relation"`
	TuplesetRelation    *string `json:"tupleset_relation"`
	TuplesetComputed    *string `json:"tupleset_computed"`
	GroupID             int     `json:"group_id"`
	GroupOp             string  `json:"group_op"` // or | intersection | exclusion
	Negated             bool    `json:"negated"`
	AllowObjectWildcard bool    `json:"allow_object_wildcard"`
}

type TypeRestriction struct {
	ObjectType          string  `json:"object_type"`
	Relation            string  `json:"relation"`
	AllowedUserType     string  `json:"allowed_user_type"`
	AllowedUserRelation *string `json:"allowed_user_relation"`
	AllowWildcard       bool    `json:"allow_wildcard"`
	Condition           *string `json:"condition,omitempty"`
}

type Condition struct {
	Name            string          `json:"name"`
	Expression      string          `json:"expression"`
	Lang            string          `json:"lang"`
	RequiredContext json.RawMessage `json:"required_context"`
	TimeSource      string          `json:"time_source,omitempty"`
	Description     string          `json:"description,omitempty"`
}

type Gate struct {
	ObjectType string          `json:"object_type"`
	Relation   string          `json:"relation"`
	Name       string          `json:"name"`
	Spec       json.RawMessage `json:"spec"`
}

type GrantRule struct {
	ObjectType     string  `json:"object_type"`
	Relation       string  `json:"relation"`
	Requires       string  `json:"requires"`
	RequiresRevoke *string `json:"requires_revoke"`
}

// ExportModel returns a store's live model (authz.export_model), the
// round-trippable canonical form.
func ExportModel(ctx context.Context, db DB, store string) (*Model, error) {
	var m Model
	if err := QueryJSON(ctx, db, &m, "SELECT authz.export_model($1)", store); err != nil {
		return nil, err
	}
	return &m, nil
}

// ExportModelJSON returns the export as raw JSON, for callers that only pass
// it on (pretty-printing, HTTP responses).
func ExportModelJSON(ctx context.Context, db DB, store string) (json.RawMessage, error) {
	var raw []byte
	if err := db.QueryRow(ctx, "SELECT authz.export_model($1)", store).Scan(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// DescribeModel renders a store's model as OpenFGA-style DSL text
// (authz.describe_model). Display only: conditions, gates, grant rules and
// namespaces have no DSL form, so the text is lossy and not round-trippable —
// use ExportModel / RenderSQL for that.
func DescribeModel(ctx context.Context, db DB, store string) (string, error) {
	var text string
	if err := db.QueryRow(ctx, "SELECT authz.describe_model($1)", store).Scan(&text); err != nil {
		return "", err
	}
	return text, nil
}

// RenderSQL renders a model as the sequence of engine calls that rebuilds it
// in the named store — the complete, loss-free, copy-and-run form of a model
// (the shape of examples/models/*/model.sql). The store argument is the
// target; pass the source store to reproduce it, another name to clone.
func RenderSQL(store string, m *Model) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...); b.WriteByte('\n') }
	q := sqlQuote

	w("-- Model of store %s as engine calls (authz.export_model rendered by pgauthzadm).", store)
	w("-- Run against a store that exists: SELECT authz.create_store(%s);", q(store))
	w("")
	if len(m.Types) > 0 {
		w("-- Types")
		for _, t := range m.Types {
			args := []string{q(store), q(t.Name)}
			if t.HashModulus != 0 {
				args = append(args, fmt.Sprintf("p_hash_modulus => %d", t.HashModulus))
			}
			if t.Namespace != nil && *t.Namespace != "" {
				args = append(args, "p_namespace => "+q(*t.Namespace))
			}
			if t.Description != nil && *t.Description != "" {
				args = append(args, "p_description => "+q(*t.Description))
			}
			if len(t.Labels) > 0 {
				ls := make([]string, len(t.Labels))
				for i, l := range t.Labels {
					ls[i] = q(l)
				}
				args = append(args, "p_labels => ARRAY["+strings.Join(ls, ", ")+"]")
			}
			w("SELECT authz.model_register_type(%s);", strings.Join(args, ", "))
		}
		w("")
	}
	if len(m.Relations) > 0 {
		w("-- Relations")
		for _, r := range m.Relations {
			args := []string{q(store), q(r.Name)}
			if r.Description != nil && *r.Description != "" {
				args = append(args, "p_description => "+q(*r.Description))
			}
			if md := strings.TrimSpace(string(r.Metadata)); md != "" && md != "null" && md != "{}" {
				args = append(args, "p_metadata => "+q(md)+"::jsonb")
			}
			w("SELECT authz.model_register_relation(%s);", strings.Join(args, ", "))
			if len(r.PayloadSchema) > 0 && string(r.PayloadSchema) != "null" {
				w("SELECT authz.model_set_payload_schema(%s, %s, %s::jsonb);", q(store), q(r.Name), q(string(r.PayloadSchema)))
			}
		}
		w("")
	}
	if len(m.Conditions) > 0 {
		w("-- Conditions (evaluated against the request context)")
		for _, c := range m.Conditions {
			args := []string{q(store), q(c.Name), q(c.Expression)}
			lang := c.Lang
			if lang == "" {
				lang = "sql"
			}
			args = append(args, "p_lang => "+q(lang))
			if len(c.RequiredContext) > 0 && string(c.RequiredContext) != "null" {
				args = append(args, "p_required_context => "+q(string(c.RequiredContext))+"::jsonb")
			}
			if c.TimeSource != "" {
				args = append(args, "p_time_source => "+q(c.TimeSource))
			}
			if c.Description != "" {
				args = append(args, "p_description => "+q(c.Description))
			}
			w("SELECT authz.create_condition(%s);", strings.Join(args, ", "))
		}
		w("")
	}
	if len(m.Rules) > 0 {
		w("-- Rules: direct = granted by a tuple, computed = implied by another relation,")
		w("-- ttu = inherited through a related object. Same group_id = one term of the")
		w("-- relation's expression; group_op intersection/exclusion combine groups.")
		rules := append([]ModelRule(nil), m.Rules...)
		sort.SliceStable(rules, func(i, j int) bool {
			if rules[i].ObjectType != rules[j].ObjectType {
				return rules[i].ObjectType < rules[j].ObjectType
			}
			if rules[i].Relation != rules[j].Relation {
				return rules[i].Relation < rules[j].Relation
			}
			if rules[i].GroupID != rules[j].GroupID {
				return rules[i].GroupID < rules[j].GroupID
			}
			// a group's base rule before its negated ones: the engine refuses
			// a negated rule whose group has no base yet (an exclusion with
			// nothing to exclude from would grant everyone not excluded)
			return !rules[i].Negated && rules[j].Negated
		})
		for _, r := range rules {
			args := []string{q(store), q(r.ObjectType), q(r.Relation), q(r.RuleType)}
			switch r.RuleType {
			case "computed":
				args = append(args, q(deref(r.ComputedRelation)))
			case "ttu":
				args = append(args, "NULL", q(deref(r.TuplesetRelation)), q(deref(r.TuplesetComputed)))
			}
			if r.GroupID != 0 {
				args = append(args, fmt.Sprintf("p_group_id => %d", r.GroupID))
			}
			if r.GroupOp != "" && r.GroupOp != "or" {
				args = append(args, "p_group_op => "+q(r.GroupOp))
			}
			if r.Negated {
				args = append(args, "p_negated => true")
			}
			if r.AllowObjectWildcard {
				args = append(args, "p_allow_object_wildcard => true")
			}
			w("SELECT authz.model_add_rule(%s);", strings.Join(args, ", "))
		}
		w("")
	}
	if len(m.TypeRestrictions) > 0 {
		w("-- Type restrictions: which subject types a direct relation accepts")
		for _, x := range m.TypeRestrictions {
			args := []string{q(store), q(x.ObjectType), q(x.Relation), q(x.AllowedUserType)}
			if x.AllowedUserRelation != nil && *x.AllowedUserRelation != "" {
				args = append(args, "p_allowed_user_relation => "+q(*x.AllowedUserRelation))
			}
			if x.AllowWildcard {
				args = append(args, "p_allow_wildcard => true")
			}
			if x.Condition != nil && *x.Condition != "" {
				args = append(args, "p_condition => "+q(*x.Condition))
			}
			w("SELECT authz.model_add_type_restriction(%s);", strings.Join(args, ", "))
		}
		w("")
	}
	if len(m.GrantRules) > 0 {
		w("-- Grant rules: who may share which relation (authz.grant / authz.revoke)")
		for _, g := range m.GrantRules {
			args := []string{q(store), q(g.ObjectType), q(g.Relation), q(g.Requires)}
			if g.RequiresRevoke != nil && *g.RequiresRevoke != "" {
				args = append(args, q(*g.RequiresRevoke))
			}
			w("SELECT authz.model_add_grant_rule(%s);", strings.Join(args, ", "))
		}
		w("")
	}
	if len(m.Gates) > 0 {
		w("-- Temporal gates: evaluated against the action log after the graph allows")
		for _, g := range m.Gates {
			w("SELECT authz.add_gate(%s, %s, %s, %s, %s::jsonb);", q(store), q(g.ObjectType), q(g.Relation), q(g.Name), q(string(g.Spec)))
		}
		w("")
	}
	return b.String()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sqlQuote renders s as a SQL string literal.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
