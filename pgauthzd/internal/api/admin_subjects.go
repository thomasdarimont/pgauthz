package api

// Data subject requests over the admin API (PRODUCTION.md → Data subject
// requests): the takeout as rows or CSV (list_subject_objects) and the
// export as one JSON document (export_subject). Store-scoped like the rest
// of the store management; this is the path for application teams,
// scripts and pgauthzctl. Erasure is deliberately NOT here: it belongs at
// the end of a data-subject workflow, after the applications deleted
// their records by the takeout's references, and a machine-callable
// erasure invites scripts that run it first. The console's Data subject
// tab (a person, a confirmation, the audit record) and the SQL function
// are the erasure paths.

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
)

const subjectListMax = 1_000_000

// decisionSink is the postgres decision-log sink when this instance writes
// one — the only sink whose lines this instance can erase.
func (h *Handler) decisionSink() *decisionlog.PostgresSink {
	if h.decisions == nil {
		return nil
	}
	return h.decisions.Postgres
}

// subjectPath reads and validates the {type}/{id} of a subject route.
func subjectPath(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	typ, id := r.PathValue("type"), r.PathValue("id")
	if !storeNameRe.MatchString(typ) {
		writeBadRequest(w, "subject types are [a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters")
		return "", "", false
	}
	if id == "" || id == "*" {
		writeBadRequest(w, "a data subject is one concrete id (no wildcard)")
		return "", "", false
	}
	return typ, id, true
}

// csvList splits a comma-separated query parameter; nil when absent.
func csvList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func subjectLimit(w http.ResponseWriter, q url.Values) (int, bool) {
	raw := q.Get("limit")
	if raw == "" {
		return 10000, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > subjectListMax {
		writeBadRequest(w, "limit must be an integer in [1, "+strconv.Itoa(subjectListMax)+"]")
		return 0, false
	}
	return n, true
}

// GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}/objects
//
//	?relations=a,b&object_types=x,y&limit=N&format=csv
//
// One row per (object type, relation, object id) the subject reaches;
// `direct` says a tuple names it outright, `is_wildcard` marks the "every
// object" row, `truncated` that a pair hit the limit. CSV carries the
// store and subject in every row so a file stands on its own.
func (h *Handler) adminSubjectObjects(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	typ, id, ok := subjectPath(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, ok := subjectLimit(w, q)
	if !ok {
		return
	}
	rows, err := a.SubjectObjects(r.Context(), store, typ, id, csvList(q.Get("relations")), csvList(q.Get("object_types")), limit)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if q.Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+store+"-"+typ+"-"+url.PathEscape(id)+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"store", "subject_type", "subject_id", "object_type", "relation", "object_id", "is_wildcard", "direct", "truncated"})
		for _, o := range rows {
			_ = cw.Write([]string{store, typ, id, o.ObjectType, o.Relation, o.ObjectID, strconv.FormatBool(o.IsWildcard), strconv.FormatBool(o.Direct), strconv.FormatBool(o.Truncated)})
		}
		cw.Flush()
		return
	}
	truncated := false
	for _, o := range rows {
		truncated = truncated || o.Truncated
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"store": store, "subject": map[string]string{"type": typ, "id": id}, "objects": rows, "truncated": truncated,
	})
}

// GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}?relations=&limit=
//
// The export document (authz.export_subject): direct tuples both sides,
// effective objects, events by and about the person, audit rows. The
// decision log is not in it: this instance's sink is write-only, the
// console's export adds the lines (its Data subject tab).
func (h *Handler) adminSubjectExport(w http.ResponseWriter, r *http.Request) {
	_, store, ok := h.requireStoreScope(w, r)
	if !ok {
		return
	}
	a, ok := h.storeAdmin(w)
	if !ok {
		return
	}
	typ, id, ok := subjectPath(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, ok := subjectLimit(w, q)
	if !ok {
		return
	}
	doc, err := a.ExportSubject(r.Context(), store, typ, id, csvList(q.Get("relations")), limit)
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func registerAdminSubjects(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}/objects", h.adminSubjectObjects)
	mux.HandleFunc("GET /pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}", h.adminSubjectExport)
}
