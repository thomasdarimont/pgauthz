package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Translation overrides (CONSOLE_I18N_DIR): one <lang>.json per language, a
// flat object of English source string → translation, merged by the SPA over
// its built-in dictionary (built-in: frontend/src/i18n/<lang>.json). A file
// for a language the SPA does not ship adds that language; its optional
// "@language" entry is the name shown in the language picker.

var langName = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z]{2,4})?$`)

// handleI18nList — GET /api/i18n: the languages that have an override file.
func (s *Server) handleI18nList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	out := []map[string]string{}
	if s.cfg.I18nDir == "" {
		writeJSON(w, http.StatusOK, out)
		return
	}
	entries, err := os.ReadDir(s.cfg.I18nDir)
	if err != nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, e := range entries {
		lang := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || lang == e.Name() || !langName.MatchString(lang) {
			continue
		}
		name := lang
		if dict, err := s.readOverride(lang); err == nil {
			if n, ok := dict["@language"].(string); ok && n != "" {
				name = n
			}
		}
		out = append(out, map[string]string{"code": lang, "name": name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["code"] < out[j]["code"] })
	writeJSON(w, http.StatusOK, out)
}

// handleI18n — GET /api/i18n/{lang}: the override dictionary, {} when none.
func (s *Server) handleI18n(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if !langName.MatchString(lang) {
		writeError(w, http.StatusBadRequest, "invalid language code")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	dict, err := s.readOverride(lang)
	if err != nil {
		if os.IsNotExist(err) || s.cfg.I18nDir == "" {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeError(w, http.StatusInternalServerError, "override file for "+lang+" is not a JSON object: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dict)
}

func (s *Server) readOverride(lang string) (map[string]any, error) {
	if s.cfg.I18nDir == "" {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(filepath.Join(s.cfg.I18nDir, lang+".json"))
	if err != nil {
		return nil, err
	}
	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return nil, err
	}
	return dict, nil
}
