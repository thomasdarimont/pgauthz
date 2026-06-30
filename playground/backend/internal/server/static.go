package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleStatic serves the SPA from webDir, mapping the public base path to files
// and falling back to index.html for client-side routes.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Map the public path (under basePath) to a file under webDir.
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, s.cfg.BasePath))
	p := filepath.Join(s.cfg.WebDir, clean)
	if !strings.HasPrefix(p, filepath.Clean(s.cfg.WebDir)) {
		http.NotFound(w, r)
		return
	}
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		p = filepath.Join(s.cfg.WebDir, "index.html") // SPA fallback
	}
	http.ServeFile(w, r, p)
}
