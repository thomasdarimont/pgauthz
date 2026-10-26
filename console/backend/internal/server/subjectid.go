package server

// Who signed in: the person's id in the console store, resolved from the
// ID token's claims — a list of claims tried in order (the first non-empty
// wins; CONSOLE_SUBJECT_ID_CLAIMS, default preferred_username then sub),
// or a CEL expression over `claims` (CONSOLE_SUBJECT_ID_CEL) for identity
// providers whose claims need shaping (the strings extension is on): `claims.upn`,
// `has(claims.email) ? claims.email.split('@')[0] : claims.sub`. The
// expression is compiled once; it must yield a non-empty string.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"thomasdarimont.de/authz/console-bff/internal/config"
)

type subjectResolver struct {
	once sync.Once
	prog cel.Program
	err  error
}

func (s *Server) subjectID(claims map[string]any) (string, error) {
	if s.cfg.SubjectIDCEL != "" {
		s.subject.once.Do(func() {
			env, err := cel.NewEnv(cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)), ext.Strings()) // ext: split, lowerAscii, …
			if err != nil {
				s.subject.err = err
				return
			}
			ast, iss := env.Compile(s.cfg.SubjectIDCEL)
			if iss.Err() != nil {
				s.subject.err = fmt.Errorf("CONSOLE_SUBJECT_ID_CEL: %w", iss.Err())
				return
			}
			s.subject.prog, s.subject.err = env.Program(ast)
		})
		if s.subject.err != nil {
			return "", s.subject.err
		}
		out, _, err := s.subject.prog.Eval(map[string]any{"claims": claims})
		if err != nil {
			return "", fmt.Errorf("CONSOLE_SUBJECT_ID_CEL: %w", err)
		}
		id, ok := out.Value().(string)
		if !ok || strings.TrimSpace(id) == "" {
			return "", errors.New("CONSOLE_SUBJECT_ID_CEL yielded no non-empty string for this ID token")
		}
		return strings.TrimSpace(id), nil
	}
	claimsTried := s.cfg.SubjectIDClaims
	if len(claimsTried) == 0 {
		claimsTried = []string{"preferred_username", "sub"}
	}
	for _, c := range claimsTried {
		if config.TechnicalClaims[strings.TrimSpace(c)] {
			continue // refused by config.Validate; never an identity even if it slipped through
		}
		if v, ok := claimPath(claims, c).(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("the ID token carries none of the claims %s (CONSOLE_SUBJECT_ID_CLAIMS); is the openid scope requested?", strings.Join(claimsTried, ", "))
}
