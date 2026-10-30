// Package policy evaluates the shared Rego bundle (policies/) inside the execution plane with the
// embedded OPA library. This is the second, independent policy decision before any tool runs.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

type Decision struct {
	Allow             bool     `json:"allow"`
	RequireApproval   bool     `json:"require_approval"`
	ApprovalSatisfied bool     `json:"approval_satisfied"`
	DenyReasons       []string `json:"deny_reasons"`
	Error             string   `json:"error,omitempty"`
	Engine            string   `json:"engine"`
	Plane             string   `json:"plane"`
}

type Engine struct {
	query  rego.PreparedEvalQuery
	SHA256 string
	Files  []string
}

// Load compiles every non-test .rego file in dir. Missing or invalid policy => error (caller must refuse to run).
func Load(ctx context.Context, dir string) (*Engine, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*.rego"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	h := sha256.New()
	opts := []func(*rego.Rego){rego.Query("data.asvas.decision.decision")}
	var files []string
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.rego") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		h.Write(b)
		opts = append(opts, rego.Module(p, string(b)))
		files = append(files, filepath.Base(p))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no policy files found under %s", dir)
	}
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{query: q, SHA256: hex.EncodeToString(h.Sum(nil)), Files: files}, nil
}

// Evaluate fails closed: any error yields a deny decision.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) Decision {
	d := Decision{Engine: "opa-embedded", Plane: "execution"}
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err == nil && (len(rs) != 1 || len(rs[0].Expressions) != 1) {
		err = errors.New("policy returned no decision")
	}
	if err != nil {
		d.DenyReasons = []string{"policy evaluation failed: deny by default"}
		d.Error = err.Error()
		return d
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		d.DenyReasons = []string{"malformed policy decision"}
		return d
	}
	d.Allow, _ = m["allow"].(bool)
	d.RequireApproval, _ = m["require_approval"].(bool)
	d.ApprovalSatisfied, _ = m["approval_satisfied"].(bool)
	if rr, ok := m["deny_reasons"].([]any); ok {
		for _, r := range rr {
			if s, ok := r.(string); ok {
				d.DenyReasons = append(d.DenyReasons, s)
			}
		}
	}
	return d
}
