// Package envelope decodes and authenticates job envelopes produced by the control plane.
//
// Nothing in an envelope is trusted until the HMAC over the exact received bytes verifies.
// Decoding is strict: unknown fields are rejected, and tool parameters are re-validated here,
// independently of the control plane's validation.
package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/asvas/execution-plane/internal/canonical"
)

type Target struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

type Approval struct {
	ApprovalID  string `json:"approval_id"`
	BindingHash string `json:"binding_hash"`
	ExpiresUnix int64  `json:"expires_unix"`
	Token       string `json:"token"`
}

type ScopeTarget struct {
	Host    string   `json:"host"`
	Ports   []int    `json:"ports"`
	Schemes []string `json:"schemes"`
}

type Envelope struct {
	V                 int                        `json:"v"`
	JobID             string                     `json:"job_id"`
	Attempt           int                        `json:"attempt"`
	TenantID          string                     `json:"tenant_id"`
	AssessmentID      string                     `json:"assessment_id"`
	ToolID            string                     `json:"tool_id"`
	RiskTier          string                     `json:"risk_tier"`
	Category          string                     `json:"category"`
	Target            Target                     `json:"target"`
	Params            json.RawMessage            `json:"params"`
	MaxRequests       int                        `json:"max_requests"`
	RequestsPerSecond int                        `json:"requests_per_second"`
	TimeoutSeconds    int                        `json:"timeout_seconds"`
	DeadlineUnix      int64                      `json:"deadline_unix"`
	IssuedUnix        int64                      `json:"issued_unix"`
	Scope             map[string]json.RawMessage `json:"scope"`
	Policy            map[string]json.RawMessage `json:"policy"`
	Approval          *Approval                  `json:"approval"`
}

// SecurityHeadersParams / AllowedMethodsParams mirror control-plane/asvas/tools.py.
type SecurityHeadersParams struct {
	Path         string `json:"path"`
	Method       string `json:"method"`
	MaxRedirects int    `json:"max_redirects"`
}

type AllowedMethodsParams struct {
	Path string `json:"path"`
}

var (
	pathRE = regexp.MustCompile(`^/[A-Za-z0-9/._~\-]{0,255}$`)
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hostRE = regexp.MustCompile(`^[a-z0-9.:\-]{1,253}$`)
)

var ErrBadSignature = errors.New("envelope signature invalid")

func strictDecode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Open verifies the HMAC over the raw body and strictly decodes it.
func Open(body, sig string, envelopeKey []byte) (*Envelope, error) {
	if !canonical.HMACVerify(envelopeKey, body, sig) {
		return nil, ErrBadSignature
	}
	var e Envelope
	if err := strictDecode([]byte(body), &e); err != nil {
		return nil, fmt.Errorf("envelope decode: %w", err)
	}
	return &e, e.validate()
}

func (e *Envelope) validate() error {
	switch {
	case e.V != 1:
		return errors.New("unsupported envelope version")
	case !uuidRE.MatchString(e.JobID) || !uuidRE.MatchString(e.TenantID) || !uuidRE.MatchString(e.AssessmentID):
		return errors.New("malformed identifiers")
	case e.Attempt < 1 || e.Attempt > 3:
		return errors.New("attempt out of range")
	case e.Target.Scheme != "http" && e.Target.Scheme != "https":
		return errors.New("scheme must be http or https")
	case !hostRE.MatchString(e.Target.Host):
		return errors.New("malformed host")
	case e.Target.Port < 1 || e.Target.Port > 65535:
		return errors.New("port out of range")
	case e.TimeoutSeconds < 1 || e.TimeoutSeconds > 300:
		return errors.New("timeout out of range (hard limit 300 s)")
	case e.RequestsPerSecond < 1 || e.RequestsPerSecond > 10:
		return errors.New("requests_per_second out of range")
	case e.MaxRequests < 1 || e.MaxRequests > 10:
		return errors.New("max_requests out of range")
	}
	_, err := e.ToolParams()
	return err
}

// ToolParams validates params for the envelope's tool. Unknown tools are rejected: there is no generic tool.
func (e *Envelope) ToolParams() (any, error) {
	switch e.ToolID {
	case "http.security_headers":
		var p SecurityHeadersParams
		if err := strictDecode(e.Params, &p); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
		if !pathRE.MatchString(p.Path) || strings.Contains(p.Path, "..") {
			return nil, errors.New("params: invalid path")
		}
		if p.Method != "GET" && p.Method != "HEAD" {
			return nil, errors.New("params: method must be GET or HEAD")
		}
		if p.MaxRedirects < 0 || p.MaxRedirects > 3 {
			return nil, errors.New("params: max_redirects out of range")
		}
		return p, nil
	case "http.allowed_methods":
		var p AllowedMethodsParams
		if err := strictDecode(e.Params, &p); err != nil {
			return nil, fmt.Errorf("params: %w", err)
		}
		if !pathRE.MatchString(p.Path) || strings.Contains(p.Path, "..") {
			return nil, errors.New("params: invalid path")
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", e.ToolID)
	}
}

// BindingHash recomputes, from the fields that will actually be executed, the hash an approval is bound to.
func (e *Envelope) BindingHash() (string, error) {
	var params any
	d := json.NewDecoder(bytes.NewReader(e.Params))
	d.UseNumber()
	if err := d.Decode(&params); err != nil {
		return "", err
	}
	v, err := canonical.Normalize(map[string]any{
		"assessment_id": e.AssessmentID, "job_id": e.JobID, "tool_id": e.ToolID,
		"target": map[string]any{"scheme": e.Target.Scheme, "host": e.Target.Host, "port": e.Target.Port},
	})
	if err != nil {
		return "", err
	}
	v.(map[string]any)["params"] = params
	s, err := canonical.Marshal(v)
	if err != nil {
		return "", err
	}
	return canonical.SHA256Hex(s), nil
}

// VerifyApproval checks the approval token HMAC and that it is bound to exactly these parameters.
func (e *Envelope) VerifyApproval(approvalKey []byte) (bool, string) {
	if e.Approval == nil {
		return false, "no approval"
	}
	bh, err := e.BindingHash()
	if err != nil {
		return false, "cannot compute binding: " + err.Error()
	}
	if bh != e.Approval.BindingHash {
		return false, "approval binding does not match job parameters"
	}
	msg, err := canonical.Marshal(map[string]any{
		"approval_id": e.Approval.ApprovalID, "binding_hash": e.Approval.BindingHash, "expires_unix": e.Approval.ExpiresUnix,
	})
	if err != nil {
		return false, err.Error()
	}
	if !canonical.HMACVerify(approvalKey, msg, e.Approval.Token) {
		return false, "approval token signature invalid"
	}
	return true, ""
}

// ScopeTargets returns the signed scope's targets.
func (e *Envelope) ScopeTargets() ([]ScopeTarget, error) {
	var ts []ScopeTarget
	if err := json.Unmarshal(e.Scope["targets"], &ts); err != nil {
		return nil, err
	}
	return ts, nil
}

func (e *Envelope) CIDRs(key string) []string {
	var out []string
	if raw, ok := e.Scope[key]; ok {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}
