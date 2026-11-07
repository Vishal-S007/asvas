package envelope

import (
	"encoding/json"
	"errors"
	"fmt"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"github.com/asvas/execution-plane/internal/canonical"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const WireVersion = 2

// HasUnknownFields reports whether m or any nested message carries fields this build does not know.
func HasUnknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					found = found || HasUnknownFields(mv.Message())
					return !found
				})
			}
		case fd.IsList() && fd.Message() != nil:
			for i := 0; i < v.List().Len() && !found; i++ {
				found = HasUnknownFields(v.List().Get(i).Message())
			}
		case fd.Message() != nil:
			found = HasUnknownFields(v.Message())
		}
		return !found
	})
	return found
}

// OpenPB authenticates a serialized JobEnvelope (HMAC over the exact bytes), decodes it, rejects unknown fields,
// and returns the validated Envelope.
func OpenPB(data []byte, sig string, envelopeKey []byte) (*Envelope, error) {
	if !canonical.HMACVerifyBytes(envelopeKey, data, sig) {
		return nil, ErrBadSignature
	}
	var m pb.JobEnvelope
	if err := proto.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("envelope decode: %w", err)
	}
	if HasUnknownFields(m.ProtoReflect()) {
		return nil, errors.New("envelope carries unknown fields")
	}
	if m.GetVersion() != WireVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", m.GetVersion())
	}
	e, err := fromPB(&m)
	if err != nil {
		return nil, err
	}
	return e, e.validate()
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func fromPB(m *pb.JobEnvelope) (*Envelope, error) {
	e := &Envelope{V: 1, JobID: m.GetJobId(), Attempt: int(m.GetAttempt()), TenantID: m.GetTenantId(),
		AssessmentID: m.GetAssessmentId(), ToolID: m.GetToolId(), RiskTier: m.GetRiskTier(), Category: m.GetCategory(),
		MaxRequests: int(m.GetMaxRequests()), RequestsPerSecond: int(m.GetRequestsPerSecond()),
		TimeoutSeconds: int(m.GetTimeoutSeconds()), DeadlineUnix: m.GetDeadlineUnix(), IssuedUnix: m.GetIssuedUnix()}
	if t := m.GetTarget(); t != nil {
		e.Target = Target{Scheme: t.GetScheme(), Host: t.GetHost(), Port: int(t.GetPort())}
	}
	// The oneof must match the tool; params are re-expressed with the exact key set the control plane hashes.
	switch p := m.GetParams().(type) {
	case *pb.JobEnvelope_SecurityHeaders:
		if e.ToolID != "http.security_headers" {
			return nil, errors.New("params do not match tool_id")
		}
		e.Params = mustJSON(SecurityHeadersParams{Path: p.SecurityHeaders.GetPath(), Method: p.SecurityHeaders.GetMethod(),
			MaxRedirects: int(p.SecurityHeaders.GetMaxRedirects())})
	case *pb.JobEnvelope_AllowedMethods:
		if e.ToolID != "http.allowed_methods" {
			return nil, errors.New("params do not match tool_id")
		}
		e.Params = mustJSON(AllowedMethodsParams{Path: p.AllowedMethods.GetPath()})
	case *pb.JobEnvelope_Tls:
		if e.ToolID != "tls.configuration" {
			return nil, errors.New("params do not match tool_id")
		}
		e.Params = mustJSON(TLSParams{ExpiryWarningDays: int(p.Tls.GetExpiryWarningDays())})
	default:
		return nil, errors.New("envelope has no tool parameters")
	}
	s := m.GetScope()
	if s == nil || s.GetAuthorization() == nil || m.GetPolicy() == nil {
		return nil, errors.New("envelope lacks scope, authorization or policy")
	}
	targets := make([]map[string]any, 0, len(s.GetTargets()))
	for _, t := range s.GetTargets() {
		targets = append(targets, map[string]any{"host": t.GetHost(), "ports": t.GetPorts(), "schemes": t.GetSchemes()})
	}
	a := s.GetAuthorization()
	e.Scope = map[string]json.RawMessage{
		"targets":        mustJSON(targets),
		"allowed_cidrs":  mustJSON(nonNil(s.GetAllowedCidrs())),
		"excluded_cidrs": mustJSON(nonNil(s.GetExcludedCidrs())),
		"authorization": mustJSON(map[string]string{"statement": a.GetStatement(), "reference": a.GetReference(),
			"authorized_by": a.GetAuthorizedBy(), "valid_from": a.GetValidFrom(), "valid_until": a.GetValidUntil()}),
	}
	p := m.GetPolicy()
	e.Policy = map[string]json.RawMessage{
		"allowed_tools":                mustJSON(nonNil(p.GetAllowedTools())),
		"approval_required_risk_tiers": mustJSON(nonNil(p.GetApprovalRequiredRiskTiers())),
		"max_requests_per_second":      mustJSON(p.GetMaxRequestsPerSecond()),
		"max_total_requests":           mustJSON(p.GetMaxTotalRequests()),
		"job_timeout_seconds":          mustJSON(p.GetJobTimeoutSeconds()),
		"require_kernel_egress":        mustJSON(p.GetRequireKernelEgress()),
	}
	if ap := m.GetApproval(); ap != nil {
		e.Approval = &Approval{ApprovalID: ap.GetApprovalId(), BindingHash: ap.GetBindingHash(),
			ExpiresUnix: ap.GetExpiresUnix(), Token: ap.GetToken()}
	}
	return e, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
