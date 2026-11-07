package worker

import (
	"fmt"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"github.com/asvas/execution-plane/internal/checks"
)

var statusPB = map[string]pb.JobStatus{
	"SUCCEEDED": pb.JobStatus_JOB_STATUS_SUCCEEDED, "FAILED": pb.JobStatus_JOB_STATUS_FAILED,
	"TIMED_OUT": pb.JobStatus_JOB_STATUS_TIMED_OUT, "CANCELLED": pb.JobStatus_JOB_STATUS_CANCELLED,
	"DENIED": pb.JobStatus_JOB_STATUS_DENIED,
}

// ResultToPB converts the executor's result into the wire message.
func ResultToPB(r Result) *pb.JobResult {
	m := &pb.JobResult{JobId: r.JobID, Attempt: int32(r.Attempt), TenantId: r.TenantID, AssessmentId: r.AssessmentID,
		WorkerId: r.WorkerID, Status: statusPB[r.Status], Error: r.Error, Backend: r.Backend, EgressMode: r.EgressMode,
		RequestsUsed: int32(r.RequestsUsed), StartedUnix: r.StartedUnix, FinishedUnix: r.FinishedUnix,
		SandboxAttestation: map[string]string{}}
	if d := r.PolicyDecision; d != nil {
		m.PolicyDecision = &pb.PolicyDecision{Allow: d.Allow, RequireApproval: d.RequireApproval,
			ApprovalSatisfied: d.ApprovalSatisfied, DenyReasons: d.DenyReasons, Error: d.Error, Engine: d.Engine, Plane: d.Plane}
	}
	for k, v := range r.Attestation {
		m.SandboxAttestation[k] = fmt.Sprint(v)
	}
	for _, x := range r.Exchanges {
		m.Exchanges = append(m.Exchanges, exchangeToPB(x))
	}
	return m
}

func exchangeToPB(x checks.Exchange) *pb.Exchange {
	e := &pb.Exchange{Seq: int32(x.Seq), StartedUnixMs: x.StartedUnixMS, DurationMs: x.DurationMS,
		Request: &pb.Request{Method: x.Request.Method, Url: x.Request.URL, Scheme: x.Request.Scheme, Host: x.Request.Host,
			Port: int32(x.Request.Port), Path: x.Request.Path, ResolvedIp: x.Request.ResolvedIP}, Error: x.Error}
	if rs := x.Response; rs != nil {
		e.Response = &pb.Response{Status: int32(rs.Status), BodySha256: rs.BodySHA256, BodyLen: int32(rs.BodyLen),
			BodyTruncated: rs.BodyTruncated, BodyExcerpt: rs.BodyExcerpt, TlsVersion: rs.TLSVersion}
		for _, h := range rs.Headers {
			e.Response.Headers = append(e.Response.Headers, &pb.Header{Name: h[0], Value: h[1]})
		}
	}
	if rd := x.Redirect; rd != nil {
		e.Redirect = &pb.Redirect{Location: rd.Location, Decision: rd.Decision, Reason: rd.Reason}
	}
	if t := x.TLS; t != nil {
		e.Tls = &pb.TLSInfo{Probe: t.Probe, Handshake: t.Handshake, Version: t.Version, CipherSuite: t.CipherSuite,
			Alpn: t.ALPN, VerifyError: t.VerifyError, HostnameError: t.HostnameError, LeafSubject: t.LeafSubject,
			LeafIssuer: t.LeafIssuer, LeafSans: t.LeafSANs, LeafNotBefore: t.LeafNotBefore, LeafNotAfter: t.LeafNotAfter,
			LeafSha256: t.LeafSHA256, SelfSigned: t.SelfSigned, DaysUntilExpiry: int32(t.DaysUntilExpiry),
			ExpiryWarningDays: int32(t.ExpiryWarningDays), ChainLength: int32(t.ChainLength)}
	}
	return e
}
