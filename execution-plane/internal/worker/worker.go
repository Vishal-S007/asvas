// Package worker consumes signed job envelopes from Redis Streams and executes them through the
// policy engine and sandbox backend, publishing signed results.
package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"github.com/asvas/execution-plane/internal/canonical"
	"github.com/asvas/execution-plane/internal/checks"
	"github.com/asvas/execution-plane/internal/envelope"
	"github.com/asvas/execution-plane/internal/netguard"
	"github.com/asvas/execution-plane/internal/policy"
	"github.com/asvas/execution-plane/internal/sandbox"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

const (
	Jobs     = "asvas:jobs"
	Results  = "asvas:results"
	Control  = "asvas:control"
	Workers  = "asvas:workers"
	Group    = "executors"
	MaxIssue = 10 * time.Minute
)

type Config struct {
	WorkerID  string
	Slots     int
	MasterKey string
	Net       netguard.Config
	Resolver  netguard.Resolver
	PolicySHA string
	Version   string
	GRPCAddr  string // advertised mTLS address of this executor's ExecutorService ("" = disabled)
}

type running struct {
	tenant, assessment string
	cancel             context.CancelCauseFunc
}

type Worker struct {
	cfg     Config
	rdb     *redis.Client
	pol     *policy.Engine
	sb      sandbox.Backend
	keys    struct{ env, res, appr, ctl []byte }
	slots   chan int
	mu      sync.Mutex
	active  map[string]*running // job_id -> running
	log     *slog.Logger
	started time.Time
}

func New(cfg Config, rdb *redis.Client, pol *policy.Engine, sb sandbox.Backend, log *slog.Logger) *Worker {
	w := &Worker{cfg: cfg, rdb: rdb, pol: pol, sb: sb, active: map[string]*running{}, log: log, started: time.Now()}
	w.keys.env = canonical.DerivedKey(cfg.MasterKey, "envelope")
	w.keys.res = canonical.DerivedKey(cfg.MasterKey, "result")
	w.keys.appr = canonical.DerivedKey(cfg.MasterKey, "approval")
	w.keys.ctl = canonical.DerivedKey(cfg.MasterKey, "control")
	w.slots = make(chan int, cfg.Slots)
	for i := 1; i <= cfg.Slots; i++ {
		w.slots <- i
	}
	if w.cfg.Resolver == nil {
		w.cfg.Resolver = netguard.SystemResolver
	}
	return w
}

// Result is the signed message returned to the control plane.
type Result struct {
	JobID          string            `json:"job_id"`
	Attempt        int               `json:"attempt"`
	TenantID       string            `json:"tenant_id"`
	AssessmentID   string            `json:"assessment_id"`
	WorkerID       string            `json:"worker_id"`
	Status         string            `json:"status"` // SUCCEEDED FAILED TIMED_OUT CANCELLED DENIED
	Error          string            `json:"error,omitempty"`
	PolicyDecision *policy.Decision  `json:"policy_decision,omitempty"`
	Backend        string            `json:"backend"`
	EgressMode     string            `json:"egress_mode"`
	RequestsUsed   int               `json:"requests_used"`
	Exchanges      []checks.Exchange `json:"exchanges"`
	Attestation    map[string]any    `json:"sandbox_attestation,omitempty"`
	StartedUnix    int64             `json:"started_unix"`
	FinishedUnix   int64             `json:"finished_unix"`
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.rdb.XGroupCreateMkStream(ctx, Jobs, Group, "0").Err(); err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	go w.heartbeat(ctx)
	go w.controlLoop(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	for ctx.Err() == nil {
		// Reclaim messages from crashed executors; claim keys prevent double execution.
		if msgs, _, err := w.rdb.XAutoClaim(ctx, &redis.XAutoClaimArgs{Stream: Jobs, Group: Group, Consumer: w.cfg.WorkerID,
			MinIdle: 30 * time.Second, Start: "0-0", Count: 5}).Result(); err == nil {
			for _, m := range msgs {
				w.dispatch(ctx, &wg, m)
			}
		}
		free := len(w.slots)
		if free == 0 {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		res, err := w.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{Group: Group, Consumer: w.cfg.WorkerID,
			Streams: []string{Jobs, ">"}, Count: int64(free), Block: time.Second}).Result()
		if err != nil {
			if !errors.Is(err, redis.Nil) && ctx.Err() == nil {
				w.log.Error("xreadgroup", "err", err)
				time.Sleep(time.Second)
			}
			continue
		}
		for _, s := range res {
			for _, m := range s.Messages {
				w.dispatch(ctx, &wg, m)
			}
		}
	}
	return ctx.Err()
}

func (w *Worker) dispatch(ctx context.Context, wg *sync.WaitGroup, m redis.XMessage) {
	slot := <-w.slots
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { w.slots <- slot }()
		w.handle(ctx, slot, m)
		w.rdb.XAck(context.Background(), Jobs, Group, m.ID)
	}()
}

func (w *Worker) handle(ctx context.Context, slot int, m redis.XMessage) {
	b64, _ := m.Values["envelope_pb"].(string)
	sig, _ := m.Values["sig"].(string)
	data, derr := base64.StdEncoding.DecodeString(b64)
	if derr != nil {
		w.log.Warn("rejected envelope: not base64", "stream_id", m.ID)
		return
	}
	env, err := envelope.OpenPB(data, sig, w.keys.env)
	if err != nil {
		// Unauthenticated or malformed: nothing about it can be trusted, including its job id. Drop + log.
		w.log.Warn("rejected envelope", "stream_id", m.ID, "err", err)
		if env == nil || errors.Is(err, envelope.ErrBadSignature) {
			return
		}
		w.publish(ctx, w.base(env, "DENIED", "envelope validation failed: "+err.Error()))
		return
	}
	claim := fmt.Sprintf("asvas:claim:%s:%d", env.JobID, env.Attempt)
	ok, err := w.rdb.SetNX(ctx, claim, w.cfg.WorkerID, time.Hour).Result()
	if err != nil || !ok {
		w.log.Warn("duplicate delivery ignored", "job", env.JobID, "attempt", env.Attempt)
		return
	}
	w.publish(ctx, w.Execute(ctx, slot, env))
}

func (w *Worker) base(env *envelope.Envelope, status, msg string) Result {
	info := w.sb.Info()
	return Result{JobID: env.JobID, Attempt: env.Attempt, TenantID: env.TenantID, AssessmentID: env.AssessmentID,
		WorkerID: w.cfg.WorkerID, Status: status, Error: msg, Backend: info.Backend, EgressMode: info.EgressMode,
		Exchanges: []checks.Exchange{}, StartedUnix: time.Now().Unix(), FinishedUnix: time.Now().Unix()}
}

func (w *Worker) halted(ctx context.Context, env *envelope.Envelope) bool {
	n, err := w.rdb.Exists(ctx, "asvas:halt:tenant:"+env.TenantID, "asvas:halt:assessment:"+env.AssessmentID).Result()
	return err != nil || n > 0 // fail closed if Redis is unreachable
}

// Execute runs all execution-plane checks and, if everything passes, the sandboxed tool.
func (w *Worker) Execute(ctx context.Context, slot int, env *envelope.Envelope) Result {
	now := time.Now()
	if w.halted(ctx, env) {
		return w.base(env, "CANCELLED", "assessment cancelled or tenant emergency-stopped before execution")
	}
	if now.Unix() > env.DeadlineUnix {
		return w.base(env, "DENIED", "job envelope past its deadline")
	}
	if now.Sub(time.Unix(env.IssuedUnix, 0)) > MaxIssue {
		return w.base(env, "DENIED", "job envelope too old")
	}
	params, err := env.ToolParams()
	if err != nil {
		return w.base(env, "DENIED", err.Error())
	}
	approval := map[string]any{"present": false}
	if env.Approval != nil {
		ok, why := env.VerifyApproval(w.keys.appr)
		approval = map[string]any{"present": true, "verified": ok, "expires_unix": env.Approval.ExpiresUnix}
		if !ok {
			w.log.Warn("approval verification failed", "job", env.JobID, "why", why)
		}
	}
	// Resolve the job target and every scope target ONCE; these pinned addresses are all the sandbox may use.
	sts, err := env.ScopeTargets()
	if err != nil {
		return w.base(env, "DENIED", "scope document unreadable")
	}
	var ngTargets []netguard.ScopeTarget
	for _, t := range sts {
		ngTargets = append(ngTargets, netguard.ScopeTarget{Host: t.Host, Ports: t.Ports, Schemes: t.Schemes})
	}
	allowed, excluded := env.CIDRs("allowed_cidrs"), env.CIDRs("excluded_cidrs")
	addrs, rerr := w.cfg.Resolver(ctx, env.Target.Host)
	resolved := []any{}
	for _, a := range addrs {
		resolved = append(resolved, a.String())
	}
	allow, rejected := netguard.BuildAllowlist(ctx, w.cfg.Net, w.cfg.Resolver, ngTargets, allowed, excluded)
	input := w.policyInput(env, resolved, approval)
	dec := w.pol.Evaluate(ctx, input)
	if rerr != nil {
		dec.Allow = false
		dec.DenyReasons = append(dec.DenyReasons, "target resolution failed: "+rerr.Error())
	}
	var target netguard.Endpoint
	found := false
	for _, e := range allow {
		if e.Key() == (netguard.Endpoint{Scheme: env.Target.Scheme, Host: env.Target.Host, Port: env.Target.Port}).Key() {
			target, found = e, true
		}
	}
	if !found {
		dec.Allow = false
		dec.DenyReasons = append(dec.DenyReasons, fmt.Sprintf("target not in execution-plane allowlist (%v)", rejected))
	} else if !sameAddrs(target.IPs, addrs) {
		dec.Allow = false
		dec.DenyReasons = append(dec.DenyReasons, "DNS answers changed between resolutions (possible rebinding)")
	}
	if !dec.Allow {
		r := w.base(env, "DENIED", "execution-plane policy denied: "+fmt.Sprint(dec.DenyReasons))
		r.PolicyDecision = &dec
		return r
	}
	spec := checks.Spec{ToolID: env.ToolID, Target: target, Allow: allow, MaxRequests: env.MaxRequests,
		RPS: env.RequestsPerSecond}
	switch p := params.(type) {
	case envelope.SecurityHeadersParams:
		spec.Path, spec.Method, spec.MaxRedirect = p.Path, p.Method, p.MaxRedirects
	case envelope.AllowedMethodsParams:
		spec.Path = p.Path
	case envelope.TLSParams:
		spec.ExpiryDays = p.ExpiryWarningDays
	}
	remaining := time.Until(time.Unix(env.DeadlineUnix, 0))
	if lim := time.Duration(env.TimeoutSeconds) * time.Second; remaining > lim {
		remaining = lim
	}
	spec.TimeoutMS = remaining.Milliseconds()
	jctx, cancel := context.WithCancelCause(ctx)
	tctx, tcancel := context.WithTimeout(jctx, remaining)
	defer tcancel()
	defer cancel(nil)
	w.mu.Lock()
	w.active[env.JobID] = &running{tenant: env.TenantID, assessment: env.AssessmentID, cancel: cancel}
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.active, env.JobID); w.mu.Unlock() }()

	started := time.Now()
	res, err := w.sb.Run(tctx, slot, spec)
	out := w.base(env, "SUCCEEDED", res.Error)
	out.StartedUnix = started.Unix()
	out.PolicyDecision = &dec
	out.Exchanges = res.Exchanges
	if out.Exchanges == nil {
		out.Exchanges = []checks.Exchange{}
	}
	out.RequestsUsed = res.RequestsUsed
	out.Attestation = res.Attestation
	switch {
	case context.Cause(jctx) != nil && errors.Is(err, context.Canceled):
		out.Status, out.Error = "CANCELLED", "killed: "+context.Cause(jctx).Error()
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(tctx.Err(), context.DeadlineExceeded):
		out.Status, out.Error = "TIMED_OUT", "sandbox killed after timeout"
	case err != nil:
		out.Status, out.Error = "FAILED", err.Error()
	case len(res.Exchanges) == 0 || (res.Exchanges[0].Response == nil &&
		(res.Exchanges[0].TLS == nil || !res.Exchanges[0].TLS.Handshake)):
		out.Status = "FAILED"
		if out.Error == "" {
			out.Error = "no response from target"
		}
	}
	out.FinishedUnix = time.Now().Unix()
	return out
}

func sameAddrs(a []string, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, x := range b {
		if !set[x.String()] {
			return false
		}
	}
	return true
}

func (w *Worker) policyInput(env *envelope.Envelope, resolved []any, approval map[string]any) map[string]any {
	raw := func(m map[string]json.RawMessage) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			var x any
			_ = json.Unmarshal(v, &x)
			out[k] = x
		}
		return out
	}
	pp := []any{}
	for _, p := range w.cfg.Net.ProtectedPorts {
		pp = append(pp, p)
	}
	return map[string]any{
		"action": map[string]any{"tool_id": env.ToolID, "risk_tier": env.RiskTier, "category": env.Category,
			"max_requests": env.MaxRequests, "requests_per_second": env.RequestsPerSecond, "timeout_seconds": env.TimeoutSeconds},
		"target":   map[string]any{"scheme": env.Target.Scheme, "host": env.Target.Host, "port": env.Target.Port, "resolved_ips": resolved},
		"scope":    raw(env.Scope),
		"policy":   raw(env.Policy),
		"approval": approval,
		"context": map[string]any{"now_unix": time.Now().Unix(), "loopback_allowed": w.cfg.Net.AllowLoopback,
			"protected_ports": pp, "halted": false, "plane": "execution",
			"kernel_egress": strings.HasPrefix(w.sb.Info().EgressMode, "nftables")},
	}
}

func (w *Worker) publish(ctx context.Context, r Result) {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(ResultToPB(r))
	if err != nil {
		w.log.Error("encode result", "err", err, "job", r.JobID)
		return
	}
	if err := w.rdb.XAdd(context.Background(), &redis.XAddArgs{Stream: Results, MaxLen: 100000, Approx: true,
		Values: map[string]any{"result_pb": base64.StdEncoding.EncodeToString(data),
			"sig": canonical.HMACHexBytes(w.keys.res, data)}}).Err(); err != nil {
		w.log.Error("publish result", "err", err, "job", r.JobID)
	}
	w.log.Info("job finished", "job", r.JobID, "attempt", r.Attempt, "status", r.Status, "error", r.Error)
}

// Status reports live executor state for the gRPC GetStatus RPC.
func (w *Worker) Status() *pb.WorkerStatus {
	info := w.sb.Info()
	w.mu.Lock()
	n := len(w.active)
	w.mu.Unlock()
	return &pb.WorkerStatus{WorkerId: w.cfg.WorkerID, Backend: info.Backend, IsolationLevel: info.IsolationLevel,
		EgressMode: info.EgressMode, Note: info.Note, Slots: int32(w.cfg.Slots), RunningJobs: int32(n),
		PolicySha256: w.cfg.PolicySHA, Version: w.cfg.Version, Uid: int32(os.Geteuid()),
		LoopbackTargetsAllowed: w.cfg.Net.AllowLoopback, StartedUnix: w.started.Unix()}
}

// ApplyControl authenticates a serialized ControlMessage and kills matching running jobs.
// It is used by both the control stream and the gRPC Control RPC.
func (w *Worker) ApplyControl(data []byte, sig string) (int, error) {
	if !canonical.HMACVerifyBytes(w.keys.ctl, data, sig) {
		return 0, errors.New("control message signature invalid")
	}
	var msg pb.ControlMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		return 0, fmt.Errorf("control decode: %w", err)
	}
	if envelope.HasUnknownFields(msg.ProtoReflect()) {
		return 0, errors.New("control message carries unknown fields")
	}
	switch msg.GetType() {
	case pb.ControlType_CONTROL_TYPE_CANCEL_ASSESSMENT:
		if msg.GetAssessmentId() == "" {
			return 0, errors.New("cancel without assessment id")
		}
		n := w.KillMatching(msg.GetTenantId(), msg.GetAssessmentId(), "assessment cancelled: "+msg.GetReason())
		w.log.Warn("cancel_assessment", "assessment", msg.GetAssessmentId(), "killed", n)
		return n, nil
	case pb.ControlType_CONTROL_TYPE_EMERGENCY_STOP:
		n := w.KillMatching(msg.GetTenantId(), "", "emergency stop: "+msg.GetReason())
		w.log.Warn("EMERGENCY STOP", "tenant", msg.GetTenantId(), "killed", n)
		return n, nil
	}
	return 0, errors.New("unknown control type")
}

// KillMatching cancels running jobs for an assessment or a whole tenant. Returns how many were signalled.
func (w *Worker) KillMatching(tenant, assessment, reason string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, r := range w.active {
		if (assessment != "" && r.assessment == assessment) || (assessment == "" && r.tenant == tenant) {
			r.cancel(errors.New(reason))
			n++
		}
	}
	return n
}

func (w *Worker) controlLoop(ctx context.Context) {
	last := "$"
	for ctx.Err() == nil {
		res, err := w.rdb.XRead(ctx, &redis.XReadArgs{Streams: []string{Control, last}, Block: time.Second}).Result()
		if err != nil {
			continue
		}
		for _, s := range res {
			for _, m := range s.Messages {
				last = m.ID
				b64, _ := m.Values["control_pb"].(string)
				sig, _ := m.Values["sig"].(string)
				data, err := base64.StdEncoding.DecodeString(b64)
				if err == nil {
					_, err = w.ApplyControl(data, sig)
				}
				if err != nil {
					w.log.Warn("control message ignored", "err", err)
				}
			}
		}
	}
}

func (w *Worker) heartbeat(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		info := w.sb.Info()
		w.mu.Lock()
		n := len(w.active)
		w.mu.Unlock()
		hb, _ := json.Marshal(map[string]any{"heartbeat_unix": time.Now().Unix(), "backend": info.Backend,
			"isolation_level": info.IsolationLevel, "egress_mode": info.EgressMode, "note": info.Note,
			"syscall_monitor": info.SyscallMonitor,
			"slots":           w.cfg.Slots, "running_jobs": n, "policy_sha256": w.cfg.PolicySHA, "version": w.cfg.Version,
			"pid": os.Getpid(), "uid": os.Geteuid(), "started_unix": w.started.Unix(),
			"loopback_targets_allowed": w.cfg.Net.AllowLoopback, "grpc_addr": w.cfg.GRPCAddr})
		w.rdb.HSet(context.Background(), Workers, w.cfg.WorkerID, string(hb))
		select {
		case <-ctx.Done():
			w.rdb.HDel(context.Background(), Workers, w.cfg.WorkerID)
			return
		case <-t.C:
		}
	}
}
