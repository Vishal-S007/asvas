// asvas-executor: ASVAS execution plane (Go). See docs/architecture.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"github.com/asvas/execution-plane/internal/grpcserver"
	"github.com/asvas/execution-plane/internal/netguard"
	"github.com/asvas/execution-plane/internal/policy"
	"github.com/asvas/execution-plane/internal/sandbox"
	"github.com/asvas/execution-plane/internal/worker"
	"github.com/redis/go-redis/v9"
)

const version = "0.1.0-m1"

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "sandbox-child" || os.Args[1] == "egress-probe" || os.Args[1] == "exec-probe") {
		os.Exit(sandbox.ChildMain(os.Args[1]))
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("executor exiting", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	envName := env("ASVAS_ENV", "development")
	key := env("ASVAS_SIGNING_KEY", "dev-only-change-me")
	if envName == "production" && key == "dev-only-change-me" {
		return fmt.Errorf("ASVAS_SIGNING_KEY must be set outside development")
	}
	allowLoop := env("ASVAS_ALLOW_LOOPBACK_TARGETS", "false") == "true"
	if envName == "production" && allowLoop {
		return fmt.Errorf("loopback targets cannot be enabled in production")
	}
	var ports []int
	for _, p := range strings.Split(env("ASVAS_PROTECTED_PORTS", "5432,6379,8000,8181,5173,7474,7687,6333,7443"), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, n)
		}
	}
	slots, _ := strconv.Atoi(env("ASVAS_EXECUTOR_SLOTS", "4"))
	if base, err := strconv.Atoi(env("ASVAS_SANDBOX_BASE_UID", "61000")); err == nil && base >= 1000 {
		sandbox.BaseUID = base
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pol, err := policy.Load(ctx, env("ASVAS_POLICY_DIR", "../policies"))
	if err != nil {
		return fmt.Errorf("refusing to start without policy: %w", err)
	}
	var sb sandbox.Backend
	switch env("ASVAS_EXECUTION_BACKEND", "devprocess") {
	case "firecracker":
		if _, err := sandbox.NewFirecracker(); err != nil {
			return err
		}
	case "devprocess":
		d, err := sandbox.NewDevProcess(slots)
		if err != nil {
			return err
		}
		if d.Egress() != nil {
			defer d.Egress().Teardown()
			// Prove kernel egress filtering works before accepting jobs.
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			ok, detail := d.SelfTest(ctx, ln.Addr().(*net.TCPAddr).Port)
			ln.Close()
			if !ok {
				d.SetEgressMode("app-pinned-only (nftables self-test FAILED: sandbox reached a non-allowlisted port)")
				log.Error("egress self-test failed", "detail", detail)
			} else {
				log.Info("egress self-test passed", "detail", detail)
			}
		}
		if ok, detail := d.SyscallSelfTest(ctx); ok {
			log.Info("syscall monitor self-test passed", "detail", detail)
		} else if d.Info().SyscallMonitor != "" && strings.HasPrefix(d.Info().SyscallMonitor, "ebpf") {
			d.SetSyscallMonitor("ebpf self-test FAILED: " + detail)
			log.Error("syscall monitor self-test failed", "detail", detail)
		}
		sb = d
	default:
		return fmt.Errorf("unknown ASVAS_EXECUTION_BACKEND")
	}
	opt, err := redis.ParseURL(env("ASVAS_REDIS_URL", "redis://localhost:6379/0"))
	if err != nil {
		return err
	}
	if opt.TLSConfig != nil { // rediss://: verify against the configured CA (or system roots)
		opt.TLSConfig.MinVersion = tls.VersionTLS12
		if caFile := env("ASVAS_REDIS_CA", ""); caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return fmt.Errorf("redis CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("redis CA: no certificates in %s", caFile)
			}
			opt.TLSConfig.RootCAs = pool
		}
	} else if envName == "production" {
		return fmt.Errorf("ASVAS_REDIS_URL must use rediss:// (TLS) outside development")
	}
	rdb := redis.NewClient(opt)
	host, _ := os.Hostname()
	cfg := worker.Config{WorkerID: fmt.Sprintf("%s-%d", host, os.Getpid()), Slots: slots, MasterKey: key,
		Net: netguard.Config{AllowLoopback: allowLoop, ProtectedPorts: ports}, PolicySHA: pol.SHA256, Version: version}
	ca, crt, tkey := env("ASVAS_TLS_CA", ""), env("ASVAS_TLS_CERT", ""), env("ASVAS_TLS_KEY", "")
	var w *worker.Worker
	if ca != "" && crt != "" && tkey != "" {
		tlsCfg, err := grpcserver.LoadTLSConfig(ca, crt, tkey)
		if err != nil {
			return fmt.Errorf("executor TLS: %w", err)
		}
		lazy := &lazyBackend{}
		addr, err := grpcserver.Serve(ctx, env("ASVAS_GRPC_ADDR", "127.0.0.1:7443"), grpcserver.New(tlsCfg, lazy))
		if err != nil {
			return err
		}
		cfg.GRPCAddr = addr.String()
		w = worker.New(cfg, rdb, pol, sb, log)
		lazy.w = w
		log.Info("ExecutorService listening (mutual TLS 1.3)", "addr", cfg.GRPCAddr)
	} else {
		if envName == "production" {
			return fmt.Errorf("ASVAS_TLS_CA/CERT/KEY are required outside development")
		}
		log.Warn("ExecutorService disabled: no TLS material configured (development only)")
		w = worker.New(cfg, rdb, pol, sb, log)
	}
	info := sb.Info()
	log.Info("executor started", "backend", info.Backend, "isolation", info.IsolationLevel, "egress", info.EgressMode,
		"policy_sha256", pol.SHA256, "slots", slots, "loopback_targets", allowLoop)
	err = w.Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// lazyBackend lets the gRPC server start (and its address be advertised) before the worker exists.
type lazyBackend struct{ w *worker.Worker }

func (l *lazyBackend) Status() *pb.WorkerStatus {
	if l.w == nil {
		return &pb.WorkerStatus{}
	}
	return l.w.Status()
}

func (l *lazyBackend) ApplyControl(data []byte, sig string) (int, error) {
	if l.w == nil {
		return 0, fmt.Errorf("executor starting")
	}
	return l.w.ApplyControl(data, sig)
}
