// asvas-executor: ASVAS execution plane (Go). See docs/architecture.md.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	if len(os.Args) > 1 && (os.Args[1] == "sandbox-child" || os.Args[1] == "egress-probe") {
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
	for _, p := range strings.Split(env("ASVAS_PROTECTED_PORTS", "5432,6379,8000,8181,5173,7474,7687,6333"), ",") {
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
		sb = d
	default:
		return fmt.Errorf("unknown ASVAS_EXECUTION_BACKEND")
	}
	opt, err := redis.ParseURL(env("ASVAS_REDIS_URL", "redis://localhost:6379/0"))
	if err != nil {
		return err
	}
	rdb := redis.NewClient(opt)
	host, _ := os.Hostname()
	w := worker.New(worker.Config{WorkerID: fmt.Sprintf("%s-%d", host, os.Getpid()), Slots: slots, MasterKey: key,
		Net: netguard.Config{AllowLoopback: allowLoop, ProtectedPorts: ports}, PolicySHA: pol.SHA256, Version: version},
		rdb, pol, sb, log)
	info := sb.Info()
	log.Info("executor started", "backend", info.Backend, "isolation", info.IsolationLevel, "egress", info.EgressMode,
		"policy_sha256", pol.SHA256, "slots", slots, "loopback_targets", allowLoop)
	err = w.Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
