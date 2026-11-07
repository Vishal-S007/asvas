"""Test harness. Uses a dedicated database (asvas_test), Redis DB 15, a real OPA server and (for integration
tests) the real Go executor and local test target. Nothing contacts non-local systems."""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
os.environ.update({
    "ASVAS_ENV": "test",
    "ASVAS_DATABASE_URL": os.environ.get("TEST_DATABASE_URL",
                                         "postgresql+psycopg://asvas_app:asvas_app_dev@localhost:5432/asvas_test"),
    "ASVAS_MIGRATION_DATABASE_URL": os.environ.get("TEST_MIGRATION_DATABASE_URL",
                                                   "postgresql+psycopg://asvas_owner:asvas_owner_dev@localhost:5432/asvas_test"),
    "ASVAS_REDIS_URL": os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15"),
    "ASVAS_ALLOW_LOOPBACK_TARGETS": "true",
    "ASVAS_SIGNING_KEY": "test-signing-key-not-secret",
    "ASVAS_JWT_SECRET": "test-jwt-secret-not-secret-0123456789abcdef",
    "ASVAS_DISPATCH_GRACE_SECONDS": "2",
    "ASVAS_RATE_LIMIT_PER_MINUTE": "100000",
})


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port: int, timeout: float = 15) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open")


@pytest.fixture(scope="session")
def opa_url():
    opa = os.environ.get("OPA_BIN") or shutil.which("opa") or str(ROOT / ".tools" / "opa")
    if not Path(opa).exists():
        pytest.skip("OPA binary not available (set OPA_BIN)")
    port = _free_port()
    p = subprocess.Popen([opa, "run", "--server", "--addr", f"127.0.0.1:{port}", "--log-level", "error",
                          str(ROOT / "policies" / "asvas" / "decision.rego")])
    _wait_port(port)
    os.environ["ASVAS_OPA_URL"] = f"http://127.0.0.1:{port}"
    yield f"http://127.0.0.1:{port}"
    p.terminate()


@pytest.fixture(scope="session")
def migrated(opa_url):
    from asvas import cli
    from asvas.config import get_settings
    get_settings.cache_clear()
    cli.migrate(os.environ["ASVAS_MIGRATION_DATABASE_URL"])
    return True


@pytest.fixture()
def clean(migrated):
    """Truncate all data (TRUNCATE does not fire the append-only row triggers) and reseed users."""
    from sqlalchemy import create_engine, text

    from asvas.orchestration.bus import ensure_groups, get_redis
    from asvas.seed import seed
    eng = create_engine(os.environ["ASVAS_MIGRATION_DATABASE_URL"])
    with eng.begin() as c:
        c.execute(text("TRUNCATE tenants, users, assessments, plan_nodes, jobs, job_results, approvals, evidence, assets, "
                       "asset_relations, findings, finding_retests, audit_events, tenant_controls, "
                       "checkpoints, checkpoint_blobs, checkpoint_writes, reports CASCADE"))
    seed(eng)
    eng.dispose()
    r = get_redis()
    r.flushdb()
    ensure_groups(r)
    yield


@pytest.fixture()
def deps(clean):
    from asvas.orchestration.engine import Deps
    from asvas.planning.providers import DeterministicTestProvider
    return Deps(provider_factory=DeterministicTestProvider)


@pytest.fixture()
def client(deps):
    from fastapi.testclient import TestClient

    from asvas.api.app import create_app
    from asvas.auth import issue_token, lookup_user
    app = create_app(deps)
    c = TestClient(app)

    def as_user(email: str) -> dict:
        u = lookup_user(email=email)
        return {"Authorization": f"Bearer {issue_token(u['id'], u['tenant_id'], u['role'])}"}

    c.as_user = as_user  # type: ignore[attr-defined]
    return c


def scope_body(ports=(18080, 18081), host="127.0.0.1", cidrs=("127.0.0.1/32",), tools=("http.security_headers",),
               approval=("high",), valid_minutes=(-5, 1440), **policy):
    now = dt.datetime.now(dt.UTC)
    return {
        "name": "test assessment",
        "scope": {"targets": [{"host": host, "ports": list(ports), "schemes": ["http"]}],
                  "allowed_cidrs": list(cidrs),
                  "authorization": {"statement": "Local test target owned by the test suite; non-destructive.",
                                    "reference": "TEST-1", "authorized_by": "pytest",
                                    "valid_from": (now + dt.timedelta(minutes=valid_minutes[0])).isoformat(),
                                    "valid_until": (now + dt.timedelta(minutes=valid_minutes[1])).isoformat()}},
        "testing_policy": {"allowed_tools": list(tools), "approval_required_risk_tiers": list(approval), **policy},
    }


@pytest.fixture()
def make_assessment(client):
    def _make(email="operator@acme.test", **kw):
        r = client.post("/api/v1/assessments", json=scope_body(**kw), headers=client.as_user(email))
        assert r.status_code == 201, r.text
        return r.json()
    return _make


# ----------------------------------------------------------------------------- integration: real executor

@pytest.fixture(scope="session")
def target_server():
    weak, hard, tlsp = _free_port(), _free_port(), _free_port()
    flag = Path(os.environ.get("PYTEST_TMP", "/tmp")) / f"asvas-target-fixed-{weak}"
    flag.unlink(missing_ok=True)
    p = subprocess.Popen([sys.executable, str(ROOT / "test-target" / "target.py")],
                         env={**os.environ, "WEAK_PORT": str(weak), "HARDENED_PORT": str(hard), "TLS_PORT": str(tlsp),
                              "TARGET_FIXED_FLAG": str(flag)}, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    _wait_port(weak)
    _wait_port(hard)
    _wait_port(tlsp)
    yield {"weak": weak, "hardened": hard, "tls": tlsp, "fixed_flag": flag}
    p.terminate()
    flag.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def executor_bin():
    out = ROOT / "execution-plane" / "bin" / "asvas-executor"
    go = shutil.which("go") or "/usr/local/go/bin/go"
    try:
        subprocess.run([go, "build", "-o", str(out), "./cmd/asvas-executor"], cwd=ROOT / "execution-plane", check=True,
                       env={**os.environ, "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "auto")})
    except (OSError, subprocess.CalledProcessError) as e:
        pytest.skip(f"cannot build executor: {e}")
    out.chmod(0o755)
    return out


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    """Development PKI for the executor's mTLS gRPC endpoint (scripts/dev-certs.sh)."""
    d = tmp_path_factory.mktemp("pki")
    subprocess.run([str(ROOT / "scripts" / "dev-certs.sh"), str(d)], check=True, capture_output=True)
    return d


@pytest.fixture()
def executor(executor_bin, clean, target_server, pki, monkeypatch, tmp_path):
    from asvas.config import get_settings
    from asvas.orchestration.bus import WORKERS, get_redis
    s = get_settings()
    monkeypatch.setattr(s, "executor_tls_ca", str(pki / "ca.crt"))
    monkeypatch.setattr(s, "executor_tls_cert", str(pki / "control-plane.crt"))
    monkeypatch.setattr(s, "executor_tls_key", str(pki / "control-plane.key"))
    env = {"ASVAS_TLS_CA": str(pki / "ca.crt"), "ASVAS_TLS_CERT": str(pki / "executor.crt"),
           "ASVAS_TLS_KEY": str(pki / "executor.key"), "ASVAS_GRPC_ADDR": "127.0.0.1:0","PATH": os.environ.get("PATH", ""), "ASVAS_ENV": "development",
           "ASVAS_SIGNING_KEY": os.environ["ASVAS_SIGNING_KEY"], "ASVAS_REDIS_URL": os.environ["ASVAS_REDIS_URL"],
           "ASVAS_POLICY_DIR": str(ROOT / "policies"), "ASVAS_ALLOW_LOOPBACK_TARGETS": "true",
           "ASVAS_EXECUTOR_SLOTS": "3", "ASVAS_SANDBOX_BASE_UID": "62000"}
    log = open(tmp_path / "executor.log", "w")  # noqa: SIM115 - closed at teardown
    p = subprocess.Popen([str(executor_bin)], env=env, stderr=log, stdout=log, text=True)
    r = get_redis()
    end = time.time() + 20
    while time.time() < end and not r.hlen(WORKERS):
        time.sleep(0.1)
    if not r.hlen(WORKERS):
        p.kill()
        raise RuntimeError("executor did not register: " + (tmp_path / "executor.log").read_text())
    yield p
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
    log.close()


class Orchestrator:
    """In-process orchestrator loop (same handlers as `asvas orchestrator`)."""

    def __init__(self, deps):
        from asvas.orchestration import bus
        self.deps, self.bus = deps, bus
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.errors: list[BaseException] = []

    def _run(self):
        from asvas.cli import handle
        from asvas.orchestration import engine
        r = self.deps.r
        last = 0.0
        while not self.stop.is_set():
            resp = r.xreadgroup(self.bus.ORCH_GROUP, "pytest", {self.bus.RESULTS: ">", self.bus.ORCH: ">"},
                                count=20, block=200) or []
            for stream, msgs in resp:
                for mid, fields in msgs:
                    try:
                        handle(self.deps, stream, fields)
                    except BaseException as e:  # noqa: BLE001
                        self.errors.append(e)
                    r.xack(stream, self.bus.ORCH_GROUP, mid)
            if time.time() - last > 1:
                try:
                    engine.reap(self.deps)
                except BaseException as e:  # noqa: BLE001
                    self.errors.append(e)
                last = time.time()

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join(5)


@pytest.fixture()
def orchestrator(deps):
    with Orchestrator(deps) as o:
        yield o
    assert not o.errors, o.errors


def wait_status(client, headers, aid, statuses, timeout=60.0):
    end = time.time() + timeout
    a = None
    while time.time() < end:
        a = client.get(f"/api/v1/assessments/{aid}", headers=headers).json()
        if a["status"] in statuses:
            return a
        time.sleep(0.2)
    raise AssertionError(f"timeout waiting for {statuses}; last={json.dumps(a, default=str)[:500]}")
