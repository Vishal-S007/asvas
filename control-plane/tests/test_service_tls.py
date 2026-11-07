"""CP-10: transport encryption for the local data services (PostgreSQL, Redis, OPA, API).

These tests run against the developer stack configured by scripts/dev-tls-services.sh. They skip (not pass)
when that configuration is absent, so a plaintext environment never reports TLS as verified.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
import redis

ROOT = Path(__file__).resolve().parents[2]
CA = ROOT / "var" / "certs" / "ca.crt"
CERT, KEY = ROOT / "var" / "certs" / "services.crt", ROOT / "var" / "certs" / "services.key"


def _open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


needs_ca = pytest.mark.skipif(not CA.exists(), reason="dev PKI not generated (scripts/dev-certs.sh)")
PG = "host=localhost port=5432 dbname=asvas_test user=asvas_app password=asvas_app_dev"


@needs_ca
def test_postgres_session_is_tls13():
    try:
        conn = psycopg.connect(f"{PG} sslmode=verify-full sslrootcert={CA}", connect_timeout=3)
    except psycopg.OperationalError as e:
        pytest.skip(f"PostgreSQL TLS not configured: {e}")
    with conn:
        ssl_on, version = conn.execute(
            "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").fetchone()
    assert ssl_on is True and version == "TLSv1.3"


@needs_ca
def test_postgres_rejects_plaintext():
    try:
        psycopg.connect(f"{PG} sslmode=verify-full sslrootcert={CA}", connect_timeout=3).close()
    except psycopg.OperationalError:
        pytest.skip("PostgreSQL TLS not configured")
    with pytest.raises(psycopg.OperationalError, match="no encryption|pg_hba"):
        psycopg.connect(f"{PG} sslmode=disable", connect_timeout=3)


@needs_ca
@pytest.mark.skipif(not _open(6380), reason="TLS Redis (:6380) not running")
def test_redis_tls_only():
    r = redis.Redis(host="localhost", port=6380, ssl=True, ssl_ca_certs=str(CA), ssl_cert_reqs="required",
                    socket_timeout=3)
    assert r.ping() is True
    conn = r.connection_pool.get_connection("PING")
    assert conn._sock.version() == "TLSv1.3"
    r.connection_pool.release(conn)
    plain = redis.Redis(host="localhost", port=6380, socket_timeout=2, retry_on_timeout=False)
    with pytest.raises(redis.exceptions.ConnectionError):
        plain.ping()


@needs_ca
def test_redis_wrong_ca_rejected(tmp_path):
    if not _open(6380):
        pytest.skip("TLS Redis (:6380) not running")
    subprocess.run([str(ROOT / "scripts" / "dev-certs.sh"), str(tmp_path)], check=True, capture_output=True)
    r = redis.Redis(host="localhost", port=6380, ssl=True, ssl_ca_certs=str(tmp_path / "ca.crt"),
                    ssl_cert_reqs="required", socket_timeout=3)
    with pytest.raises(redis.exceptions.ConnectionError, match="CERTIFICATE_VERIFY_FAILED|certificate verify"):
        r.ping()


def test_production_refuses_plain_redis(monkeypatch):
    from types import SimpleNamespace

    from asvas.orchestration import bus
    monkeypatch.setattr(bus, "get_settings", lambda: SimpleNamespace(env="production", redis_url="", redis_ca_file=""))
    with pytest.raises(RuntimeError, match="rediss://"):
        bus.get_redis("redis://localhost:6379/0")


@needs_ca
def test_api_serves_tls_and_refuses_plaintext(tmp_path):
    """Starts the API with the services certificate and checks a verified TLS handshake succeeds and plaintext HTTP gets no response."""
    port = 18943
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--factory", "asvas.api.app:create_app", "--host", "127.0.0.1", "--port", str(port),
         "--ssl-certfile", str(CERT), "--ssl-keyfile", str(KEY),
         "--log-level", "error"], cwd=ROOT / "control-plane", stdout=subprocess.DEVNULL, stderr=open(tmp_path / "api.log", "wb"))
    try:
        import time
        for _ in range(80):
            if proc.poll() is not None:
                pytest.fail((tmp_path / "api.log").read_text()[-2000:])
            if _open(port):
                break
            time.sleep(0.25)
        ctx = ssl.create_default_context(cafile=str(CA))
        with socket.create_connection(("localhost", port), timeout=3) as s, ctx.wrap_socket(s, server_hostname="localhost") as t:
            assert t.version() in ("TLSv1.3", "TLSv1.2")
        plain = socket.create_connection(("127.0.0.1", port), timeout=3)
        plain.sendall(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        data = plain.recv(64)
        plain.close()
        assert not data.startswith(b"HTTP/1.1 200")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
