"""Neo4j projection (DA-03): projection content, tenant isolation, resilience when the graph store fails."""

import os

import pytest

from asvas.db import tenant_tx
from asvas.graphstore import DisabledGraphStore, Neo4jGraphStore, project
from asvas.orchestration import engine
from tests.test_lifecycle import jobs_of, result, start, tid_of

NEO4J = os.environ.get("TEST_NEO4J_URI", "bolt://127.0.0.1:7687")


@pytest.fixture()
def neo(deps):
    store = Neo4jGraphStore(NEO4J, "neo4j", os.environ.get("TEST_NEO4J_PASSWORD", "asvas_neo4j_dev"))
    if not store.health()["reachable"]:
        pytest.skip("Neo4j not reachable")
    store._driver.execute_query("MATCH (n) WHERE n.uid IS NOT NULL DETACH DELETE n")
    deps.graph = store
    yield store
    store.close()


def _run(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    assert engine.ingest_result(deps, *result(job)) == "ok"
    return aid, op


def test_projection_matches_postgres(client, make_assessment, deps, neo):
    aid, op = _run(client, make_assessment, deps)
    g = client.get(f"/api/v1/assessments/{aid}/graph", headers=op).json()
    assert g["source"] == "neo4j"
    kinds = sorted(n.get("kind") or n["type"] for n in g["nodes"])
    findings = client.get(f"/api/v1/assessments/{aid}/findings", headers=op).json()
    assert kinds.count("Finding") == len(findings) == 5
    assert "host" in kinds and "service" in kinds
    assert any(e["type"] == "RELATES" and e["relation"] == "exposes" for e in g["edges"])
    assert sum(e["type"] == "HAS_FINDING" for e in g["edges"]) == 5
    # Idempotent: re-projection does not duplicate anything.
    engine.sync_graph(deps, tid_of(), aid)
    g2 = client.get(f"/api/v1/assessments/{aid}/graph", headers=op).json()
    assert len(g2["nodes"]) == len(g["nodes"]) and len(g2["edges"]) == len(g["edges"])


def test_graph_tenant_isolation(client, make_assessment, deps, neo):
    aid, _ = _run(client, make_assessment, deps)
    globex = client.as_user("operator@globex.test")
    assert client.get(f"/api/v1/assessments/{aid}/graph", headers=globex).status_code == 404
    # Even a direct store query with another tenant id returns nothing.
    from asvas.auth import lookup_user
    gid = lookup_user(email="operator@globex.test")["tenant_id"]
    assert neo.assessment_graph(str(gid), aid)["nodes"] == []


def test_graph_failure_does_not_lose_data(client, make_assessment, deps):
    class Broken(DisabledGraphStore):
        name = "broken"

        def sync_assessment(self, *a):
            raise ConnectionError("neo4j down")

    deps.graph = Broken()
    aid, op = _run(client, make_assessment, deps)
    assert client.get(f"/api/v1/assessments/{aid}", headers=op).json()["status"] == "COMPLETED"
    assert len(client.get(f"/api/v1/assessments/{aid}/findings", headers=op).json()) == 5
    tl = client.get(f"/api/v1/assessments/{aid}/timeline", headers=op).json()
    assert any(e["event_type"] == "graph.sync_failed" for e in tl)
    with tenant_tx(tid_of()) as conn:
        assert project(DisabledGraphStore(), conn, tid_of(), aid) is None


def test_graph_disabled_is_503(client, make_assessment, deps):
    deps.graph = DisabledGraphStore()
    aid, op = _run(client, make_assessment, deps)
    r = client.get(f"/api/v1/assessments/{aid}/graph", headers=op)
    assert r.status_code == 503 and "not configured" in r.json()["title"]
