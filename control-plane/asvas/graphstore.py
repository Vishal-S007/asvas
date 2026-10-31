"""Asset/finding topology graph (spec pp. 10, 24, 84; requirement DA-03).

PostgreSQL remains the source of truth. After each committed change the assessment's assets, relations and
findings are *projected* into Neo4j (idempotent MERGE), so a failed or disabled graph store never loses data:
`asvas graph-resync` rebuilds the projection from PostgreSQL.

Tenant isolation: every node carries `tenant_id`, node identity is `uid = <tenant_id>:<id>`, and every query this
module issues is parameterised with the caller's tenant id. Neo4j Community has no row-level security, so this
is application-enforced (tested in tests/test_graphstore.py).
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Protocol

from sqlalchemy import Connection

from asvas.config import get_settings
from asvas.db import rows

log = logging.getLogger("asvas.graph")


class GraphStore(Protocol):
    name: str

    def sync_assessment(self, tenant_id: str, assessment_id: str, snapshot: dict[str, Any]) -> None: ...
    def assessment_graph(self, tenant_id: str, assessment_id: str) -> dict[str, Any]: ...
    def health(self) -> dict[str, Any]: ...


def snapshot(conn: Connection, assessment_id) -> dict[str, Any]:
    """Read the data to project from PostgreSQL (inside a tenant-bound transaction)."""
    a = str(assessment_id)
    return {
        "assets": rows(conn, "SELECT id::text, kind, identifier, attributes FROM assets WHERE assessment_id = :a", a=a),
        "relations": rows(conn, "SELECT src_asset::text AS src, dst_asset::text AS dst, relation FROM asset_relations "
                                "WHERE assessment_id = :a", a=a),
        "findings": rows(conn, "SELECT id::text, asset_id::text, rule_id, check_id, title, severity, verification_status, "
                               "state, cwe FROM findings WHERE assessment_id = :a", a=a),
    }


class DisabledGraphStore:
    name = "disabled"

    def sync_assessment(self, tenant_id, assessment_id, snapshot) -> None:
        return None

    def assessment_graph(self, tenant_id, assessment_id) -> dict[str, Any]:
        raise GraphUnavailable("graph store is not configured (ASVAS_NEO4J_URI unset)")

    def health(self) -> dict[str, Any]:
        return {"backend": self.name, "reachable": False, "detail": "ASVAS_NEO4J_URI not set"}


class GraphUnavailable(Exception):
    pass


SCHEMA = [
    "CREATE CONSTRAINT asvas_asset_uid IF NOT EXISTS FOR (n:Asset) REQUIRE n.uid IS UNIQUE",
    "CREATE CONSTRAINT asvas_finding_uid IF NOT EXISTS FOR (n:Finding) REQUIRE n.uid IS UNIQUE",
    "CREATE CONSTRAINT asvas_assessment_uid IF NOT EXISTS FOR (n:Assessment) REQUIRE n.uid IS UNIQUE",
    "CREATE INDEX asvas_asset_scope IF NOT EXISTS FOR (n:Asset) ON (n.tenant_id, n.assessment_id)",
    "CREATE INDEX asvas_finding_scope IF NOT EXISTS FOR (n:Finding) ON (n.tenant_id, n.assessment_id)",
]

SYNC = """
MERGE (a:Assessment {uid: $t + ':' + $aid})
  SET a.tenant_id = $t, a.assessment_id = $aid, a.id = $aid
WITH a
UNWIND $assets AS x
  MERGE (n:Asset {uid: $t + ':' + x.id})
    SET n.tenant_id = $t, n.assessment_id = $aid, n.id = x.id, n.kind = x.kind, n.identifier = x.identifier,
        n.attributes_json = x.attributes_json
  MERGE (a)-[:HAS_ASSET]->(n)
WITH DISTINCT a
UNWIND $relations AS r
  MATCH (s:Asset {uid: $t + ':' + r.src}), (d:Asset {uid: $t + ':' + r.dst})
  MERGE (s)-[rel:RELATES {relation: r.relation}]->(d)
WITH DISTINCT a
UNWIND $findings AS f
  MATCH (n:Asset {uid: $t + ':' + f.asset_id})
  MERGE (x:Finding {uid: $t + ':' + f.id})
    SET x.tenant_id = $t, x.assessment_id = $aid, x.id = f.id, x.rule_id = f.rule_id, x.check_id = f.check_id,
        x.title = f.title, x.severity = f.severity, x.verification_status = f.verification_status,
        x.state = f.state, x.cwe = f.cwe
  MERGE (n)-[:HAS_FINDING]->(x)
"""

READ = """
MATCH (n {tenant_id: $t, assessment_id: $aid}) WHERE n:Asset OR n:Finding
OPTIONAL MATCH (n)-[r]->(m {tenant_id: $t, assessment_id: $aid})
RETURN n, labels(n) AS labels, collect(CASE WHEN m IS NULL THEN NULL
       ELSE {type: type(r), relation: r.relation, to: m.id} END) AS out
"""


class Neo4jGraphStore:
    name = "neo4j"

    def __init__(self, uri: str, user: str, password: str):
        from neo4j import GraphDatabase
        self._driver = GraphDatabase.driver(uri, auth=(user, password), connection_timeout=3,
                                            max_transaction_retry_time=5)
        self._schema_done = False

    def _schema(self) -> None:
        if not self._schema_done:
            for stmt in SCHEMA:
                self._driver.execute_query(stmt)
            self._schema_done = True

    def sync_assessment(self, tenant_id, assessment_id, snapshot) -> None:
        import json
        self._schema()
        self._driver.execute_query(
            SYNC, t=str(tenant_id), aid=str(assessment_id),
            assets=[{"id": x["id"], "kind": x["kind"], "identifier": x["identifier"],
                     "attributes_json": json.dumps(x["attributes"], default=str)} for x in snapshot["assets"]],
            relations=snapshot["relations"], findings=snapshot["findings"])

    def assessment_graph(self, tenant_id, assessment_id) -> dict[str, Any]:
        import json
        try:
            res = self._driver.execute_query(READ, t=str(tenant_id), aid=str(assessment_id))
        except Exception as e:  # noqa: BLE001
            raise GraphUnavailable(f"neo4j query failed: {type(e).__name__}") from e
        nodes, edges = [], []
        for rec in res.records:
            n = dict(rec["n"])
            label = "Finding" if "Finding" in rec["labels"] else "Asset"
            node = {"id": n["id"], "type": label}
            if label == "Asset":
                node.update(kind=n["kind"], identifier=n["identifier"],
                            attributes=json.loads(n.get("attributes_json") or "{}"))
            else:
                node.update({k: n.get(k) for k in ("rule_id", "check_id", "title", "severity",
                                                     "verification_status", "state", "cwe")})
            nodes.append(node)
            for o in rec["out"]:
                if o:
                    edges.append({"from": n["id"], "to": o["to"], "type": o["type"], "relation": o["relation"]})
        return {"source": "neo4j", "nodes": nodes, "edges": edges}

    def delete_tenant_data(self, tenant_id) -> None:
        self._driver.execute_query("MATCH (n {tenant_id: $t}) DETACH DELETE n", t=str(tenant_id))

    def health(self) -> dict[str, Any]:
        try:
            info = self._driver.get_server_info()
            return {"backend": self.name, "reachable": True, "server": info.agent}
        except Exception as e:  # noqa: BLE001
            return {"backend": self.name, "reachable": False, "detail": type(e).__name__}

    def close(self) -> None:
        self._driver.close()


@functools.lru_cache
def get_graph_store() -> GraphStore:
    s = get_settings()
    if not s.neo4j_uri:
        return DisabledGraphStore()
    return Neo4jGraphStore(s.neo4j_uri, s.neo4j_user, s.neo4j_password.get_secret_value())


def project(store: GraphStore, conn: Connection, tenant_id, assessment_id) -> str | None:
    """Best-effort projection. Returns an error string (for audit) instead of raising: PostgreSQL stays authoritative."""
    if store.name == "disabled":
        return None
    try:
        store.sync_assessment(str(tenant_id), str(assessment_id), snapshot(conn, assessment_id))
        return None
    except Exception as e:  # noqa: BLE001
        log.warning("graph projection failed: %s", e)
        return f"{type(e).__name__}: {e}"[:300]
