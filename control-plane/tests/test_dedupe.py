"""DA-15: Bloom-filter de-duplication of discovery records; bounded result parsing."""

from __future__ import annotations

from asvas.db import rows, tenant_tx
from asvas.dedupe import BloomFilter, LocalBloom, false_positive_rate
from asvas.evidence import correlate_assets
from asvas.orchestration import bus, engine, memory
from tests.test_lifecycle import WEAK_EXCHANGE, jobs_of, result, start, tid_of

TARGET = {"scheme": "http", "host": "127.0.0.1", "port": 18080}


def test_bloom_semantics_and_fp_rate(deps):
    b = BloomFilter(deps.r, "asvas:st:x:bloom", 60)
    assert b.add("a") is False and b.add("a") is True and "a" in b and "b" not in b
    lb = LocalBloom(m=1 << 16)
    seen = sum(lb.add(f"item-{i}") for i in range(2000))
    assert seen <= 2000 * 0.02  # false positives among distinct items stay low
    assert false_positive_rate(110_000) < 0.011
    assert deps.r.ttl("asvas:st:x:bloom") > 0


def test_duplicates_skipped_new_data_written(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    bloom = memory.bloom(deps.r, aid, 30)
    with tenant_tx(tid_of()) as conn:
        s1: dict = {}
        correlate_assets(conn, tid_of(), aid, TARGET, [WEAK_EXCHANGE], bloom, s1)
        s2: dict = {}
        correlate_assets(conn, tid_of(), aid, TARGET, [WEAK_EXCHANGE], bloom, s2)
        changed = {**WEAK_EXCHANGE, "request": {**WEAK_EXCHANGE["request"], "resolved_ip": "127.0.0.2"}}
        s3: dict = {}
        correlate_assets(conn, tid_of(), aid, TARGET, [changed], bloom, s3)
        host = rows(conn, "SELECT attributes FROM assets WHERE assessment_id = :a AND kind = 'host'", a=aid)
        rel = rows(conn, "SELECT count(*) AS n FROM asset_relations WHERE assessment_id = :a", a=aid)[0]["n"]
    assert s1 == {"written": 2, "duplicates_skipped": 0, "bloom_false_positives": 0}
    assert s2 == {"written": 0, "duplicates_skipped": 2, "bloom_false_positives": 0}
    assert s3["written"] == 1 and s3["duplicates_skipped"] == 1  # changed host record is not dropped
    assert host[0]["attributes"]["resolved_ips"] == ["127.0.0.2"] and rel == 1


def test_bloom_false_positive_never_drops_data(client, make_assessment, deps):
    class AlwaysSeen:
        def add(self, _):
            return True
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    st: dict = {}
    with tenant_tx(tid_of()) as conn:
        correlate_assets(conn, tid_of(), aid, TARGET, [WEAK_EXCHANGE], AlwaysSeen(), st)
        n = rows(conn, "SELECT count(*) AS n FROM assets WHERE assessment_id = :a", a=aid)[0]["n"]
    assert n == 2 and st["bloom_false_positives"] == 2 and st["written"] == 2


def test_ingest_records_dedupe_stats_and_bloom_erased(client, make_assessment, deps):
    aid, op = start(client, make_assessment, deps, ports=(18080,))
    [job] = jobs_of(aid)
    engine.ingest_result(deps, result(job))
    with tenant_tx(tid_of()) as conn:
        ev = rows(conn, "SELECT detail FROM execution_log WHERE event = 'discovery_dedupe'")
    assert ev and ev[0]["detail"]["written"] == 2
    status = client.get(f"/api/v1/assessments/{aid}", headers=op).json()["status"]
    assert status == "COMPLETED" and not deps.r.exists(memory.prefix(aid) + "bloom")  # erased with the run


def test_oversized_result_dropped_before_decoding(deps):
    assert bus.verify_result({"result_pb": "A" * (bus.MAX_RESULT_B64 + 4), "sig": "0" * 64}) is None
