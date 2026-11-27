"""End-to-end pipeline on recorded real API responses (offline, deterministic).

Covers the project's key guarantees:
- a full run loads every source, passes all dbt tests and publishes;
- re-running with no upstream change creates no duplicate and no new history or alert;
- a new KEV entry is detected as a change and alerted exactly once;
- an unreachable API makes the run "partial" (other sources still refresh);
- a contract violation blocks the source; a failing dbt build blocks publication.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime

import duckdb
import pytest

from cybersentinel.pipeline import run_pipeline
from cybersentinel.replay import ReplaySession
from cybersentinel.settings import load_settings
from tests.conftest import load_api

pytestmark = pytest.mark.integration


def published(sql: str):
    s = load_settings()
    con = duckdb.connect(str(s.published_path), read_only=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def ops(sql: str):
    s = load_settings()
    con = duckdb.connect(str(s.ops_db_path), read_only=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


@pytest.fixture
def first_run(isolated_env):
    summary = run_pipeline(trigger="test", session=ReplaySession())
    return summary


def test_full_run_publishes_deduplicated_prioritised_data(first_run):
    assert first_run["status"] == "success", first_run
    assert first_run["published"]
    assert all(s["status"] == "success" for s in first_run["sources"].values())

    total, distinct = published(
        "select count(*), count(distinct vulnerability_id) from marts.fct_vulnerabilities"
    )[0]
    assert total == distinct > 0
    # Log4Shell is in KEV, NVD, OSV and EPSS: one canonical row, Critical, affecting the watchlist.
    row = published(
        "select source_count, priority_tier, watchlist_affected_count from marts.fct_vulnerabilities "
        "where vulnerability_id = 'CVE-2021-44228'"
    )
    assert row == [(4, "Critical", 1)]
    assert (
        published("select count(*) from marts.fct_package_exposure where package_name like '%log4j%'")[0][0]
        > 0
    )
    assert ops("select is_baseline from ops.pipeline_runs")[0][0] is True


def test_second_identical_run_is_idempotent(first_run):
    before_vulns = published("select count(*) from marts.fct_vulnerabilities")[0][0]
    before_history = published("select count(*) from snapshots.snap_vulnerability_state")[0][0]
    before_epss = published("select count(*) from raw.epss_scores")[0][0]

    second = run_pipeline(trigger="test", session=ReplaySession())
    assert second["status"] == "success"
    for source, result in second["sources"].items():
        assert result["inserted"] == 0, source
        assert result["updated"] == 0, source
    assert published("select count(*) from marts.fct_vulnerabilities")[0][0] == before_vulns
    assert published("select count(*) from snapshots.snap_vulnerability_state")[0][0] == before_history
    assert published("select count(*) from raw.epss_scores")[0][0] == before_epss
    assert ops("select count(*) from ops.alerts where alert_type not in ('SOURCE_STALE')")[0][0] == 0


def test_new_kev_entry_is_detected_and_alerted_once(first_run):
    kev = copy.deepcopy(load_api("cisa_kev.json"))
    nvd_ids = [i["cve"]["id"] for i in load_api("nvd_page.json")["vulnerabilities"]]
    kev_ids = {v["cveID"] for v in kev["vulnerabilities"]}
    target = next(c for c in nvd_ids if c not in kev_ids)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    kev["vulnerabilities"].append(
        {
            **kev["vulnerabilities"][0],
            "cveID": target,
            "dateAdded": today,
            "knownRansomwareCampaignUse": "Unknown",
        }
    )
    kev["count"] += 1

    run = run_pipeline(trigger="test", session=ReplaySession(overrides={"cisa_kev.json": kev}))
    assert run["status"] == "success"
    events = published(
        f"select event_type from marts.fct_vulnerability_changes "
        f"where vulnerability_id = '{target}' and run_id = '{run['run_id']}'"
    )
    assert ("KEV_ADDED",) in events
    assert published(
        f"select priority_tier in ('High', 'Critical') from marts.fct_vulnerabilities "
        f"where vulnerability_id = '{target}'"
    )[0][0]
    alerts = ops(f"select alert_type from ops.alerts where vulnerability_id = '{target}'")
    assert alerts == [("KEV_ADDED",)]

    again = run_pipeline(trigger="test", session=ReplaySession(overrides={"cisa_kev.json": kev}))
    assert again["status"] == "success"
    assert ops(f"select count(*) from ops.alerts where vulnerability_id = '{target}'")[0][0] == 1


class DownForNvd(ReplaySession):
    def request(self, method, url, **kwargs):
        if "nvd.nist.gov" in url:
            return self._response(503, {"message": "Service Unavailable"})
        return super().request(method, url, **kwargs)


def test_api_outage_gives_partial_run_and_keeps_publishing(first_run, monkeypatch):
    monkeypatch.setattr("cybersentinel.http.time.sleep", lambda s: None)
    session = DownForNvd()
    session.is_replay = True
    run = run_pipeline(trigger="test", session=session)
    assert run["sources"]["nvd"]["status"] == "failed"
    assert run["status"] == "partial" and run["published"]
    assert ops("select count(*) from ops.alerts where alert_type = 'SOURCE_FAILED'")[0][0] == 1
    # previously loaded NVD data is still published
    assert published("select count(*) from marts.fct_vulnerabilities where in_nvd")[0][0] > 0


def test_contract_violation_blocks_the_source(first_run):
    bad = copy.deepcopy(load_api("epss.json"))
    for row in bad["data"]:
        row["epss"] = "7.5"  # impossible probability for every row -> reject rate 100 %
    run = run_pipeline(trigger="test", session=ReplaySession(overrides={"epss.json": bad}))
    assert run["sources"]["epss"]["status"] == "blocked"
    assert run["status"] == "partial"
    assert ops("select count(*) from ops.quarantine where table_name = 'epss_scores'")[0][0] > 0
    assert published("select max(epss_score) <= 1 from marts.fct_vulnerabilities")[0][0]


def test_failing_dbt_build_is_never_published(first_run, tmp_path, monkeypatch):
    before = published("select count(*) from marts.fct_vulnerabilities")[0][0]
    broken_rules = tmp_path / "scoring.yaml"
    broken_rules.write_text("version: 1\nsignals: {}\n", encoding="utf-8")
    monkeypatch.setenv("SCORING_PATH", str(broken_rules))
    run = run_pipeline(trigger="test", session=ReplaySession())
    assert run["status"] == "failed" and not run["published"]
    assert ops(f"select status, published from ops.pipeline_runs where run_id = '{run['run_id']}'") == [
        ("failed", False)
    ]
    assert ops("select count(*) from ops.alerts where alert_type = 'PIPELINE_FAILED'")[0][0] == 1
    assert published("select count(*) from marts.fct_vulnerabilities")[0][0] == before
