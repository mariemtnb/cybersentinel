"""Connector parsing on saved real API responses (no network)."""

import copy

from cybersentinel.ingestion import cisa, epss, nvd, osv
from cybersentinel.ingestion.base import RawPayload
from cybersentinel.ingestion.watchlist import WatchedPackage
from tests.conftest import load_api


def test_cisa_parse_real_catalog(kev_payload):
    batch = cisa.parse(kev_payload)
    table = batch.tables["cisa_kev"]
    assert not batch.critical_errors
    assert len(table) == kev_payload[0].body["count"]
    assert table["cve_id"].str.match(r"^CVE-\d{4}-\d{4,}$").all()
    assert "CVE-2021-44228" in set(table["cve_id"])


def test_cisa_count_mismatch_is_critical(kev_payload):
    kev_payload[0].body["count"] += 5
    assert "declares count" in cisa.parse(kev_payload).critical_errors[0]


def test_cisa_new_field_is_reported_as_schema_drift(kev_payload):
    kev_payload[0].body["vulnerabilities"][0]["exploitMaturity"] = "high"
    batch = cisa.parse(kev_payload)
    assert any("exploitMaturity" in w for w in batch.schema_warnings)
    assert not batch.critical_errors  # drift is a warning, the data still flows


def test_cisa_unexpected_structure_is_critical():
    batch = cisa.parse([RawPayload("catalog", {"error": "maintenance"})])
    assert batch.critical_errors


def test_nvd_parse_picks_primary_cvss_and_english_description(nvd_payload):
    table = nvd.parse(nvd_payload).tables["nvd_cves"]
    log4shell = table.set_index("cve_id").loc["CVE-2021-44228"]
    assert log4shell["cvss_base_score"] == 10.0
    assert log4shell["cvss_severity"] == "CRITICAL"
    assert log4shell["cvss_version"] == "3.1"
    assert log4shell["description"].startswith("Apache Log4j2")


def test_nvd_duplicate_cve_across_pages_keeps_latest(nvd_payload):
    page2 = copy.deepcopy(nvd_payload[0].body)
    item = next(i for i in page2["vulnerabilities"] if i["cve"]["id"] == "CVE-2021-44228")
    item["cve"]["lastModified"] = "2099-01-01T00:00:00.000"
    page2["vulnerabilities"] = [item]
    batch = nvd.parse([nvd_payload[0], RawPayload("kev_0002", page2)])
    rows = batch.tables["nvd_cves"].query("cve_id == 'CVE-2021-44228'")
    assert len(rows) == 1 and rows["last_modified"].iloc[0].startswith("2099")
    assert batch.metadata["duplicates_collapsed"] == 1


def test_nvd_windows_respect_120_day_limit():
    from datetime import UTC, datetime, timedelta

    now = datetime(2026, 11, 16, tzinfo=UTC)
    windows = nvd.plan_windows(now - timedelta(days=300), now, backfill_days=7)
    assert len(windows) == 3
    assert all(end - start <= timedelta(days=120) for start, end in windows)
    assert windows[-1][1] == now


def test_nvd_first_run_uses_backfill_days():
    from datetime import UTC, datetime, timedelta

    now = datetime(2026, 11, 16, tzinfo=UTC)
    ((start, end),) = nvd.plan_windows(None, now, backfill_days=7)
    assert end - start == timedelta(days=7)


def test_osv_parse_and_range_verdicts():
    recorded = load_api("osv_querybatch.json")
    details = load_api("osv_vulns.json")
    packages = [
        WatchedPackage(q["package"]["name"], q["package"]["ecosystem"], q["version"])
        for q in recorded["queries"]
    ]
    hits = {
        p.key: [(v["id"], v["modified"]) for v in r["vulns"]]
        for p, r in zip(packages, recorded["results"], strict=True)
    }
    payloads = [RawPayload(f"vuln_{oid}", body) for oid, body in details.items()]
    batch = osv.parse(payloads, packages, hits, known_affected={})
    matches = batch.tables["watchlist_matches"]
    assert set(matches["match_status"]) <= {"affected", "not_affected", "unverified"}
    log4j = matches[matches["package_name"].str.contains("log4j")]
    assert (log4j["match_status"] == "affected").any()
    vulns = batch.tables["osv_vulnerabilities"]
    assert vulns["osv_id"].is_unique
    assert "CVE-2021-44228" in set(vulns["cve_id"])
    assert len(batch.tables["watchlist_packages"]) == len(packages)


def test_epss_time_series_is_expanded_and_deduplicated(epss_payload):
    batch = epss.parse(epss_payload)
    table = batch.tables["epss_scores"]
    assert not table.duplicated(["cve_id", "score_date"]).any()
    assert table["cve_id"].nunique() == len(epss_payload[0].body["data"])
    assert len(table) > table["cve_id"].nunique()  # history rows were added
