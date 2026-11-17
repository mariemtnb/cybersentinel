"""Live smoke tests: one small real request per source, parsed and validated against its contract.

Run with `pytest -m live tests/live`. Excluded from the default test run and from the
mandatory CI job (see .github/workflows/smoke.yml).
"""

import os

import pytest

from cybersentinel.ingestion import cisa, epss, nvd, osv
from cybersentinel.ingestion.watchlist import WatchedPackage
from cybersentinel.settings import PROJECT_ROOT
from cybersentinel.validation.contracts import load_all
from cybersentinel.validation.validate import validate_table

pytestmark = pytest.mark.live
CONTRACTS = load_all(PROJECT_ROOT / "contracts")


def assert_valid(table_name, df):
    _, rejected, report = validate_table(df, CONTRACTS[table_name])
    assert report.passed, report.critical


def test_cisa_kev_live():
    batch = cisa.extract(cisa.make_client())
    assert not batch.critical_errors
    assert len(batch.tables["cisa_kev"]) > 1000
    assert_valid("cisa_kev", batch.tables["cisa_kev"])


def test_nvd_single_cve_live():
    client = nvd.make_client(os.environ.get("NVD_API_KEY"))
    batch = nvd.parse(nvd.fetch(client, None, 0, False, ["CVE-2021-44228"])[0])
    assert_valid("nvd_cves", batch.tables["nvd_cves"])
    assert batch.tables["nvd_cves"]["cve_id"].tolist() == ["CVE-2021-44228"]


def test_osv_querybatch_live():
    pkg = WatchedPackage("org.apache.logging.log4j:log4j-core", "Maven", "2.14.1")
    batch = osv.extract(osv.make_client(), [pkg], {}, {})
    assert (batch.tables["watchlist_matches"]["match_status"] == "affected").any()
    assert_valid("osv_vulnerabilities", batch.tables["osv_vulnerabilities"])


def test_epss_live():
    batch = epss.extract(epss.make_client(), ["CVE-2021-44228"], [])
    assert_valid("epss_scores", batch.tables["epss_scores"])
