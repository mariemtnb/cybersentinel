"""The explainable prioritization engine."""

import pandas as pd
import pytest

from cybersentinel.prioritization.rules import ScoringConfigError, load_rules
from cybersentinel.prioritization.scoring import score_one, score_vulnerabilities
from cybersentinel.settings import PROJECT_ROOT

RULES = load_rules(PROJECT_ROOT / "config" / "scoring.yaml")


def signals(**kw):
    base = {
        "cvss_base_score": None,
        "severity_label": None,
        "is_kev": False,
        "kev_ransomware": False,
        "epss_score": None,
        "watchlist_affected_count": 0,
        "fix_available": None,
    }
    return {**base, **kw}


def test_log4shell_like_vulnerability_is_critical_and_capped_at_100():
    r = score_one(
        signals(
            cvss_base_score=10.0,
            is_kev=True,
            kev_ransomware=True,
            epss_score=0.97,
            watchlist_affected_count=1,
            fix_available=True,
        ),
        RULES,
    )
    assert r["priority_tier"] == "Critical"
    assert r["priority_score"] == 100
    assert "CISA KEV" in r["priority_reason"] and "EPSS" in r["priority_reason"]


def test_high_cvss_alone_is_not_critical():
    # A severe flaw nobody exploits and that does not touch our inventory is not top priority.
    r = score_one(signals(cvss_base_score=9.8, epss_score=0.002), RULES)
    assert r["priority_tier"] == "Medium"
    assert r["points_cvss"] == pytest.approx(29.4)


def test_each_signal_is_reported_separately():
    r = score_one(
        signals(cvss_base_score=5.0, epss_score=0.2, watchlist_affected_count=2, fix_available=True), RULES
    )
    assert (r["points_cvss"], r["points_kev"], r["points_epss"], r["points_watchlist"], r["points_fix"]) == (
        15.0,
        0.0,
        14.0,
        15.0,
        5.0,
    )
    assert r["priority_score"] == 49.0


def test_kev_floor_raises_to_high():
    r = score_one(signals(cvss_base_score=2.0, is_kev=True, epss_score=0.001), RULES)
    assert r["priority_score"] < 45
    assert r["priority_tier"] == "High"
    assert "Raised to High" in r["priority_reason"]


def test_kev_and_watchlist_floor_is_critical():
    r = score_one(signals(cvss_base_score=3.0, is_kev=True, watchlist_affected_count=1), RULES)
    assert r["priority_tier"] == "Critical"


def test_missing_cvss_falls_back_to_advisory_label():
    r = score_one(signals(severity_label="HIGH"), RULES)
    assert r["points_cvss"] == pytest.approx(22.5)
    assert "estimated from advisory label" in r["priority_reason"]


def test_fix_points_only_count_for_affected_watchlist_packages():
    r = score_one(signals(cvss_base_score=5.0, fix_available=True), RULES)
    assert r["points_fix"] == 0


def test_dataframe_scoring_handles_pandas_missing_values():
    df = pd.DataFrame([signals(cvss_base_score=7.5, is_kev=pd.NA, epss_score=float("nan"))])
    out = score_vulnerabilities(df, RULES)
    assert out.loc[0, "priority_tier"] in {"Low", "Medium"}


def test_invalid_rules_are_refused(tmp_path):
    bad = tmp_path / "scoring.yaml"
    bad.write_text(
        (PROJECT_ROOT / "config" / "scoring.yaml")
        .read_text(encoding="utf-8")
        .replace("name: Low", "name: Minor"),
        encoding="utf-8",
    )
    with pytest.raises(ScoringConfigError):
        load_rules(bad)
