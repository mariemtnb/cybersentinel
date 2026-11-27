"""Data contracts: invalid rows are isolated with a reason; broken tables are blocked."""

import pandas as pd
import pytest

from cybersentinel.settings import PROJECT_ROOT
from cybersentinel.validation.contracts import ContractError, load_all, load_contract
from cybersentinel.validation.validate import validate_table

CONTRACTS = load_all(PROJECT_ROOT / "contracts")


def kev_rows(n=3, **override):
    rows = [
        {
            "cve_id": f"CVE-2024-{1000 + i}",
            "vendor_project": "Acme",
            "product": "Widget",
            "vulnerability_name": "Acme Widget RCE",
            "date_added": "2024-05-01",
            "short_description": "x",
            "required_action": "patch",
            "due_date": "2024-05-22",
            "known_ransomware_campaign_use": "Unknown",
            "notes": "",
            "cwes": "CWE-78",
            "catalog_version": "2024.05.01",
        }
        for i in range(n)
    ]
    for key, value in override.items():
        rows[0][key] = value
    return pd.DataFrame(rows)


def test_every_source_table_has_a_contract():
    expected = {
        "cisa_kev",
        "nvd_cves",
        "nvd_cpe_matches",
        "osv_vulnerabilities",
        "osv_affected_ranges",
        "watchlist_packages",
        "watchlist_matches",
        "epss_scores",
    }
    assert expected <= set(CONTRACTS)


def test_valid_rows_pass_and_get_typed():
    valid, rejected, report = validate_table(kev_rows(), CONTRACTS["cisa_kev"])
    assert report.passed and len(valid) == 3 and rejected.empty
    assert str(valid["date_added"].dtype).startswith("datetime64")


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("cve_id", "CVE-24-1", "does not match"),
        ("cve_id", None, "required value is missing"),
        ("date_added", "2024-13-45", "not a valid date"),
        ("known_ransomware_campaign_use", "Maybe", "value not allowed"),
    ],
)
def test_invalid_row_is_rejected_with_reason(field, value, reason):
    contract = CONTRACTS["cisa_kev"]
    df = pd.concat([kev_rows(60)], ignore_index=True)  # 1 bad row out of 60 stays under the 2 % limit
    df.loc[0, field] = value
    valid, rejected, report = validate_table(df, contract)
    assert len(rejected) == 1 and len(valid) == 59
    assert reason in rejected["_reject_reasons"].iloc[0]
    assert report.passed


def test_duplicate_primary_key_keeps_first_and_rejects_the_rest():
    df = pd.concat([kev_rows(60), kev_rows(1)], ignore_index=True)
    valid, rejected, _ = validate_table(df, CONTRACTS["cisa_kev"])
    assert valid["cve_id"].is_unique
    assert "duplicate primary key" in rejected["_reject_reasons"].iloc[0]


def test_reject_rate_above_contract_limit_blocks_the_table():
    df = kev_rows(10)
    df.loc[:2, "cve_id"] = "not-a-cve"
    _, _, report = validate_table(df, CONTRACTS["cisa_kev"])
    assert not report.passed
    assert "reject rate" in report.critical[0]


def test_missing_column_is_a_schema_change_and_blocks():
    df = kev_rows().drop(columns=["product"])
    valid, _, report = validate_table(df, CONTRACTS["cisa_kev"])
    assert not report.passed and valid.empty
    assert "product" in report.critical[0]


def test_scores_outside_their_range_are_rejected():
    epss = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "score_date": ["2026-11-01"] * 2,
            "epss": [0.5, 1.7],
            "percentile": [0.9, 0.9],
        }
    )
    contract = CONTRACTS["epss_scores"]
    valid, rejected, _ = validate_table(epss, contract)
    assert list(valid["cve_id"]) == ["CVE-2024-0001"]
    assert "above maximum" in rejected["_reject_reasons"].iloc[0]


def test_min_rows_blocks_an_empty_kev_catalog():
    _, _, report = validate_table(kev_rows().iloc[0:0], CONTRACTS["cisa_kev"])
    assert not report.passed


def test_contract_with_unknown_type_is_refused(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "kind: DataContract\nid: x\nschema:\n  - name: t\n    properties:\n"
        "      - {name: a, logicalType: complex}\n",
        encoding="utf-8",
    )
    with pytest.raises(ContractError):
        load_contract(bad)
