"""Idempotent loading into the DuckDB raw schema."""

import pandas as pd

from cybersentinel.loading import warehouse


def con_with_schema(tmp_path):
    con = warehouse.connect(tmp_path / "w.duckdb")
    warehouse.init_warehouse(con)
    return con


def nvd_df(score=7.5, modified="2026-11-01T00:00:00Z"):
    return pd.DataFrame(
        [
            {
                "cve_id": "CVE-2026-0001",
                "source_identifier": "x",
                "published": pd.Timestamp("2026-10-01", tz="UTC"),
                "last_modified": pd.Timestamp(modified),
                "vuln_status": "Analyzed",
                "description": "d",
                "cvss_version": "3.1",
                "cvss_base_score": score,
                "cvss_severity": "HIGH",
                "cvss_vector": "v",
                "cvss_source": "nvd",
                "cwe_ids": None,
                "reference_count": 1,
                "has_patch_reference": False,
            }
        ]
    )


def test_loading_the_same_batch_twice_changes_nothing(tmp_path):
    con = con_with_schema(tmp_path)
    first = warehouse.load_table(con, "nvd_cves", nvd_df(), "run1")
    second = warehouse.load_table(con, "nvd_cves", nvd_df(), "run2")
    assert (first.inserted, first.updated) == (1, 0)
    assert (second.inserted, second.updated, second.unchanged) == (0, 0, 1)
    assert con.execute("select count(*), any_value(_loaded_run_id) from raw.nvd_cves").fetchone() == (
        1,
        "run1",
    )


def test_changed_record_is_updated_in_place(tmp_path):
    con = con_with_schema(tmp_path)
    warehouse.load_table(con, "nvd_cves", nvd_df(), "run1")
    result = warehouse.load_table(con, "nvd_cves", nvd_df(score=9.8, modified="2026-11-05T00:00:00Z"), "run2")
    assert (result.inserted, result.updated) == (0, 1)
    assert con.execute("select cvss_base_score from raw.nvd_cves").fetchone()[0] == 9.8


def test_older_nvd_version_never_overwrites_newer(tmp_path):
    con = con_with_schema(tmp_path)
    warehouse.load_table(con, "nvd_cves", nvd_df(score=9.8, modified="2026-11-05T00:00:00Z"), "run1")
    warehouse.load_table(con, "nvd_cves", nvd_df(score=5.0, modified="2026-10-01T00:00:00Z"), "run2")
    assert con.execute("select cvss_base_score from raw.nvd_cves").fetchone()[0] == 9.8


def test_replace_keys_rewrites_only_changed_parents(tmp_path):
    con = con_with_schema(tmp_path)
    cpe = pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-1", "CVE-2"],
            "part": ["a"] * 3,
            "vendor": ["v1", "v2", "v3"],
            "product": ["p"] * 3,
            "vulnerable": [True] * 3,
        }
    )
    warehouse.load_table(con, "nvd_cpe_matches", cpe, "run1")
    # CVE-1 now has a single vendor; CVE-2 unchanged.
    new = cpe.iloc[[0, 2]].reset_index(drop=True)
    warehouse.load_table(con, "nvd_cpe_matches", new, "run2")
    rows = con.execute(
        "select cve_id, vendor, _loaded_run_id from raw.nvd_cpe_matches order by 1, 2"
    ).fetchall()
    assert rows == [("CVE-1", "v1", "run2"), ("CVE-2", "v3", "run1")]


def test_epss_history_accumulates_one_row_per_day(tmp_path):
    con = con_with_schema(tmp_path)
    day1 = pd.DataFrame(
        {"cve_id": ["CVE-1"], "score_date": [pd.Timestamp("2026-11-15")], "epss": [0.1], "percentile": [0.5]}
    )
    day2 = day1.assign(score_date=pd.Timestamp("2026-11-16"), epss=0.3)
    warehouse.load_table(con, "epss_scores", day1, "run1")
    warehouse.load_table(con, "epss_scores", day2, "run2")
    warehouse.load_table(con, "epss_scores", day2, "run3")  # re-run: no duplicate
    assert con.execute("select count(*) from raw.epss_scores").fetchone()[0] == 2
