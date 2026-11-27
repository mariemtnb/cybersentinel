"""DuckDB warehouse: the `raw` schema and idempotent loading.

The `raw` schema holds validated source records exactly as the connectors flattened them,
plus a few technical columns (_row_hash, _loaded_run_id, _loaded_at). dbt reads from here.

Idempotency — running the pipeline twice with no upstream change must not duplicate anything:
- every table has a primary key, so a record can exist only once;
- loading is an UPSERT (INSERT … ON CONFLICT DO UPDATE);
- a row is only rewritten if its content hash changed, so an unchanged record is neither
  counted as "updated" nor touched;
- for NVD, an older version of a CVE never overwrites a newer one (last_modified guard).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pandas as pd

RAW_DDL = {
    "cisa_kev": """
        CREATE TABLE IF NOT EXISTS raw.cisa_kev (
            cve_id VARCHAR PRIMARY KEY, vendor_project VARCHAR, product VARCHAR, vulnerability_name VARCHAR,
            date_added DATE, short_description VARCHAR, required_action VARCHAR, due_date DATE,
            known_ransomware_campaign_use VARCHAR, notes VARCHAR, cwes VARCHAR, catalog_version VARCHAR,
            in_current_catalog BOOLEAN DEFAULT TRUE,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ)""",
    "nvd_cves": """
        CREATE TABLE IF NOT EXISTS raw.nvd_cves (
            cve_id VARCHAR PRIMARY KEY, source_identifier VARCHAR, published TIMESTAMPTZ,
            last_modified TIMESTAMPTZ, vuln_status VARCHAR, description VARCHAR, cvss_version VARCHAR,
            cvss_base_score DOUBLE, cvss_severity VARCHAR, cvss_vector VARCHAR, cvss_source VARCHAR,
            cwe_ids VARCHAR, reference_count INTEGER, has_patch_reference BOOLEAN,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ)""",
    "nvd_cpe_matches": """
        CREATE TABLE IF NOT EXISTS raw.nvd_cpe_matches (
            cve_id VARCHAR, part VARCHAR, vendor VARCHAR, product VARCHAR, vulnerable BOOLEAN,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ,
            PRIMARY KEY (cve_id, part, vendor, product))""",
    "osv_vulnerabilities": """
        CREATE TABLE IF NOT EXISTS raw.osv_vulnerabilities (
            osv_id VARCHAR PRIMARY KEY, cve_id VARCHAR, aliases VARCHAR, summary VARCHAR, details VARCHAR,
            published TIMESTAMPTZ, modified TIMESTAMPTZ, withdrawn TIMESTAMPTZ, severity_label VARCHAR,
            cvss_type VARCHAR, cvss_vector VARCHAR, affected_json VARCHAR,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ)""",
    "osv_affected_ranges": """
        CREATE TABLE IF NOT EXISTS raw.osv_affected_ranges (
            osv_id VARCHAR, ecosystem VARCHAR, package_name VARCHAR, range_type VARCHAR, range_index INTEGER,
            introduced VARCHAR, fixed VARCHAR, last_affected VARCHAR,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ)""",
    "watchlist_matches": """
        CREATE TABLE IF NOT EXISTS raw.watchlist_matches (
            package_name VARCHAR, ecosystem VARCHAR, package_version VARCHAR, osv_id VARCHAR,
            match_status VARCHAR, fixed_version VARCHAR, evidence VARCHAR, checked_at TIMESTAMPTZ,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ,
            PRIMARY KEY (package_name, ecosystem, package_version, osv_id))""",
    "watchlist_packages": """
        CREATE TABLE IF NOT EXISTS raw.watchlist_packages (
            package_name VARCHAR, ecosystem VARCHAR, package_version VARCHAR, owner VARCHAR,
            advisories_returned INTEGER, checked_at TIMESTAMPTZ,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ,
            PRIMARY KEY (package_name, ecosystem, package_version))""",
    "epss_scores": """
        CREATE TABLE IF NOT EXISTS raw.epss_scores (
            cve_id VARCHAR, score_date DATE, epss DOUBLE, percentile DOUBLE,
            _row_hash VARCHAR, _loaded_run_id VARCHAR, _loaded_at TIMESTAMPTZ,
            PRIMARY KEY (cve_id, score_date))""",
}

# How each table is written:
#   upsert        insert new keys, update changed rows (content hash), never delete;
#   replace_keys  delete every row of the parent keys present in the batch, then insert
#                 (child tables whose rows can disappear when the parent changes);
#   replace_all   the batch is the full current state (watchlist evaluation is recomputed each run).
LOAD_MODE = {
    "cisa_kev": ("upsert", ["cve_id"]),
    "nvd_cves": ("upsert", ["cve_id"]),
    "nvd_cpe_matches": ("replace_keys", ["cve_id"]),
    "osv_vulnerabilities": ("upsert", ["osv_id"]),
    "osv_affected_ranges": ("replace_keys", ["osv_id"]),
    "watchlist_matches": ("replace_all", ["package_name", "ecosystem", "package_version", "osv_id"]),
    "watchlist_packages": ("replace_all", ["package_name", "ecosystem", "package_version"]),
    "epss_scores": ("upsert", ["cve_id", "score_date"]),
}
TECH_COLUMNS = ["_row_hash", "_loaded_run_id", "_loaded_at"]
# Columns excluded from the change hash: a new evaluation timestamp alone is not a change.
HASH_EXCLUDE = {"watchlist_matches": {"checked_at"}, "watchlist_packages": {"checked_at"}}


@dataclass
class LoadResult:
    table: str
    inserted: int
    updated: int
    deleted: int
    unchanged: int


def connect(path: Path, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    path = Path(path)
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(path), read_only=read_only)


def init_warehouse(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("CREATE SCHEMA IF NOT EXISTS raw")
    for ddl in RAW_DDL.values():
        con.execute(ddl)


def _row_hashes(df: pd.DataFrame, exclude: set[str]) -> list[str]:
    cols = [c for c in df.columns if c not in exclude]
    as_text = df[cols].astype("string").fillna("\x00")
    joined = (
        as_text.apply(lambda row: "\x1f".join(row.values), axis=1) if len(df) else pd.Series([], dtype=str)
    )
    return [hashlib.md5(v.encode("utf-8"), usedforsecurity=False).hexdigest() for v in joined]


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")


def _check_identifiers(table: str, columns: list[str]) -> None:
    """Table and column names are interpolated into SQL, so they must be known, simple identifiers.

    Names only ever come from LOAD_MODE and the data contracts (never from API data), and
    every *value* goes through a registered DataFrame, never through string formatting.
    """
    if table not in LOAD_MODE:
        raise ValueError(f"unknown table {table!r}")
    bad = [c for c in columns if not _IDENTIFIER.match(c)]
    if bad:
        raise ValueError(f"unsafe column name(s) {bad}")


def load_table(con: duckdb.DuckDBPyConnection, table: str, df: pd.DataFrame, run_id: str) -> LoadResult:
    """Load one validated table into raw.<table>. Runs inside one transaction."""
    _check_identifiers(table, list(df.columns) if df is not None else [])
    mode, keys = LOAD_MODE[table]
    if df is None or (df.empty and mode != "replace_all"):
        return LoadResult(table, 0, 0, 0, 0)
    incoming = df.copy()
    incoming["_row_hash"] = _row_hashes(df, HASH_EXCLUDE.get(table, set()))
    incoming["_loaded_run_id"] = run_id
    incoming["_loaded_at"] = datetime.now(UTC)
    cols = list(df.columns) + TECH_COLUMNS
    col_list = ", ".join(cols)
    key_join = " AND ".join(f"t.{k} IS NOT DISTINCT FROM i.{k}" for k in keys)
    target = f"raw.{table}"

    con.register("incoming_df", incoming[cols])
    con.execute("BEGIN TRANSACTION")
    try:
        existing_same = con.execute(
            f"SELECT count(*) FROM incoming_df i JOIN {target} t ON {key_join} AND t._row_hash = i._row_hash"
        ).fetchone()[0]
        existing_any = con.execute(
            f"SELECT count(*) FROM incoming_df i JOIN {target} t ON {key_join}"
        ).fetchone()[0]
        deleted = 0

        if mode == "upsert":
            updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c not in keys)
            guard = (
                "raw.nvd_cves.last_modified IS NULL OR EXCLUDED.last_modified >= raw.nvd_cves.last_modified"
                if table == "nvd_cves"
                else "TRUE"
            )
            con.execute(
                f"INSERT INTO {target} ({col_list}) SELECT {col_list} FROM incoming_df "
                f"ON CONFLICT ({', '.join(keys)}) DO UPDATE SET {updates} "
                f"WHERE {target}._row_hash IS DISTINCT FROM EXCLUDED._row_hash AND ({guard})"
            )
            inserted, updated = len(incoming) - existing_any, existing_any - existing_same
        else:
            if mode == "replace_keys":
                parent = keys[0]
                # Leave groups that are identical untouched so the run stays idempotent.
                changed_parents = (
                    con.execute(f"""
                    WITH i AS (SELECT {parent}, list_sort(list(_row_hash)) AS h FROM incoming_df GROUP BY 1),
                         t AS (SELECT {parent}, list_sort(list(_row_hash)) AS h FROM {target}
                               WHERE {parent} IN (SELECT {parent} FROM i) GROUP BY 1)
                    SELECT i.{parent} FROM i LEFT JOIN t USING ({parent}) WHERE t.h IS DISTINCT FROM i.h
                """)
                    .df()[parent]
                    .tolist()
                )
                con.register(
                    "changed_parents", pd.DataFrame({parent: pd.Series(changed_parents, dtype="string")})
                )
                deleted = con.execute(
                    f"DELETE FROM {target} WHERE {parent} IN (SELECT {parent} FROM changed_parents)"
                ).fetchone()[0]
                inserted = con.execute(
                    f"INSERT INTO {target} ({col_list}) SELECT {col_list} FROM incoming_df "
                    f"WHERE {parent} IN (SELECT {parent} FROM changed_parents)"
                ).fetchone()[0]
                con.unregister("changed_parents")
                con.execute("COMMIT")
                # A child group is replaced as a whole: counted as deleted + inserted rows, no "updates".
                return LoadResult(table, inserted, 0, deleted, len(incoming) - inserted)
            else:  # replace_all
                deleted = con.execute(f"""
                    DELETE FROM {target} t WHERE NOT EXISTS (
                        SELECT 1 FROM incoming_df i WHERE {key_join} AND t._row_hash = i._row_hash)""").fetchone()[
                    0
                ]
                con.execute(f"""
                    INSERT INTO {target} ({col_list}) SELECT {col_list} FROM incoming_df i
                    WHERE NOT EXISTS (SELECT 1 FROM {target} t WHERE {key_join})""")
            inserted = len(incoming) - existing_any
            updated = existing_any - existing_same
            deleted = max(deleted - updated, 0)
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.unregister("incoming_df")
    return LoadResult(table, inserted, updated, deleted, existing_same)


def mark_kev_catalog(con: duckdb.DuckDBPyConnection, cve_ids: list[str]) -> None:
    """KEV is a full snapshot: flag entries that disappeared from the latest catalog (rare, but it happens)."""
    con.register("kev_ids", pd.DataFrame({"cve_id": cve_ids}))
    con.execute("UPDATE raw.cisa_kev SET in_current_catalog = cve_id IN (SELECT cve_id FROM kev_ids)")
    con.unregister("kev_ids")
