"""Operational state: pipeline runs, per-source results, quarantine, watermarks and alerts.

Stored in its own small DuckDB file (data/state/pipeline_state.duckdb), separate from the warehouse:
- a failed run is still recorded here even though nothing is published;
- the dashboard can read the live pipeline status without waiting for a publication;
- the connection is opened only for a few milliseconds per write, so the dashboard and dbt
  (which attaches this file read-only) rarely collide. Reads retry on a lock.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd

OPS_DDL = [
    "CREATE SCHEMA IF NOT EXISTS ops",
    """CREATE TABLE IF NOT EXISTS ops.pipeline_runs (
        run_id VARCHAR PRIMARY KEY, trigger VARCHAR, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
        status VARCHAR, published BOOLEAN DEFAULT FALSE, is_baseline BOOLEAN DEFAULT FALSE,
        duration_seconds DOUBLE, error VARCHAR, dbt_summary VARCHAR)""",
    """CREATE TABLE IF NOT EXISTS ops.source_runs (
        run_id VARCHAR, source VARCHAR, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, status VARCHAR,
        records_extracted INTEGER, records_valid INTEGER, records_rejected INTEGER, records_inserted INTEGER,
        records_updated INTEGER, records_unchanged INTEGER, requests INTEGER, api_errors INTEGER,
        schema_warnings VARCHAR, error VARCHAR, source_timestamp VARCHAR, raw_location VARCHAR,
        metadata VARCHAR, PRIMARY KEY (run_id, source))""",
    """CREATE TABLE IF NOT EXISTS ops.quarantine (
        run_id VARCHAR, source VARCHAR, table_name VARCHAR, record_key VARCHAR, reasons VARCHAR,
        record_json VARCHAR, quarantined_at TIMESTAMPTZ)""",
    """CREATE TABLE IF NOT EXISTS ops.ingestion_state (
        source VARCHAR PRIMARY KEY, watermark TIMESTAMPTZ, run_id VARCHAR, updated_at TIMESTAMPTZ)""",
    """CREATE TABLE IF NOT EXISTS ops.nvd_lookup_misses (
        cve_id VARCHAR PRIMARY KEY, last_tried_at TIMESTAMPTZ, run_id VARCHAR)""",
    """CREATE TABLE IF NOT EXISTS ops.alerts (
        alert_id VARCHAR PRIMARY KEY, run_id VARCHAR, created_at TIMESTAMPTZ, alert_type VARCHAR,
        severity VARCHAR, vulnerability_id VARCHAR, title VARCHAR, message VARCHAR,
        delivered_to VARCHAR)""",
]


class OpsStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            for ddl in OPS_DDL:
                con.execute(ddl)

    @contextmanager
    def connect(self, read_only: bool = False, attempts: int = 20) -> Iterator[duckdb.DuckDBPyConnection]:
        last = None
        for i in range(attempts):
            try:
                con = duckdb.connect(str(self.path), read_only=read_only)
                break
            except duckdb.IOException as exc:  # file locked by another process
                last = exc
                time.sleep(0.25 * (i + 1))
        else:
            raise last  # type: ignore[misc]
        try:
            yield con
        finally:
            con.close()

    # --- runs ---------------------------------------------------------------------------
    def start_run(self, run_id: str, trigger: str) -> datetime:
        started = datetime.now(UTC)
        with self.connect() as con:
            # Until a first fully successful run exists, a run is a "baseline": everything is new
            # then, so its change events do not raise security alerts.
            baseline = con.execute(
                "SELECT count(*) = 0 FROM ops.pipeline_runs WHERE status = 'success' AND published"
            ).fetchone()[0]
            con.execute(
                "INSERT INTO ops.pipeline_runs (run_id, trigger, started_at, status, is_baseline) "
                "VALUES (?, ?, ?, 'running', ?)",
                [run_id, trigger, started, baseline],
            )
        return started

    def is_baseline(self, run_id: str) -> bool:
        with self.connect() as con:
            row = con.execute(
                "SELECT is_baseline FROM ops.pipeline_runs WHERE run_id = ?", [run_id]
            ).fetchone()
        return bool(row and row[0])

    def finish_run(
        self,
        run_id: str,
        status: str,
        published: bool,
        error: str | None = None,
        dbt_summary: dict | None = None,
    ) -> None:
        finished = datetime.now(UTC)
        with self.connect() as con:
            con.execute(
                """UPDATE ops.pipeline_runs SET finished_at = ?, status = ?, published = ?, error = ?,
                           dbt_summary = ?, duration_seconds = date_diff('millisecond', started_at, ?) / 1000.0
                           WHERE run_id = ?""",
                [
                    finished,
                    status,
                    published,
                    error,
                    json.dumps(dbt_summary) if dbt_summary else None,
                    finished,
                    run_id,
                ],
            )

    def record_source(
        self, run_id: str, source: str, started_at: datetime, status: str, **fields: Any
    ) -> None:
        row = {
            "run_id": run_id,
            "source": source,
            "started_at": started_at,
            "finished_at": datetime.now(UTC),
            "status": status,
            **fields,
        }
        for key in ("schema_warnings", "metadata"):
            if key in row and not isinstance(row[key], str | type(None)):
                row[key] = json.dumps(row[key], default=str)
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self.connect() as con:
            con.execute(
                f"INSERT OR REPLACE INTO ops.source_runs ({cols}) VALUES ({marks})", list(row.values())
            )

    # --- quarantine ------------------------------------------------------------------------
    def quarantine(
        self, run_id: str, source: str, table: str, rejected: pd.DataFrame, key_cols: list[str]
    ) -> int:
        if rejected is None or rejected.empty:
            return 0
        now = datetime.now(UTC)
        records = []
        for _, row in rejected.iterrows():
            data = {k: (None if pd.isna(v) else v) for k, v in row.items() if k != "_reject_reasons"}
            key = "|".join(str(data.get(k)) for k in key_cols) if key_cols else None
            records.append(
                (run_id, source, table, key, row["_reject_reasons"], json.dumps(data, default=str), now)
            )
        with self.connect() as con:
            con.executemany("INSERT INTO ops.quarantine VALUES (?, ?, ?, ?, ?, ?, ?)", records)
        return len(records)

    # --- watermarks -------------------------------------------------------------------------
    def get_watermark(self, source: str) -> datetime | None:
        with self.connect() as con:
            row = con.execute(
                "SELECT watermark FROM ops.ingestion_state WHERE source = ?", [source]
            ).fetchone()
        return row[0] if row else None

    def set_watermark(self, source: str, watermark: datetime, run_id: str) -> None:
        with self.connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO ops.ingestion_state VALUES (?, ?, ?, ?)",
                [source, watermark, run_id, datetime.now(UTC)],
            )

    # --- NVD lookups that returned nothing (retried after a cool-down, not on every run) -------
    def recent_lookup_misses(self, days: int = 7) -> set[str]:
        with self.connect(read_only=True) as con:
            rows = con.execute(
                "SELECT cve_id FROM ops.nvd_lookup_misses WHERE last_tried_at > now() - to_days(?)", [days]
            ).fetchall()
        return {r[0] for r in rows}

    def record_lookup_misses(self, cve_ids: list[str], run_id: str) -> None:
        if not cve_ids:
            return
        now = datetime.now(UTC)
        with self.connect() as con:
            con.executemany(
                "INSERT OR REPLACE INTO ops.nvd_lookup_misses VALUES (?, ?, ?)",
                [(c, now, run_id) for c in cve_ids],
            )

    # --- alerts ------------------------------------------------------------------------------
    def unseen_alert_ids(self, alert_ids: list[str]) -> set[str]:
        """Alert IDs are deterministic, so a re-run produces the same IDs and nothing is re-sent."""
        if not alert_ids:
            return set()
        with self.connect(read_only=True) as con:
            seen = {
                r[0]
                for r in con.execute(
                    "SELECT alert_id FROM ops.alerts WHERE list_contains(?, alert_id)", [alert_ids]
                ).fetchall()
            }
        return set(alert_ids) - seen

    def insert_alerts(self, alerts: list[dict]) -> None:
        with self.connect() as con:
            for a in alerts:
                con.execute(
                    "INSERT OR IGNORE INTO ops.alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        a["alert_id"],
                        a["run_id"],
                        a["created_at"],
                        a["alert_type"],
                        a["severity"],
                        a.get("vulnerability_id"),
                        a["title"],
                        a["message"],
                        a.get("delivered_to"),
                    ],
                )

    def query(self, sql: str, params: list | None = None) -> pd.DataFrame:
        with self.connect(read_only=True) as con:
            return con.execute(sql, params or []).df()
