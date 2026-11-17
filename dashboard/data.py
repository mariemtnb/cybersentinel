"""Read-only data access for the dashboard.

- Analytics come from the PUBLISHED warehouse only (the audited copy, see loading/publish.py).
- Pipeline health comes from the live ops database, so a failed, unpublished run is visible.
Connections are opened read-only for each query and closed immediately. Results are cached
for 60 s and the cache key includes the file's modification time, so a new publication is
picked up at once. Every query uses bound parameters (`?`), never string formatting.
"""

from __future__ import annotations

import time
from pathlib import Path

import duckdb
import pandas as pd
import streamlit as st

from cybersentinel.settings import load_settings

SETTINGS = load_settings()


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return 0.0


def published_available() -> bool:
    return SETTINGS.published_path.exists()


def ops_available() -> bool:
    return SETTINGS.ops_db_path.exists()


def _read(path: Path, sql: str, params: tuple) -> pd.DataFrame:
    last = None
    for attempt in range(6):
        try:
            con = duckdb.connect(str(path), read_only=True)
        except (duckdb.IOException, duckdb.Error) as exc:  # file being replaced / written
            last = exc
            time.sleep(0.3 * (attempt + 1))
            continue
        try:
            return con.execute(sql, list(params)).df()
        finally:
            con.close()
    raise last  # type: ignore[misc]


@st.cache_data(ttl=60, show_spinner=False)
def _cached(path_str: str, sql: str, params: tuple, _mtime_key: float) -> pd.DataFrame:
    return _read(Path(path_str), sql, params)


def query(sql: str, params: tuple | list = ()) -> pd.DataFrame:
    path = SETTINGS.published_path
    return _cached(str(path), sql, tuple(params), _mtime(path))


def ops_query(sql: str, params: tuple | list = ()) -> pd.DataFrame:
    path = SETTINGS.ops_db_path
    return _cached(str(path), sql, tuple(params), _mtime(path))


def last_published_run() -> pd.Series | None:
    if not ops_available():
        return None
    df = ops_query("""
        SELECT run_id, trigger, finished_at, status, is_baseline FROM ops.pipeline_runs
        WHERE published ORDER BY finished_at DESC LIMIT 1""")
    return None if df.empty else df.iloc[0]
