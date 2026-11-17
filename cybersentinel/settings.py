"""Central configuration.

Every value comes from an environment variable with a safe default, so the same code runs
on a laptop, in Docker Compose and in CI. Secrets (NVD_API_KEY, ALERT_WEBHOOK_URL, S3 keys)
are only ever read from the environment — never from a file in the repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value is not None else default


def _env_path(name: str, default: Path) -> Path:
    value = _env(name)
    path = Path(value) if value else default
    return path if path.is_absolute() else (PROJECT_ROOT / path)


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    warehouse_path: Path
    published_path: Path
    ops_db_path: Path
    raw_storage: str  # "local" or "s3"
    lake_dir: Path  # local root of the raw/validated/rejected areas when RAW_STORAGE=local
    s3_bucket: str | None
    s3_endpoint_url: str | None
    s3_region: str | None
    nvd_api_key: str | None = field(repr=False)
    nvd_backfill_days: int
    nvd_max_cve_lookups: int
    watchlist_path: Path
    scoring_path: Path
    contracts_dir: Path
    dbt_project_dir: Path
    alert_webhook_url: str | None = field(repr=False)
    log_level: str
    http_timeout: int

    @property
    def has_nvd_key(self) -> bool:
        return bool(self.nvd_api_key)


def load_settings() -> Settings:
    data_dir = _env_path("CYBERSENTINEL_DATA_DIR", PROJECT_ROOT / "data")
    return Settings(
        data_dir=data_dir,
        warehouse_path=_env_path("CYBERSENTINEL_WAREHOUSE", data_dir / "warehouse" / "cybersentinel.duckdb"),
        published_path=_env_path("CYBERSENTINEL_PUBLISHED", data_dir / "published" / "cybersentinel.duckdb"),
        ops_db_path=_env_path("CYBERSENTINEL_OPS_DB", data_dir / "state" / "pipeline_state.duckdb"),
        raw_storage=(_env("RAW_STORAGE", "local") or "local").lower(),
        lake_dir=_env_path("LAKE_DIR", data_dir / "lake"),
        s3_bucket=_env("S3_BUCKET"),
        s3_endpoint_url=_env("S3_ENDPOINT_URL"),
        s3_region=_env("AWS_REGION", "us-east-1"),
        nvd_api_key=_env("NVD_API_KEY"),
        nvd_backfill_days=_env_int("NVD_BACKFILL_DAYS", 7),
        nvd_max_cve_lookups=_env_int("NVD_MAX_CVE_LOOKUPS", 60),
        watchlist_path=_env_path("WATCHLIST_PATH", PROJECT_ROOT / "config" / "watchlist.yaml"),
        scoring_path=_env_path("SCORING_PATH", PROJECT_ROOT / "config" / "scoring.yaml"),
        contracts_dir=PROJECT_ROOT / "contracts",
        dbt_project_dir=PROJECT_ROOT / "warehouse",
        alert_webhook_url=_env("ALERT_WEBHOOK_URL"),
        log_level=_env("LOG_LEVEL", "INFO") or "INFO",
        http_timeout=_env_int("HTTP_TIMEOUT_SECONDS", 60),
    )
