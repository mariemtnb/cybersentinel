"""The pipeline steps, in dependency order.

    extract ─► raw layer (original payloads) ─► validate (contracts) ─► load (DuckDB raw schema)
        ─► dbt build (staging → intermediate → marts + tests)        = WRITE + AUDIT
        ─► publish (atomic copy of the audited warehouse)             = PUBLISH
        ─► alerts

Source order: CISA KEV and OSV first, then NVD (it looks up CVEs that KEV/OSV reference but
the warehouse does not know yet), then EPSS (it scores every CVE the other three produced).

Run status:
- success  every source loaded, dbt build and tests passed, the new warehouse is published;
- partial  at least one source failed (API down) or was blocked by its quality gate; its
           previous data stays in place, the rest is refreshed and published;
- failed   dbt build/tests failed or publication failed: nothing new is published and the
           dashboard keeps serving the last good version.

The same functions are called by the Prefect flow (orchestration/flows.py) and by the CLI.
"""

from __future__ import annotations

import json
import secrets
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cybersentinel.http import SourceUnavailableError
from cybersentinel.ingestion import cisa, epss, nvd, osv
from cybersentinel.ingestion.base import SourceBatch
from cybersentinel.ingestion.watchlist import load_watchlist
from cybersentinel.loading import warehouse
from cybersentinel.loading.ops import OpsStore
from cybersentinel.logs import get_logger, setup_logging
from cybersentinel.settings import Settings, load_settings
from cybersentinel.storage.raw_store import RawStore, make_raw_store
from cybersentinel.validation.contracts import Contract, load_all
from cybersentinel.validation.validate import validate_table

log = get_logger("pipeline")

SOURCES = ["cisa_kev", "osv", "nvd", "epss"]


@dataclass
class RunContext:
    settings: Settings
    run_id: str
    started_at: datetime
    ops: OpsStore
    raw_store: RawStore
    contracts: dict[str, Contract]
    session: Any = None  # injectable HTTP session (tests / offline replay)


@dataclass
class SourceResult:
    source: str
    status: str  # success | failed | blocked
    error: str | None = None
    counts: dict[str, int] = field(default_factory=dict)


def new_run_id(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return f"{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def start_run(trigger: str = "manual", settings: Settings | None = None, session: Any = None) -> RunContext:
    settings = settings or load_settings()
    setup_logging(settings.log_level)
    ops = OpsStore(settings.ops_db_path)
    run_id = new_run_id()
    started_at = ops.start_run(run_id, trigger)
    con = warehouse.connect(settings.warehouse_path)
    warehouse.init_warehouse(con)
    con.close()
    log.info(
        "pipeline run started",
        extra={
            "run_id": run_id,
            "trigger": trigger,
            "nvd_api_key": "configured" if settings.has_nvd_key else "absent",
        },
    )
    return RunContext(
        settings, run_id, started_at, ops, make_raw_store(settings), load_all(settings.contracts_dir), session
    )


# --- extraction context read from the warehouse ------------------------------------------------
def _query_list(ctx: RunContext, sql: str) -> list:
    con = warehouse.connect(ctx.settings.warehouse_path, read_only=True)
    try:
        return [r[0] for r in con.execute(sql).fetchall()]
    finally:
        con.close()


def _extract(ctx: RunContext, source: str) -> SourceBatch:
    s, timeout = ctx.settings, ctx.settings.http_timeout
    if source == "cisa_kev":
        return cisa.extract(cisa.make_client(timeout, ctx.session))

    if source == "osv":
        packages = load_watchlist(s.watchlist_path)
        con = warehouse.connect(s.warehouse_path, read_only=True)
        try:
            rows = con.execute(
                "SELECT osv_id, strftime(modified AT TIME ZONE 'UTC', '%Y-%m-%dT%H:%M:%S.%fZ'), "
                "affected_json FROM raw.osv_vulnerabilities"
            ).fetchall()
        finally:
            con.close()
        known_modified = {r[0]: r[1] for r in rows}
        known_affected = {r[0]: json.loads(r[2]) for r in rows if r[2]}
        return osv.extract(osv.make_client(timeout, ctx.session), packages, known_modified, known_affected)

    if source == "nvd":
        watermark = ctx.ops.get_watermark("nvd")
        has_kev_rows = _query_list(
            ctx, "SELECT count(*) > 0 FROM raw.nvd_cves n JOIN raw.cisa_kev k USING (cve_id)"
        )[0]
        # CVEs referenced by KEV or OSV that NVD has not given us yet (capped per run).
        missing = _query_list(
            ctx,
            """
            SELECT cve_id FROM (
                SELECT cve_id, 1 AS prio FROM raw.cisa_kev
                UNION ALL SELECT cve_id, 0 FROM raw.osv_vulnerabilities WHERE cve_id IS NOT NULL)
            WHERE cve_id NOT IN (SELECT cve_id FROM raw.nvd_cves)
            GROUP BY cve_id ORDER BY min(prio), cve_id""",
        )
        skip = ctx.ops.recent_lookup_misses()  # NVD had nothing for these a few days ago
        missing = [c for c in missing if c not in skip]
        lookups = missing[: s.nvd_max_cve_lookups]
        if not has_kev_rows and watermark is None:
            # Bootstrap: KEV CVEs come in bulk through hasKev; only OSV aliases need lookups.
            osv_only = set(
                _query_list(ctx, "SELECT cve_id FROM raw.osv_vulnerabilities WHERE cve_id IS NOT NULL")
            )
            lookups = [c for c in missing if c in osv_only][: s.nvd_max_cve_lookups]
        return nvd.extract(
            nvd.make_client(s.nvd_api_key, timeout, ctx.session),
            watermark,
            s.nvd_backfill_days,
            include_kev_bootstrap=not has_kev_rows,
            cve_lookups=lookups,
        )

    if source == "epss":
        tracked = _query_list(
            ctx,
            """
            SELECT DISTINCT cve_id FROM (
                SELECT cve_id FROM raw.cisa_kev UNION SELECT cve_id FROM raw.nvd_cves
                UNION SELECT cve_id FROM raw.osv_vulnerabilities WHERE cve_id IS NOT NULL) ORDER BY 1""",
        )
        scored = set(_query_list(ctx, "SELECT DISTINCT cve_id FROM raw.epss_scores"))
        return epss.extract(
            epss.make_client(timeout, ctx.session),
            [c for c in tracked if c in scored],
            [c for c in tracked if c not in scored],
        )
    raise ValueError(f"unknown source {source}")


# --- one source, end to end ----------------------------------------------------------------------
def ingest_source(ctx: RunContext, source: str) -> SourceResult:
    started = datetime.now(UTC)
    log.info("source extraction started", extra={"run_id": ctx.run_id, "source": source})
    try:
        batch = _extract(ctx, source)
    except (SourceUnavailableError, ValueError, KeyError) as exc:
        message = f"{type(exc).__name__}: {exc}"
        log.error(
            "source extraction failed", extra={"run_id": ctx.run_id, "source": source, "error": message}
        )
        ctx.ops.record_source(ctx.run_id, source, started, "failed", error=message)
        return SourceResult(source, "failed", message)

    raw_info = ctx.raw_store.save_payloads(source, ctx.run_id, ctx.started_at, batch.payloads, batch.metadata)
    requests_made = batch.metadata.get("requests", 0)
    common = {
        "requests": requests_made,
        "schema_warnings": batch.schema_warnings or None,
        "source_timestamp": str(batch.metadata.get("source_timestamp") or ""),
        "raw_location": raw_info["prefix"],
        "metadata": batch.metadata,
    }

    if batch.critical_errors:
        message = "; ".join(batch.critical_errors)
        log.error(
            "source blocked by a dataset check",
            extra={"run_id": ctx.run_id, "source": source, "error": message},
        )
        ctx.ops.record_source(ctx.run_id, source, started, "blocked", error=message, **common)
        return SourceResult(source, "blocked", message)

    validated, counts, critical, warnings = {}, {"extracted": 0, "valid": 0, "rejected": 0}, [], []
    for table, df in batch.tables.items():
        contract = ctx.contracts[table]
        valid, rejected, report = validate_table(df, contract)
        validated[table] = valid
        counts["extracted"] += report.rows_in
        counts["valid"] += report.rows_valid
        counts["rejected"] += report.rows_rejected
        critical += report.critical
        warnings += report.warnings
        ctx.raw_store.save_table("validated", table, ctx.run_id, ctx.started_at, valid)
        ctx.raw_store.save_table("rejected", table, ctx.run_id, ctx.started_at, rejected)
        ctx.ops.quarantine(ctx.run_id, source, table, rejected, contract.primary_key)
        log.info(
            "table validated",
            extra={
                "run_id": ctx.run_id,
                "source": source,
                "table": table,
                "rows_in": report.rows_in,
                "valid": report.rows_valid,
                "rejected": report.rows_rejected,
                "reasons": report.reasons,
            },
        )
    common["schema_warnings"] = (batch.schema_warnings + warnings) or None

    if critical:
        message = "; ".join(critical)
        log.error(
            "source blocked by its data contract",
            extra={"run_id": ctx.run_id, "source": source, "error": message},
        )
        ctx.ops.record_source(
            ctx.run_id,
            source,
            started,
            "blocked",
            error=message,
            records_extracted=counts["extracted"],
            records_valid=counts["valid"],
            records_rejected=counts["rejected"],
            **common,
        )
        return SourceResult(source, "blocked", message, counts)

    con = warehouse.connect(ctx.settings.warehouse_path)
    inserted = updated = unchanged = 0
    try:
        for table, df in validated.items():
            result = warehouse.load_table(con, table, df, ctx.run_id)
            inserted, updated, unchanged = (
                inserted + result.inserted,
                updated + result.updated,
                unchanged + result.unchanged,
            )
        if source == "cisa_kev":
            warehouse.mark_kev_catalog(con, validated["cisa_kev"]["cve_id"].tolist())
    finally:
        con.close()
    if source == "nvd":
        ctx.ops.set_watermark("nvd", datetime.fromisoformat(batch.metadata["watermark_to"]), ctx.run_id)
        ctx.ops.record_lookup_misses(batch.metadata.get("lookup_misses", []), ctx.run_id)

    counts.update({"inserted": inserted, "updated": updated, "unchanged": unchanged})
    ctx.ops.record_source(
        ctx.run_id,
        source,
        started,
        "success",
        records_extracted=counts["extracted"],
        records_valid=counts["valid"],
        records_rejected=counts["rejected"],
        records_inserted=inserted,
        records_updated=updated,
        records_unchanged=unchanged,
        **common,
    )
    log.info("source loaded", extra={"run_id": ctx.run_id, "source": source, **counts})
    return SourceResult(source, "success", counts=counts)


def finish(
    ctx: RunContext,
    results: dict[str, SourceResult],
    dbt_ok: bool,
    published: bool,
    error: str | None,
    dbt_summary: dict | None,
) -> str:
    if not dbt_ok or not published:
        status = "failed"
    elif all(r.status == "success" for r in results.values()):
        status = "success"
    else:
        status = "partial"
    ctx.ops.finish_run(ctx.run_id, status, published, error, dbt_summary)
    log.info("pipeline run finished", extra={"run_id": ctx.run_id, "status": status, "published": published})
    return status


def _direct(name: str, fn: Callable, *args: Any) -> Any:
    return fn(*args)


def run_steps(ctx: RunContext, sources: list[str] | None = None, call: Callable = _direct) -> dict:
    """The single definition of the step order.

    `call(name, function, *args)` runs one step. The CLI passes a plain function call; the
    Prefect flow passes a wrapper that turns each step into a Prefect task (so each step is
    visible, timed and logged in the Prefect UI) without duplicating the logic here.
    """
    from cybersentinel.alerts.alerts import generate_alerts
    from cybersentinel.loading.publish import publish
    from cybersentinel.transform import run_dbt

    results: dict[str, SourceResult] = {}
    dbt_ok, published, error, dbt_summary = False, False, None, None
    try:
        for source in sources or SOURCES:
            results[source] = call(f"ingest-{source}", ingest_source, ctx, source)
        dbt_ok, dbt_summary = call("dbt-build", run_dbt, ctx)
        if not dbt_ok:
            error = "dbt build or tests failed — the new warehouse was not published"
        else:
            call("publish", publish, ctx.settings.warehouse_path, ctx.settings.published_path)
            published = True
    except Exception as exc:  # unexpected failure: record it, never report success
        error = f"{type(exc).__name__}: {exc}"
        log.error(
            "pipeline run crashed",
            extra={"run_id": ctx.run_id, "error": error, "trace": traceback.format_exc()},
        )
    status = finish(ctx, results, dbt_ok, published, error, dbt_summary)
    try:
        call("alerts", generate_alerts, ctx, results, status)
    except Exception as exc:
        log.error("alert generation failed", extra={"run_id": ctx.run_id, "error": str(exc)})
    return {
        "run_id": ctx.run_id,
        "status": status,
        "published": published,
        "error": error,
        "sources": {k: {"status": v.status, "error": v.error, **v.counts} for k, v in results.items()},
    }


def run_pipeline(
    trigger: str = "manual",
    sources: list[str] | None = None,
    session: Any = None,
    settings: Settings | None = None,
) -> dict:
    """Run the whole pipeline once, without Prefect (CLI, tests, CI)."""
    return run_steps(start_run(trigger, settings, session), sources)
