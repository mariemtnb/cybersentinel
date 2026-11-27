"""Run dbt (`dbt build`) on the working warehouse — the WRITE + AUDIT part of write-audit-publish.

`dbt build` runs models, the snapshot and every test in dependency order, and skips the
models downstream of a failing test. If any node errors or any test fails, we do not publish.

dbt runs in a separate process (`python -m dbt.cli.main build`): dbt-duckdb keeps its
database connections open for the lifetime of the process, so running it in-process would
keep the warehouse locked. We read the structured results from target/run_results.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from cybersentinel.logs import get_logger

log = get_logger("transform")


def dbt_env(settings) -> dict[str, str]:
    """dbt's profiles.yml reads these variables, so dbt and Python always use the same files."""
    return {
        **os.environ,
        "CYBERSENTINEL_WAREHOUSE": str(settings.warehouse_path),
        "CYBERSENTINEL_OPS_DB": str(settings.ops_db_path),
        "CYBERSENTINEL_SCORING": str(settings.scoring_path),
        "PYTHONIOENCODING": "utf-8",
    }


def invoke_dbt(settings, args: list[str], run_vars: dict | None = None) -> subprocess.CompletedProcess:
    project = str(settings.dbt_project_dir)
    cmd = [sys.executable, "-m", "dbt.cli.main", *args, "--project-dir", project, "--profiles-dir", project]
    if run_vars:
        cmd += ["--vars", json.dumps(run_vars)]
    return subprocess.run(
        cmd,
        env=dbt_env(settings),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def summarise(run_results_path: Path) -> tuple[dict, list[str]]:
    data = json.loads(Path(run_results_path).read_text(encoding="utf-8"))
    statuses: Counter = Counter()
    failures = []
    for node in data.get("results", []):
        status = node.get("status")
        statuses[status] += 1
        if status in ("error", "fail", "runtime error"):
            failures.append(f"{node.get('unique_id')}: {(node.get('message') or '')[:300]}")
    return dict(statuses), failures


def run_dbt(ctx) -> tuple[bool, dict]:
    run_vars = {"run_id": ctx.run_id, "is_baseline": ctx.ops.is_baseline(ctx.run_id)}
    log.info("dbt build started", extra={"run_id": ctx.run_id})
    # --no-partial-parse: re-read the project every run. It costs ~2 s but guarantees that a
    # changed env var (e.g. the scoring rules path) is never served from a stale parse cache.
    proc = invoke_dbt(ctx.settings, ["build", "--no-partial-parse"], run_vars)
    run_results = Path(ctx.settings.dbt_project_dir) / "target" / "run_results.json"
    summary: dict = {"returncode": proc.returncode}
    failures: list[str] = []
    if run_results.exists():
        summary["statuses"], failures = summarise(run_results)
    summary["failures"] = failures[:20]
    ok = proc.returncode == 0 and not failures
    if not ok:
        summary["output_tail"] = proc.stdout[-2000:] + proc.stderr[-1000:]
    (log.info if ok else log.error)("dbt build finished", extra={"run_id": ctx.run_id, "ok": ok, **summary})
    return ok, summary
