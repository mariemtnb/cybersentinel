"""Prefect orchestration of the CyberSentinel pipeline.

Why Prefect (and not Airflow): the TPs did not use an orchestrator yet, both are allowed by
the project brief, and Prefect needs only one extra container (its API/UI server) and plain
Python functions — no DAG files, scheduler, webserver and metadata database to operate.

The flow does not re-implement the pipeline: it hands `cybersentinel.pipeline.run_steps` a
`call` function that wraps every step in a Prefect task. The order of the steps is defined
once, in pipeline.py, and is the same with or without Prefect.

Run locally once:      python -m orchestration.flows
Serve on a schedule:   python -m orchestration.serve      (used by docker compose)
"""

from __future__ import annotations

from typing import Any

from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE

from cybersentinel.pipeline import SOURCES, run_steps, start_run


def _as_task(name: str, fn, *args: Any) -> Any:
    # NO_CACHE: every run must really execute (the inputs hold open handles, nothing to cache).
    return task(fn, name=name, cache_policy=NO_CACHE, retries=0)(*args)


@flow(name="cybersentinel-daily", log_prints=True)
def daily_pipeline(trigger: str = "schedule", sources: list[str] | None = None) -> dict:
    logger = get_run_logger()
    ctx = start_run(trigger)
    logger.info("CyberSentinel run %s started (trigger=%s)", ctx.run_id, trigger)
    summary = run_steps(ctx, sources or SOURCES, call=_as_task)
    logger.info(
        "Run %s finished with status=%s, published=%s",
        summary["run_id"],
        summary["status"],
        summary["published"],
    )
    if summary["status"] == "failed":
        # Make the Prefect flow run itself fail, so the UI and notifications show it red.
        raise RuntimeError(f"CyberSentinel run {summary['run_id']} failed: {summary['error']}")
    return summary


if __name__ == "__main__":
    daily_pipeline(trigger="manual")
