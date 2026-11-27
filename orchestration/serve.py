"""Long-running scheduler process (the `pipeline` service in docker compose).

1. Optionally runs the pipeline once at start-up (RUN_ON_STARTUP=true), so `docker compose up`
   on a fresh clone produces data without waiting for the next scheduled time.
2. Registers the daily deployment with the Prefect server and executes scheduled runs.
   Schedule: PIPELINE_CRON (default 06:00 UTC every day). NVD and EPSS publish daily, so a
   daily cadence matches the sources; KEV can change any weekday and is picked up next day.
"""

from __future__ import annotations

import os

from cybersentinel.logs import get_logger, setup_logging
from orchestration.flows import daily_pipeline

log = get_logger("serve")


def main() -> None:
    setup_logging(os.environ.get("LOG_LEVEL", "INFO"))
    cron = os.environ.get("PIPELINE_CRON", "0 6 * * *")
    if os.environ.get("RUN_ON_STARTUP", "true").lower() == "true":
        log.info("running the pipeline once at start-up")
        try:
            daily_pipeline(trigger="startup")
        except Exception as exc:  # the failure is recorded in the ops database; keep the scheduler alive
            log.error("start-up run failed", extra={"error": str(exc)})
    log.info("serving the daily deployment", extra={"cron": cron, "timezone": "UTC"})
    daily_pipeline.serve(name="daily", cron=cron, parameters={"trigger": "schedule"})


if __name__ == "__main__":
    main()
