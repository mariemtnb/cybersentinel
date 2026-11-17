"""Command line entry point.

python -m cybersentinel run [--sources cisa_kev osv nvd epss] [--trigger manual]
python -m cybersentinel status            # last runs and per-source results
python -m cybersentinel watchlist         # check config/watchlist.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from cybersentinel.pipeline import SOURCES, run_pipeline
from cybersentinel.settings import load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cybersentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the whole pipeline once")
    run.add_argument("--sources", nargs="+", choices=SOURCES, default=None)
    run.add_argument("--trigger", default="manual")
    run.add_argument(
        "--replay",
        action="store_true",
        help="offline demo: replay recorded real API responses (tests/fixtures/api) into data-replay/",
    )
    sub.add_parser("status", help="show the latest pipeline runs")
    sub.add_parser("watchlist", help="validate the watchlist file")
    args = parser.parse_args(argv)

    if args.command == "run":
        session = None
        if args.replay:
            # Replay data goes to its own directory so it can never be mistaken for live data.
            from cybersentinel.replay import ReplaySession
            from cybersentinel.settings import PROJECT_ROOT

            os.environ.setdefault("CYBERSENTINEL_DATA_DIR", str(PROJECT_ROOT / "data-replay"))
            os.environ.setdefault(
                "WATCHLIST_PATH", str(PROJECT_ROOT / "tests" / "fixtures" / "watchlist.yaml")
            )
            session, args.trigger = ReplaySession(), "replay"
        summary = run_pipeline(trigger=args.trigger, sources=args.sources, session=session)
        print(json.dumps(summary, indent=2, default=str))
        return 0 if summary["status"] in ("success", "partial") else 1

    settings = load_settings()
    if args.command == "watchlist":
        from cybersentinel.ingestion.watchlist import load_watchlist

        for pkg in load_watchlist(settings.watchlist_path):
            print(pkg.key)
        return 0

    from cybersentinel.loading.ops import OpsStore

    ops = OpsStore(settings.ops_db_path)
    print(
        ops.query(
            "SELECT run_id, trigger, status, published, is_baseline, round(duration_seconds) AS secs, "
            "error FROM ops.pipeline_runs ORDER BY started_at DESC LIMIT 10"
        ).to_string(index=False)
    )
    print()
    print(
        ops.query(
            "SELECT run_id, source, status, records_extracted AS extracted, records_rejected AS rejected, "
            "records_inserted AS inserted, records_updated AS updated, requests "
            "FROM ops.source_runs ORDER BY started_at DESC LIMIT 12"
        ).to_string(index=False)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
