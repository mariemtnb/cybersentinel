"""Alerts: tell the team when something important happens.

Two families:
- security alerts, from the change events of the run that was just published:
    KEV_ADDED                 a tracked vulnerability was newly added to CISA KEV (or a new CVE arrived already in KEV)
    NEW_HIGH_PRIORITY         a new vulnerability arrived directly as Critical or High
    PRIORITY_ESCALATED        an existing vulnerability moved up to Critical
    WATCHLIST_NEWLY_AFFECTED  a watched package became affected by a vulnerability
- operational alerts:
    SOURCE_FAILED / SOURCE_BLOCKED   an API was unreachable / a quality gate blocked a source
    PIPELINE_FAILED                  nothing was published by this run
    SOURCE_STALE                     a source has not been refreshed successfully for more than 48 hours

Delivery: every alert is stored in ops.alerts (shown in the dashboard) and written to the log.
If ALERT_WEBHOOK_URL is set, a summary is POSTed as {"text": ...} — the format accepted by
Slack, Mattermost and Microsoft Teams incoming webhooks. No credential is required otherwise.

Alert IDs are deterministic hashes of the underlying event, so re-running the pipeline never
sends the same alert twice. The baseline (first) load does not raise security alerts.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import duckdb
import requests

from cybersentinel.logs import get_logger

log = get_logger("alerts")

STALE_AFTER = timedelta(hours=48)
RECENT_DAYS = 30  # "new" alerts only for vulnerabilities published / added to KEV recently
MAX_SECURITY_ALERTS = 50  # above this, one summary alert is sent instead of a flood
SECURITY_EVENTS_SQL = """
    SELECT c.event_id, c.vulnerability_id, c.event_type, c.old_value, c.new_value,
           f.priority_tier, f.priority_score, f.title, f.is_kev,
           coalesce(f.kev_date_added >= current_date - to_days(?), false)   AS kev_recent,
           coalesce(f.published_date >= current_date - to_days(?), false)   AS published_recent,
           f.watchlist_affected_count > 0                                    AS in_watchlist
    FROM marts.fct_vulnerability_changes c
    JOIN marts.fct_vulnerabilities f USING (vulnerability_id)
    WHERE c.run_id = ? AND NOT c.is_baseline
"""


def _id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def security_alerts(published_db, run_id: str, now: datetime) -> list[dict]:
    con = duckdb.connect(str(published_db), read_only=True)
    try:
        rows = con.execute(SECURITY_EVENTS_SQL, [RECENT_DAYS, RECENT_DAYS, run_id]).fetchall()
    finally:
        con.close()
    alerts = []
    for event_id, vid, etype, old, new, tier, score, title, is_kev, kev_recent, pub_recent, in_watch in rows:
        label = f"{vid} — {title or 'no title'} (priority {tier}, {score:g}/100)"
        # A CVE seen for the first time is only "news" if it is recent or touches our inventory;
        # an old CVE that merely entered the tracked scope (e.g. after a backfill) is not alerted.
        newsworthy = pub_recent or in_watch
        if etype == "KEV_ADDED" or (etype == "NEW_VULNERABILITY" and is_kev and (kev_recent or in_watch)):
            kind, sev, text = (
                "KEV_ADDED",
                "critical",
                f"Newly listed in CISA KEV (confirmed exploited): {label}",
            )
        elif etype == "NEW_VULNERABILITY" and tier in ("Critical", "High") and newsworthy:
            kind, sev, text = "NEW_HIGH_PRIORITY", "high", f"New {tier} vulnerability: {label}"
        elif etype == "PRIORITY_ESCALATED" and new == "Critical":
            kind, sev, text = "PRIORITY_ESCALATED", "high", f"Escalated {old} → Critical: {label}"
        elif etype == "WATCHLIST_EXPOSURE_CHANGED" and int(new or 0) > int(old or 0):
            kind, sev, text = "WATCHLIST_NEWLY_AFFECTED", "high", f"Watched package newly affected: {label}"
        else:
            continue
        alerts.append(
            {
                "alert_id": _id(kind, event_id),
                "run_id": run_id,
                "created_at": now,
                "alert_type": kind,
                "severity": sev,
                "vulnerability_id": vid,
                "title": text[:200],
                "message": text,
            }
        )
    # One alert per vulnerability per run: keep the most important reason (e.g. a KEV addition
    # that also escalates the priority is reported once, as KEV_ADDED).
    rank = {"KEV_ADDED": 0, "WATCHLIST_NEWLY_AFFECTED": 1, "PRIORITY_ESCALATED": 2, "NEW_HIGH_PRIORITY": 3}
    best: dict[str, dict] = {}
    for a in alerts:
        current = best.get(a["vulnerability_id"])
        if current is None or rank[a["alert_type"]] < rank[current["alert_type"]]:
            best[a["vulnerability_id"]] = a
    alerts = list(best.values())
    if len(alerts) > MAX_SECURITY_ALERTS:
        counts: dict[str, int] = {}
        for a in alerts:
            counts[a["alert_type"]] = counts.get(a["alert_type"], 0) + 1
        summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
        log.warning("alert flood suppressed", extra={"run_id": run_id, "alerts": len(alerts)})
        return [
            {
                "alert_id": _id("ALERT_SUMMARY", run_id),
                "run_id": run_id,
                "created_at": now,
                "alert_type": "ALERT_SUMMARY",
                "severity": "high",
                "vulnerability_id": None,
                "title": f"{len(alerts)} security changes in one run ({summary})",
                "message": f"Run {run_id} produced {len(alerts)} security alerts ({summary}). "
                "Individual alerts were grouped to avoid a flood; review the Threat Intelligence page.",
            }
        ]
    return alerts


def operational_alerts(ops, run_id: str, results: dict, status: str, now: datetime) -> list[dict]:
    alerts = []
    for source, result in results.items():
        if result.status in ("failed", "blocked"):
            kind = "SOURCE_FAILED" if result.status == "failed" else "SOURCE_BLOCKED"
            alerts.append(
                {
                    "alert_id": _id(kind, run_id, source),
                    "run_id": run_id,
                    "created_at": now,
                    "alert_type": kind,
                    "severity": "warning",
                    "vulnerability_id": None,
                    "title": f"{source}: {result.status}",
                    "message": f"{source}: {result.error}",
                }
            )
    if status == "failed":
        alerts.append(
            {
                "alert_id": _id("PIPELINE_FAILED", run_id),
                "run_id": run_id,
                "created_at": now,
                "alert_type": "PIPELINE_FAILED",
                "severity": "critical",
                "vulnerability_id": None,
                "title": "Pipeline run failed — dashboard still shows the previous publication",
                "message": f"Run {run_id} failed; nothing new was published.",
            }
        )
    last_success = ops.query(
        "SELECT source, max(finished_at) AS last_ok FROM ops.source_runs "
        "WHERE status = 'success' GROUP BY source"
    )
    for source, last_ok in zip(last_success["source"], last_success["last_ok"], strict=True):
        if last_ok is not None and now - last_ok.to_pydatetime() > STALE_AFTER:
            alerts.append(
                {
                    "alert_id": _id("SOURCE_STALE", source, now.strftime("%Y-%m-%d")),
                    "run_id": run_id,
                    "created_at": now,
                    "alert_type": "SOURCE_STALE",
                    "severity": "warning",
                    "vulnerability_id": None,
                    "title": f"{source} is stale",
                    "message": f"{source}: last successful refresh at {last_ok:%Y-%m-%d %H:%M} UTC",
                }
            )
    return alerts


def deliver_webhook(url: str, alerts: list[dict], run_id: str) -> bool:
    lines = [f"CyberSentinel — {len(alerts)} new alert(s) from run {run_id}"]
    lines += [f"• [{a['severity'].upper()}] {a['title']}" for a in alerts[:25]]
    if len(alerts) > 25:
        lines.append(f"… and {len(alerts) - 25} more in the dashboard")
    try:
        response = requests.post(url, json={"text": "\n".join(lines)}, timeout=15)
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        log.error("webhook delivery failed", extra={"run_id": run_id, "error": type(exc).__name__})
        return False


def generate_alerts(ctx, results: dict, status: str) -> list[dict]:
    now = datetime.now(UTC)
    candidates = operational_alerts(ctx.ops, ctx.run_id, results, status, now)
    if status in ("success", "partial"):
        candidates += security_alerts(ctx.settings.published_path, ctx.run_id, now)
    unseen = ctx.ops.unseen_alert_ids([a["alert_id"] for a in candidates])
    fresh = [a for a in candidates if a["alert_id"] in unseen]
    delivered = "log"
    if fresh and ctx.settings.alert_webhook_url:
        delivered = (
            "log+webhook"
            if deliver_webhook(ctx.settings.alert_webhook_url, fresh, ctx.run_id)
            else "log (webhook failed)"
        )
    for a in fresh:
        a["delivered_to"] = delivered
        log.warning(
            "ALERT",
            extra={
                "run_id": ctx.run_id,
                "alert_type": a["alert_type"],
                "severity": a["severity"],
                "alert": a["title"],
            },
        )
    ctx.ops.insert_alerts(fresh)
    log.info(
        "alerts generated",
        extra={
            "run_id": ctx.run_id,
            "new_alerts": len(fresh),
            "suppressed_duplicates": len(candidates) - len(fresh),
        },
    )
    return fresh
