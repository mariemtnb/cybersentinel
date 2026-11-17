"""Source D — FIRST Exploit Prediction Scoring System (EPSS), https://api.first.org/data/v1/epss.

Input : the list of CVEs the platform tracks (KEV ∪ NVD ∪ OSV aliases), read from the warehouse.
Output: table `epss_scores`, one row per (cve_id, score_date).

EPSS is a *prediction*: the probability that a CVE is exploited in the next 30 days. It is kept
separate from CISA KEV, which is *confirmed* exploitation.

Batching: the API accepts a comma-separated list of CVEs; we send 100 per request to stay
well under URL length limits. For CVEs we have never scored before we ask for
`scope=time-series`, which returns the last 30 days — so EPSS trends are visible from the
first run. Afterwards only the current day's score is requested; each day adds one row
per CVE, building the history.

Alternative considered: the official daily CSV (~400k CVEs, one gzip file). It is the better
choice for a full-universe sync; we track ~10–15k CVEs and need per-CVE history, so batched
API calls are smaller and simpler. See docs/architecture.md.
"""

from __future__ import annotations

import pandas as pd

from cybersentinel.http import HttpClient
from cybersentinel.ingestion.base import RawPayload, SourceBatch, check_fields

API_URL = "https://api.first.org/data/v1/epss"
SOURCE = "epss"
BATCH_SIZE = 100

EXPECTED_FIELDS = {"cve", "epss", "percentile", "date", "time-series", "model_version"}
REQUIRED_FIELDS = {"cve", "epss", "percentile", "date"}


def make_client(timeout: int = 60, session=None) -> HttpClient:
    return HttpClient(name=SOURCE, min_interval=0.1, timeout=timeout, session=session)


def fetch(
    client: HttpClient, cves_with_history: list[str], cves_without_history: list[str]
) -> list[RawPayload]:
    payloads: list[RawPayload] = []
    for cves, time_series in ((cves_without_history, True), (cves_with_history, False)):
        for i in range(0, len(cves), BATCH_SIZE):
            chunk = cves[i : i + BATCH_SIZE]
            params = {"cve": ",".join(chunk), "limit": BATCH_SIZE}
            if time_series:
                params["scope"] = "time-series"
            body = client.get_json(API_URL, params=params)
            if body.get("status") != "OK" and body.get("status-code") not in (200, None):
                raise ValueError(f"EPSS API returned status {body.get('status')}")
            payloads.append(
                RawPayload(
                    f"batch_{len(payloads) + 1:04d}",
                    body,
                    {"url": API_URL, "params": {**params, "cve": f"{len(chunk)} CVEs"}},
                )
            )
    return payloads


def parse(payloads: list[RawPayload]) -> SourceBatch:
    rows, records = [], []
    for payload in payloads:
        body = payload.body
        if not isinstance(body, dict) or not isinstance(body.get("data"), list):
            return SourceBatch(
                SOURCE,
                payloads,
                {},
                critical_errors=[f"{payload.name}: EPSS response has no 'data' array — unexpected structure"],
            )
        for item in body["data"]:
            records.append(item)
            rows.append(
                {
                    "cve_id": item.get("cve"),
                    "score_date": item.get("date"),
                    "epss": item.get("epss"),
                    "percentile": item.get("percentile"),
                }
            )
            for point in item.get("time-series") or []:
                rows.append(
                    {
                        "cve_id": item.get("cve"),
                        "score_date": point.get("date"),
                        "epss": point.get("epss"),
                        "percentile": point.get("percentile"),
                    }
                )
    warnings = check_fields(records, EXPECTED_FIELDS, REQUIRED_FIELDS, "data")
    table = pd.DataFrame(rows, columns=["cve_id", "score_date", "epss", "percentile"])
    before = len(table)
    table = table.drop_duplicates(["cve_id", "score_date"], keep="first").reset_index(drop=True)
    latest = table["score_date"].max() if len(table) else None
    metadata = {
        "rows_in_payloads": before,
        "duplicates_collapsed": before - len(table),
        "source_timestamp": latest,
    }
    return SourceBatch(SOURCE, payloads, {"epss_scores": table}, metadata, warnings)


def extract(client: HttpClient, cves_with_history: list[str], cves_without_history: list[str]) -> SourceBatch:
    batch = parse(fetch(client, cves_with_history, cves_without_history))
    batch.metadata.update(
        {
            "requests": client.requests_made,
            "cves_requested": len(cves_with_history) + len(cves_without_history),
            "cves_backfilled_30d": len(cves_without_history),
        }
    )
    return batch
