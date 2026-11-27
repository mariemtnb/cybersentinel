"""Source B — NIST National Vulnerability Database (NVD), CVE API 2.0.

Input : https://services.nvd.nist.gov/rest/json/cves/2.0 (optional API key in the `apiKey` header).
Output: tables `nvd_cves` (one row per CVE) and `nvd_cpe_matches` (vendor/product per CVE).

How we avoid downloading the whole database (~300k CVEs) every day:
- First run: (a) all CVEs modified in the last NVD_BACKFILL_DAYS days, and (b) every CVE that
  is in the CISA KEV catalog (`hasKev` filter, ~1.8k CVEs, one page).
- Later runs: only CVEs modified since the previous successful run (the watermark), with a
  15-minute overlap so nothing falls between two runs. NVD limits a date range to 120 days,
  so long gaps are split into 120-day windows.
- Plus a small number of targeted `cveId` lookups for CVEs that another source references
  (new KEV entries, OSV aliases) but that are not in the warehouse yet.

Rate limits (NVD documentation): 5 requests / 30 s without a key, 50 / 30 s with a key.
We wait 6 s (no key) or 0.6 s (key) between requests. Pages hold up to 2,000 CVEs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pandas as pd

from cybersentinel.http import HttpClient
from cybersentinel.ingestion.base import RawPayload, SourceBatch, check_fields

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "nvd"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
OVERLAP = timedelta(minutes=15)

EXPECTED_CVE_FIELDS = {
    "id",
    "sourceIdentifier",
    "published",
    "lastModified",
    "vulnStatus",
    "cveTags",
    "descriptions",
    "metrics",
    "weaknesses",
    "configurations",
    "references",
    "affected",
    "evaluatorComment",
    "evaluatorImpact",
    "evaluatorSolution",
    "cisaExploitAdd",
    "cisaActionDue",
    "cisaRequiredAction",
    "cisaVulnerabilityName",
    "vendorComments",
}
REQUIRED_CVE_FIELDS = {"id", "published", "lastModified"}

# Which CVSS version we take as "the" CVSS score, in order of preference. v3.1 is still the
# version scored for the largest share of CVEs; v4.0 is used when no v3.x score exists.
CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]


def make_client(api_key: str | None, timeout: int = 60, session=None) -> HttpClient:
    headers = {"apiKey": api_key} if api_key else {}
    return HttpClient(
        name=SOURCE,
        min_interval=0.6 if api_key else 6.0,
        timeout=timeout,
        headers=headers,
        session=session,
        retry_statuses=frozenset({403, 429, 500, 502, 503, 504}),  # NVD answers 403 when throttling
    )


def _fmt(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def plan_windows(
    watermark: datetime | None, now: datetime, backfill_days: int
) -> list[tuple[datetime, datetime]]:
    """Return the lastModified windows to request, each at most 120 days long."""
    start = (watermark - OVERLAP) if watermark else now - timedelta(days=backfill_days)
    windows = []
    while start < now:
        end = min(start + MAX_WINDOW, now)
        windows.append((start, end))
        start = end
    return windows


def _fetch_paged(client: HttpClient, params: dict, label: str, payloads: list[RawPayload]) -> None:
    start_index = 0
    while True:
        page_params = {**params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        body = client.get_json(API_URL, params=page_params)
        payloads.append(
            RawPayload(f"{label}_{len(payloads) + 1:04d}", body, {"url": API_URL, "params": page_params})
        )
        total = int(body.get("totalResults", 0))
        start_index += int(body.get("resultsPerPage", 0)) or PAGE_SIZE
        if start_index >= total:
            return


def fetch(
    client: HttpClient,
    watermark: datetime | None,
    backfill_days: int,
    include_kev_bootstrap: bool,
    cve_lookups: list[str],
    now: datetime | None = None,
) -> tuple[list[RawPayload], datetime]:
    now = now or datetime.now(UTC)
    payloads: list[RawPayload] = []
    for start, end in plan_windows(watermark, now, backfill_days):
        _fetch_paged(
            client, {"lastModStartDate": _fmt(start), "lastModEndDate": _fmt(end)}, "modified", payloads
        )
    if include_kev_bootstrap:
        # `hasKev` is a flag parameter with no value.
        _fetch_paged(client, {"hasKev": ""}, "kev", payloads)
    for cve_id in cve_lookups:
        body = client.get_json(API_URL, params={"cveId": cve_id})
        payloads.append(RawPayload(f"lookup_{cve_id}", body, {"url": API_URL, "params": {"cveId": cve_id}}))
    return payloads, now


def _english_description(cve: dict) -> str | None:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return item.get("value")
    return None


def _pick_cvss(metrics: dict) -> dict:
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        return {
            "cvss_version": data.get("version"),
            "cvss_base_score": data.get("baseScore"),
            # v2 keeps severity outside cvssData; v3/v4 inside it.
            "cvss_severity": (data.get("baseSeverity") or entry.get("baseSeverity")),
            "cvss_vector": data.get("vectorString"),
            "cvss_source": entry.get("source"),
        }
    return {
        "cvss_version": None,
        "cvss_base_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "cvss_source": None,
    }


def _cwe_ids(cve: dict) -> str | None:
    ids = sorted(
        {
            d.get("value")
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if (d.get("value") or "").startswith("CWE-")
        }
    )
    return ";".join(ids) or None


def _cpe_rows(cve: dict) -> list[dict]:
    rows = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                rows.append(
                    {
                        "cve_id": cve["id"],
                        "part": parts[2],
                        "vendor": parts[3].replace("\\", ""),
                        "product": parts[4].replace("\\", ""),
                        "vulnerable": bool(match.get("vulnerable")),
                    }
                )
    return rows


def parse(payloads: list[RawPayload]) -> SourceBatch:
    cve_rows, cpe_rows, raw_cves, warnings = [], [], [], []
    source_timestamp = None
    for payload in payloads:
        body = payload.body
        if not isinstance(body, dict) or "vulnerabilities" not in body:
            return SourceBatch(
                SOURCE,
                payloads,
                {},
                critical_errors=[
                    f"{payload.name}: NVD response has no 'vulnerabilities' array — unexpected structure"
                ],
            )
        source_timestamp = max(filter(None, [source_timestamp, body.get("timestamp")]), default=None)
        for item in body["vulnerabilities"]:
            cve = item.get("cve") or {}
            raw_cves.append(cve)
            references = cve.get("references") or []
            cve_rows.append(
                {
                    "cve_id": cve.get("id"),
                    "source_identifier": cve.get("sourceIdentifier"),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "vuln_status": cve.get("vulnStatus"),
                    "description": _english_description(cve),
                    **_pick_cvss(cve.get("metrics") or {}),
                    "cwe_ids": _cwe_ids(cve),
                    "reference_count": len(references),
                    "has_patch_reference": any("Patch" in (r.get("tags") or []) for r in references),
                }
            )
            if cve.get("id"):
                cpe_rows.extend(_cpe_rows(cve))

    warnings += check_fields(raw_cves, EXPECTED_CVE_FIELDS, REQUIRED_CVE_FIELDS, "cve")

    cves = pd.DataFrame(
        cve_rows,
        columns=[
            "cve_id",
            "source_identifier",
            "published",
            "last_modified",
            "vuln_status",
            "description",
            "cvss_version",
            "cvss_base_score",
            "cvss_severity",
            "cvss_vector",
            "cvss_source",
            "cwe_ids",
            "reference_count",
            "has_patch_reference",
        ],
    )
    # The same CVE can appear in two pages (overlapping windows, KEV bootstrap, lookups):
    # keep only its most recent version.
    before = len(cves)
    cves = (
        (
            cves.sort_values("last_modified", na_position="first")
            .drop_duplicates("cve_id", keep="last")
            .reset_index(drop=True)
        )
        if before
        else cves
    )
    cpes = pd.DataFrame(cpe_rows, columns=["cve_id", "part", "vendor", "product", "vulnerable"])
    if len(cpes):
        cpes = cpes.groupby(["cve_id", "part", "vendor", "product"], as_index=False)["vulnerable"].max()
    metadata = {
        "records_in_payloads": before,
        "duplicates_collapsed": before - len(cves),
        "source_timestamp": source_timestamp,
    }
    return SourceBatch(SOURCE, payloads, {"nvd_cves": cves, "nvd_cpe_matches": cpes}, metadata, warnings)


def extract(
    client: HttpClient,
    watermark: datetime | None,
    backfill_days: int,
    include_kev_bootstrap: bool,
    cve_lookups: list[str],
) -> SourceBatch:
    payloads, window_end = fetch(client, watermark, backfill_days, include_kev_bootstrap, cve_lookups)
    batch = parse(payloads)
    misses = [
        p.name.removeprefix("lookup_")
        for p in payloads
        if p.name.startswith("lookup_") and not (p.body or {}).get("vulnerabilities")
    ]
    batch.metadata.update(
        {
            "lookup_misses": misses,
            "requests": client.requests_made,
            "watermark_from": watermark.isoformat() if watermark else None,
            "watermark_to": window_end.isoformat(),
            "kev_bootstrap": include_kev_bootstrap,
            "cve_lookups": len(cve_lookups),
            "api_key_used": client.headers.get("apiKey") is not None,
        }
    )
    return batch
