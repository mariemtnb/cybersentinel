"""Source C — OSV (Open Source Vulnerabilities), https://api.osv.dev.

Input : the watchlist (config/watchlist.yaml) — package name, ecosystem, version.
Output: tables
  - `osv_vulnerabilities`  one row per OSV advisory (GHSA-…, PYSEC-…), with its CVE alias;
  - `osv_affected_ranges`  the affected version ranges of each advisory;
  - `watchlist_matches`    one row per (watched package, advisory) with our own range verdict.

Flow:
1. POST /v1/querybatch with every watched package+version. OSV answers with advisory IDs and
   their `modified` timestamp. A query with many results returns `next_page_token`; we follow it.
2. GET /v1/vulns/{id} only for advisories that are new or whose `modified` changed since the
   last run (incremental). Unchanged advisories are re-used from the warehouse.
3. For every (package, advisory) pair we re-check the version against the advisory ranges
   (see versions.py) instead of assuming that "returned by OSV" means "affected".
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pandas as pd

from cybersentinel.http import HttpClient
from cybersentinel.ingestion.base import RawPayload, SourceBatch, check_fields, first_cve
from cybersentinel.ingestion.versions import evaluate
from cybersentinel.ingestion.watchlist import WatchedPackage

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
SOURCE = "osv"
MAX_QUERIES_PER_BATCH = 1000  # documented OSV limit

EXPECTED_FIELDS = {
    "id",
    "summary",
    "details",
    "aliases",
    "modified",
    "published",
    "withdrawn",
    "database_specific",
    "references",
    "affected",
    "schema_version",
    "severity",
    "related",
    "credits",
    "upstream",
}
REQUIRED_FIELDS = {"id", "modified"}


def make_client(timeout: int = 60, session=None) -> HttpClient:
    return HttpClient(name=SOURCE, min_interval=0.05, timeout=timeout, session=session)


def _query(pkg: WatchedPackage, page_token: str | None = None) -> dict:
    q = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}, "version": pkg.version}
    if page_token:
        q["page_token"] = page_token
    return q


def fetch(client: HttpClient, packages: list[WatchedPackage], known_modified: dict[str, str]):
    """Return (payloads, hits) where hits maps package key -> list of (osv_id, modified)."""
    payloads: list[RawPayload] = []
    hits: dict[str, list[tuple[str, str]]] = {p.key: [] for p in packages}
    pending = [(p, None) for p in packages]
    while pending:
        chunk, pending = pending[:MAX_QUERIES_PER_BATCH], pending[MAX_QUERIES_PER_BATCH:]
        body = {"queries": [_query(p, token) for p, token in chunk]}
        response = client.post_json(BATCH_URL, body)
        payloads.append(
            RawPayload(f"querybatch_{len(payloads) + 1:03d}", response, {"url": BATCH_URL, "body": body})
        )
        results = response.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise ValueError("OSV querybatch returned an unexpected number of results")
        for (pkg, _), result in zip(chunk, results, strict=True):
            for vuln in result.get("vulns") or []:
                hits[pkg.key].append((vuln["id"], vuln.get("modified")))
            if result.get("next_page_token"):
                pending.append((pkg, result["next_page_token"]))

    to_fetch = sorted(
        {
            osv_id
            for pairs in hits.values()
            for osv_id, modified in pairs
            if known_modified.get(osv_id) != _norm_ts(modified)
        }
    )
    for osv_id in to_fetch:
        url = VULN_URL.format(id=osv_id)
        payloads.append(RawPayload(f"vuln_{osv_id}", client.get_json(url), {"url": url}))
    return payloads, hits


def _norm_ts(value: str | None) -> str | None:
    """OSV timestamps have nanoseconds; normalise to microseconds so they compare with stored values."""
    if not value:
        return None
    ts = pd.Timestamp(value)
    return (
        ts.tz_convert(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if ts.tzinfo
        else ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )


def _ranges(osv_id: str, affected: list[dict]) -> list[dict]:
    rows = []
    for a_idx, entry in enumerate(affected):
        pkg = entry.get("package") or {}
        for r_idx, rng in enumerate(entry.get("ranges") or []):
            introduced = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event or "last_affected" in event:
                    rows.append(
                        {
                            "osv_id": osv_id,
                            "ecosystem": pkg.get("ecosystem"),
                            "package_name": pkg.get("name"),
                            "range_type": rng.get("type"),
                            "range_index": a_idx * 100 + r_idx,
                            "introduced": introduced,
                            "fixed": event.get("fixed"),
                            "last_affected": event.get("last_affected"),
                        }
                    )
                    introduced = None
            if introduced is not None:
                rows.append(
                    {
                        "osv_id": osv_id,
                        "ecosystem": pkg.get("ecosystem"),
                        "package_name": pkg.get("name"),
                        "range_type": rng.get("type"),
                        "range_index": a_idx * 100 + r_idx,
                        "introduced": introduced,
                        "fixed": None,
                        "last_affected": None,
                    }
                )
    return rows


def parse(
    payloads: list[RawPayload],
    packages: list[WatchedPackage],
    hits: dict[str, list[tuple[str, str]]],
    known_affected: dict[str, list[dict]],
    checked_at: datetime | None = None,
) -> SourceBatch:
    checked_at = checked_at or datetime.now(UTC)
    details = [p.body for p in payloads if p.name.startswith("vuln_")]
    warnings = check_fields(details, EXPECTED_FIELDS, REQUIRED_FIELDS, "vuln")

    vuln_rows, range_rows = [], []
    affected_by_id = dict(known_affected)
    for v in details:
        aliases = v.get("aliases") or []
        severity = (v.get("severity") or [{}])[0]
        affected = v.get("affected") or []
        affected_by_id[v["id"]] = affected
        vuln_rows.append(
            {
                "osv_id": v.get("id"),
                "cve_id": v["id"] if (v.get("id") or "").startswith("CVE-") else first_cve(aliases),
                "aliases": ";".join(aliases) or None,
                "summary": v.get("summary"),
                "details": (v.get("details") or "")[:4000] or None,
                "published": v.get("published"),
                "modified": _norm_ts(v.get("modified")),
                "withdrawn": v.get("withdrawn"),
                "severity_label": (v.get("database_specific") or {}).get("severity"),
                "cvss_type": severity.get("type"),
                "cvss_vector": severity.get("score"),
                "affected_json": json.dumps(affected, separators=(",", ":")),
            }
        )
        range_rows.extend(_ranges(v["id"], affected))

    match_rows = []
    for pkg in packages:
        for osv_id, _ in hits.get(pkg.key, []):
            affected = affected_by_id.get(osv_id)
            if affected is None:
                result_status, fixed, evidence = "unverified", None, "advisory details unavailable"
            else:
                r = evaluate(pkg.ecosystem, pkg.name, pkg.version, affected)
                result_status, fixed, evidence = r.status, r.fixed_version, r.evidence
            match_rows.append(
                {
                    "package_name": pkg.name,
                    "ecosystem": pkg.ecosystem,
                    "package_version": pkg.version,
                    "osv_id": osv_id,
                    "match_status": result_status,
                    "fixed_version": fixed,
                    "evidence": evidence,
                    "checked_at": checked_at.isoformat(),
                }
            )

    package_rows = [
        {
            "package_name": p.name,
            "ecosystem": p.ecosystem,
            "package_version": p.version,
            "owner": p.owner,
            "advisories_returned": len(hits.get(p.key, [])),
            "checked_at": checked_at.isoformat(),
        }
        for p in packages
    ]
    tables = {
        "watchlist_packages": pd.DataFrame(
            package_rows,
            columns=[
                "package_name",
                "ecosystem",
                "package_version",
                "owner",
                "advisories_returned",
                "checked_at",
            ],
        ),
        "osv_vulnerabilities": pd.DataFrame(
            vuln_rows,
            columns=[
                "osv_id",
                "cve_id",
                "aliases",
                "summary",
                "details",
                "published",
                "modified",
                "withdrawn",
                "severity_label",
                "cvss_type",
                "cvss_vector",
                "affected_json",
            ],
        ),
        "osv_affected_ranges": pd.DataFrame(
            range_rows,
            columns=[
                "osv_id",
                "ecosystem",
                "package_name",
                "range_type",
                "range_index",
                "introduced",
                "fixed",
                "last_affected",
            ],
        ),
        "watchlist_matches": pd.DataFrame(
            match_rows,
            columns=[
                "package_name",
                "ecosystem",
                "package_version",
                "osv_id",
                "match_status",
                "fixed_version",
                "evidence",
                "checked_at",
            ],
        ).drop_duplicates(["package_name", "ecosystem", "package_version", "osv_id"]),
    }
    n_hits = sum(len(v) for v in hits.values())
    metadata = {
        "packages_queried": len(packages),
        "advisories_returned": n_hits,
        "advisories_fetched": len(details),
        "source_timestamp": checked_at.isoformat(),
    }
    return SourceBatch(SOURCE, payloads, tables, metadata, warnings)


def extract(
    client: HttpClient,
    packages: list[WatchedPackage],
    known_modified: dict[str, str],
    known_affected: dict[str, list[dict]],
) -> SourceBatch:
    payloads, hits = fetch(client, packages, known_modified)
    batch = parse(payloads, packages, hits, known_affected)
    batch.metadata["requests"] = client.requests_made
    return batch
