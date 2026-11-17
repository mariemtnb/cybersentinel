"""Source A — CISA Known Exploited Vulnerabilities (KEV) catalog.

Input : the public JSON feed (no authentication).
Output: table `cisa_kev`, one row per CVE that CISA confirms is exploited in the wild.

The feed is small (~2 MB) and always complete, so every run downloads the whole catalog.
"New KEV entries" are detected later, in the warehouse, by comparing with the previous state.
Dataset-level check: the catalog's own `count` field must equal the number of records.
"""

from __future__ import annotations

import pandas as pd

from cybersentinel.http import HttpClient
from cybersentinel.ingestion.base import RawPayload, SourceBatch, check_fields

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "cisa_kev"

EXPECTED_FIELDS = {
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
    "forensicTriage",
}
REQUIRED_FIELDS = {"cveID", "vendorProject", "product", "dateAdded"}
EXPECTED_TOP_LEVEL = {"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"}


def make_client(timeout: int = 60, session=None) -> HttpClient:
    return HttpClient(name=SOURCE, timeout=timeout, session=session)


def fetch(client: HttpClient) -> list[RawPayload]:
    body = client.get_json(FEED_URL)
    return [RawPayload(name="catalog", body=body, request={"url": FEED_URL})]


def parse(payloads: list[RawPayload]) -> SourceBatch:
    catalog = payloads[0].body
    warnings: list[str] = []
    critical: list[str] = []

    if not isinstance(catalog, dict) or "vulnerabilities" not in catalog:
        return SourceBatch(
            SOURCE,
            payloads,
            {"cisa_kev": pd.DataFrame()},
            critical_errors=["KEV feed has no 'vulnerabilities' array — unexpected structure"],
        )

    unexpected_top = sorted(set(catalog) - EXPECTED_TOP_LEVEL)
    if unexpected_top:
        warnings.append(f"catalog: unexpected top-level field(s) {unexpected_top}")

    records = catalog["vulnerabilities"]
    warnings += check_fields(records, EXPECTED_FIELDS, REQUIRED_FIELDS, "vulnerabilities")

    declared = catalog.get("count")
    if declared is None or int(declared) != len(records):
        critical.append(f"KEV catalog declares count={declared} but contains {len(records)} records")

    rows = [
        {
            "cve_id": (r.get("cveID") or "").strip() or None,
            "vendor_project": r.get("vendorProject"),
            "product": r.get("product"),
            "vulnerability_name": r.get("vulnerabilityName"),
            "date_added": r.get("dateAdded"),
            "short_description": r.get("shortDescription"),
            "required_action": r.get("requiredAction"),
            "due_date": r.get("dueDate"),
            "known_ransomware_campaign_use": r.get("knownRansomwareCampaignUse"),
            "notes": r.get("notes"),
            "cwes": ";".join(r.get("cwes") or []) or None,
            "catalog_version": catalog.get("catalogVersion"),
        }
        for r in records
    ]
    table = pd.DataFrame(
        rows,
        columns=[
            "cve_id",
            "vendor_project",
            "product",
            "vulnerability_name",
            "date_added",
            "short_description",
            "required_action",
            "due_date",
            "known_ransomware_campaign_use",
            "notes",
            "cwes",
            "catalog_version",
        ],
    )
    metadata = {
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": catalog.get("dateReleased"),
        "declared_count": declared,
        "source_timestamp": catalog.get("dateReleased"),
    }
    return SourceBatch(SOURCE, payloads, {"cisa_kev": table}, metadata, warnings, critical)


def extract(client: HttpClient) -> SourceBatch:
    batch = parse(fetch(client))
    batch.metadata["requests"] = client.requests_made
    return batch
