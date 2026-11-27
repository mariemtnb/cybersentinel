"""Shared types and helpers for connectors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class RawPayload:
    """One original API response, saved as-is in the raw layer."""

    name: str  # file name inside the run folder, e.g. "page_0001"
    body: Any  # the decoded JSON document
    request: dict[str, Any] = field(default_factory=dict)  # URL and parameters (never secrets)


@dataclass
class SourceBatch:
    """Everything one connector produced during one run."""

    source: str
    payloads: list[RawPayload]
    tables: dict[str, pd.DataFrame]
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_warnings: list[str] = field(default_factory=list)
    critical_errors: list[str] = field(default_factory=list)  # dataset-level checks that failed


def check_fields(records: list[dict], expected: set[str], required: set[str], label: str) -> list[str]:
    """Compare the keys of the source records with the fields we know about.

    New fields are reported as schema-drift warnings (the source evolved; nothing breaks).
    Missing required fields are reported too; the affected rows will then fail the contract.
    """
    seen: set[str] = set()
    for record in records:
        seen.update(record.keys())
    warnings = []
    unexpected = sorted(seen - expected)
    if unexpected:
        warnings.append(f"{label}: unexpected new field(s) {unexpected}")
    missing = sorted(required - seen) if records else []
    if missing:
        warnings.append(f"{label}: required field(s) absent from every record {missing}")
    return warnings


def first_cve(ids: list[str]) -> str | None:
    for value in ids:
        if value and CVE_PATTERN.match(value):
            return value
    return None
