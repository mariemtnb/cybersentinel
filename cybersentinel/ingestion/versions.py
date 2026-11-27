"""Decide whether a package version falls inside an OSV affected range.

OSV's query API already filters by version, but we do not trust that blindly: for each
(watched package, advisory) pair we re-check the advisory's own ranges. The result is one of:

- "affected"      the version is listed explicitly, or falls in [introduced, fixed) / [introduced, last_affected];
- "not_affected"  we could evaluate the ranges and the version is outside all of them;
- "unverified"    the ranges use a format we cannot compare (e.g. GIT commit ranges or an
                  unparseable version). We keep the record but never count it as confirmed.

Version comparison rules per ecosystem:
- PyPI: PEP 440 via `packaging.version`.
- npm and other SEMVER ranges: semantic versioning (major.minor.patch, pre-release < release).
- Maven and anything else with an ECOSYSTEM range: a cautious numeric dotted comparison; if a
  version has non-numeric parts we return "unverified" instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

AFFECTED, NOT_AFFECTED, UNVERIFIED = "affected", "not_affected", "unverified"

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


class UncomparableVersion(ValueError):
    pass


def _semver_key(value: str) -> tuple:
    m = _SEMVER.match(value.strip())
    if not m:
        raise UncomparableVersion(value)
    major, minor, patch, pre = m.groups()
    # A release (no pre-release) sorts after any pre-release of the same version.
    pre_key: tuple = (
        (1,)
        if pre is None
        else (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
    )
    return (int(major), int(minor), int(patch), pre_key)


def _dotted_key(value: str) -> tuple:
    parts = value.strip().split(".")
    if not all(p.isdigit() for p in parts):
        raise UncomparableVersion(value)
    nums = [int(p) for p in parts]
    while nums and nums[-1] == 0:
        nums.pop()
    return tuple(nums)


def version_key(ecosystem: str, range_type: str, value: str):
    if value == "0":
        return None  # "0" means "since the first version": handled by the caller
    if ecosystem == "PyPI":
        try:
            return Version(value)
        except InvalidVersion as exc:
            raise UncomparableVersion(value) from exc
    if range_type == "SEMVER" or ecosystem == "npm":
        return _semver_key(value)
    return _dotted_key(value)


@dataclass
class MatchResult:
    status: str
    fixed_version: str | None
    evidence: str


def normalise_name(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "PyPI" else name


def evaluate(ecosystem: str, package: str, version: str, affected: list[dict[str, Any]]) -> MatchResult:
    """Evaluate one advisory's `affected` list for one package version."""
    wanted = normalise_name(ecosystem, package)
    entries = [
        a
        for a in affected
        if (a.get("package") or {}).get("ecosystem") == ecosystem
        and normalise_name(ecosystem, (a.get("package") or {}).get("name", "")) == wanted
    ]
    if not entries:
        return MatchResult(UNVERIFIED, None, "advisory has no affected entry for this package name")

    any_evaluated = False
    for entry in entries:
        if version in (entry.get("versions") or []):
            return MatchResult(AFFECTED, _fixed_for(entry, ecosystem, version), "version listed explicitly")
        for rng in entry.get("ranges") or []:
            rtype = rng.get("type")
            if rtype not in ("ECOSYSTEM", "SEMVER"):
                continue
            try:
                hit, fixed = _in_range(ecosystem, rtype, version, rng.get("events") or [])
            except UncomparableVersion:
                continue
            any_evaluated = True
            if hit:
                return MatchResult(AFFECTED, fixed, f"{rtype} range check")
    if any_evaluated:
        return MatchResult(NOT_AFFECTED, None, "version outside every evaluated range")
    return MatchResult(UNVERIFIED, None, "no comparable range (e.g. GIT ranges only)")


def _in_range(ecosystem: str, rtype: str, version: str, events: list[dict]) -> tuple[bool, str | None]:
    """Walk the ordered OSV events. Returns (is_affected, fixed_version_of_matching_range)."""
    v = version_key(ecosystem, rtype, version)
    introduced = None
    open_range = False
    for event in events:
        if "introduced" in event:
            introduced = version_key(ecosystem, rtype, event["introduced"])
            open_range = True
        elif "fixed" in event and open_range:
            fixed = version_key(ecosystem, rtype, event["fixed"])
            if (introduced is None or v >= introduced) and v < fixed:
                return True, event["fixed"]
            open_range = False
        elif "last_affected" in event and open_range:
            last = version_key(ecosystem, rtype, event["last_affected"])
            if (introduced is None or v >= introduced) and v <= last:
                return True, None
            open_range = False
    if open_range and (introduced is None or v >= introduced):
        return True, None  # introduced and never fixed
    return False, None


def _fixed_for(entry: dict, ecosystem: str, version: str) -> str | None:
    for rng in entry.get("ranges") or []:
        if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
            try:
                hit, fixed = _in_range(ecosystem, rng["type"], version, rng.get("events") or [])
            except UncomparableVersion:
                continue
            if hit and fixed:
                return fixed
    return None
