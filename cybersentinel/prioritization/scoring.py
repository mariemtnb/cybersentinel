"""Explainable prioritization engine.

Input : one row per vulnerability with its risk signals (built by dbt in int_risk_signals):
        cvss_base_score, severity_label, is_kev, kev_ransomware, epss_score,
        watchlist_affected_count, fix_available.
Output: the same rows plus
        points_cvss, points_kev, points_epss, points_watchlist, points_fix, priority_score (0–100),
        priority_tier (Critical/High/Medium/Low), priority_reason (one readable sentence).

The function is pure (no I/O): easy to unit test, and called from the dbt Python model
`int_vulnerability_priority`, so the warehouse and the tests use exactly the same code.
"""

from __future__ import annotations

import math

import pandas as pd

from cybersentinel.prioritization.rules import TIER_ORDER, Rules


def _num(value) -> float | None:
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) else f


def _flag(value) -> bool:
    if value is None or pd.isna(value):
        return False
    return bool(value)


def score_one(row: dict, rules: Rules) -> dict:
    parts: list[str] = []

    # 1. CVSS — technical severity
    cvss = _num(row.get("cvss_base_score"))
    cvss_note = ""
    if cvss is None:
        label = str(row.get("severity_label") or "").upper()
        cvss = rules.cvss_label_fallback.get(label)
        cvss_note = f" (estimated from advisory label {label})" if cvss is not None else ""
    points_cvss = round((cvss or 0) / 10 * rules.cvss_max, 1)
    parts.append(
        f"CVSS {cvss:.1f}{cvss_note} → {points_cvss:g} pts"
        if cvss is not None
        else "no CVSS score available → 0 pts"
    )

    # 2. CISA KEV — confirmed exploitation
    is_kev = _flag(row.get("is_kev"))
    ransomware = _flag(row.get("kev_ransomware"))
    points_kev = (rules.kev_points + (rules.ransomware_bonus if ransomware else 0)) if is_kev else 0.0
    if is_kev:
        parts.append(f"in CISA KEV{' (ransomware use known)' if ransomware else ''} → {points_kev:g} pts")

    # 3. EPSS — predicted exploitation probability
    epss = _num(row.get("epss_score"))
    points_epss = 0.0
    if epss is not None:
        points_epss = next(points for minimum, points in rules.epss_bands if epss >= minimum)
        parts.append(f"EPSS {epss:.1%} → {points_epss:g} pts")
    else:
        parts.append("no EPSS score → 0 pts")

    # 4. Watchlist — affects our inventory
    affected = int(_num(row.get("watchlist_affected_count")) or 0)
    in_watchlist = affected > 0
    points_watch = rules.watchlist_points if in_watchlist else 0.0
    if in_watchlist:
        parts.append(f"affects {affected} watched package(s) → {points_watch:g} pts")

    # 5. Fix available — only meaningful for affected watchlist packages
    fix = in_watchlist and _flag(row.get("fix_available"))
    points_fix = rules.fix_points if fix else 0.0
    if fix:
        parts.append(f"fixed version available → {points_fix:g} pts")

    score = min(round(points_cvss + points_kev + points_epss + points_watch + points_fix, 1), rules.max_score)
    tier = next(name for name, minimum in rules.tiers if score >= minimum)

    present = {"kev"} if is_kev else set()
    if in_watchlist:
        present.add("watchlist")
    if fix:
        present.add("fix_available")
    floor_reason = ""
    for required, floor_tier, reason in rules.floors:
        if required <= present and TIER_ORDER.index(floor_tier) > TIER_ORDER.index(tier):
            tier, floor_reason = floor_tier, reason
    explanation = f"{tier} ({score:g}/100): " + "; ".join(parts)
    if floor_reason:
        explanation += f". Raised to {tier} because: {floor_reason}"

    return {
        "points_cvss": points_cvss,
        "points_kev": points_kev,
        "points_epss": points_epss,
        "points_watchlist": points_watch,
        "points_fix": points_fix,
        "priority_score": score,
        "priority_tier": tier,
        "priority_rank": TIER_ORDER.index(tier) + 1,
        "priority_reason": explanation,
    }


def score_vulnerabilities(df: pd.DataFrame, rules: Rules) -> pd.DataFrame:
    if df.empty:
        cols = [
            "points_cvss",
            "points_kev",
            "points_epss",
            "points_watchlist",
            "points_fix",
            "priority_score",
            "priority_tier",
            "priority_rank",
            "priority_reason",
        ]
        return df.assign(**{c: pd.Series(dtype="object") for c in cols})
    scored = pd.DataFrame([score_one(r, rules) for r in df.to_dict("records")], index=df.index)
    return pd.concat([df, scored], axis=1)
