"""Load and check config/scoring.yaml so a typo fails loudly instead of silently changing priorities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TIER_ORDER = ["Low", "Medium", "High", "Critical"]
KNOWN_SIGNALS = {"kev", "watchlist", "fix_available"}


class ScoringConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Rules:
    cvss_max: float
    cvss_label_fallback: dict[str, float]
    kev_points: float
    ransomware_bonus: float
    epss_bands: list[tuple[float, float]]  # (min_probability, points), highest first
    watchlist_points: float
    fix_points: float
    max_score: float
    tiers: list[tuple[str, float]]  # (name, min_score), highest first
    floors: list[tuple[frozenset[str], str, str]]  # (signals required, tier, reason)


def load_rules(path: Path) -> Rules:
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    try:
        s = cfg["signals"]
        bands = sorted(((float(b["min"]), float(b["points"])) for b in s["epss"]["bands"]), reverse=True)
        tiers = sorted(((t["name"], float(t["min_score"])) for t in cfg["tiers"]), key=lambda t: -t[1])
        floors = [(frozenset(f["when"]), f["tier"], f.get("reason", "")) for f in cfg.get("floors", [])]
        rules = Rules(
            cvss_max=float(s["cvss"]["max_points"]),
            cvss_label_fallback={
                k.upper(): float(v) for k, v in (s["cvss"].get("label_fallback_scores") or {}).items()
            },
            kev_points=float(s["kev"]["points"]),
            ransomware_bonus=float(s["kev"].get("ransomware_bonus", 0)),
            epss_bands=bands,
            watchlist_points=float(s["watchlist"]["points"]),
            fix_points=float(s["fix_available"]["points"]),
            max_score=float(cfg.get("max_score", 100)),
            tiers=tiers,
            floors=floors,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ScoringConfigError(f"{path}: invalid scoring configuration ({exc})") from exc

    names = {t[0] for t in rules.tiers}
    if names != set(TIER_ORDER):
        raise ScoringConfigError(f"{path}: tiers must be exactly {TIER_ORDER}, got {sorted(names)}")
    if min(t[1] for t in rules.tiers) != 0:
        raise ScoringConfigError(f"{path}: the lowest tier must start at 0")
    if not rules.epss_bands or rules.epss_bands[-1][0] != 0:
        raise ScoringConfigError(f"{path}: EPSS bands must include a band starting at 0")
    for when, tier, _ in rules.floors:
        if not when <= KNOWN_SIGNALS or tier not in TIER_ORDER:
            raise ScoringConfigError(f"{path}: invalid floor {sorted(when)} -> {tier}")
    return rules
