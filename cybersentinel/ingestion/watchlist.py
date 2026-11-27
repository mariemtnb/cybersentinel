"""Load and check the software watchlist (config/watchlist.yaml).

The watchlist is the configurable inventory of packages we want to monitor. It can be edited
without touching any code. Each entry needs `name`, `ecosystem` and `version`.
The bundled entries are demonstration assets, not a real organisation's inventory.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

SUPPORTED_ECOSYSTEMS = {"PyPI", "npm", "Maven", "Go", "RubyGems", "NuGet", "crates.io", "Packagist"}


class WatchlistError(ValueError):
    pass


@dataclass(frozen=True)
class WatchedPackage:
    name: str
    ecosystem: str
    version: str
    owner: str | None = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


def load_watchlist(path: Path) -> list[WatchedPackage]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = data.get("packages") if isinstance(data, dict) else data
    if not isinstance(entries, list) or not entries:
        raise WatchlistError(f"{path}: expected a non-empty 'packages' list")
    packages, seen = [], set()
    for i, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise WatchlistError(f"{path}: entry #{i} is not a mapping")
        missing = [k for k in ("name", "ecosystem", "version") if not str(entry.get(k) or "").strip()]
        if missing:
            raise WatchlistError(f"{path}: entry #{i} is missing {missing}")
        pkg = WatchedPackage(
            str(entry["name"]).strip(),
            str(entry["ecosystem"]).strip(),
            str(entry["version"]).strip(),
            entry.get("owner"),
        )
        if pkg.ecosystem not in SUPPORTED_ECOSYSTEMS:
            raise WatchlistError(f"{path}: entry #{i} has unsupported ecosystem '{pkg.ecosystem}'")
        if pkg.key in seen:
            raise WatchlistError(f"{path}: duplicate entry {pkg.key}")
        seen.add(pkg.key)
        packages.append(pkg)
    return packages
