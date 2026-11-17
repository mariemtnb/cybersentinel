"""Build the offline test fixtures from REAL responses saved in the raw layer.

The fixtures are trimmed copies of actual API responses captured by a live pipeline run
(data/lake/raw/...). Trimming keeps the repository small; the only edits are:
- the KEV `count` field and the NVD `totalResults`/`resultsPerPage` fields are set to the
  number of records kept, so the dataset-level checks stay meaningful;
- the OSV querybatch keeps only the fixture watchlist packages (tests/fixtures/watchlist.yaml).
Nothing else is modified or invented. See tests/fixtures/README.md.

Usage: python scripts/make_fixtures.py [path/to/data/lake]
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "api"

# CVEs chosen to cover the interesting cases: KEV + watchlist (Log4Shell, Spring4Shell),
# watchlist only, KEV only (ransomware / not), and plain NVD records.
KEEP_KEV = [
    "CVE-2021-44228",
    "CVE-2021-45046",
    "CVE-2022-22965",
    "CVE-2023-4966",
    "CVE-2017-0144",
    "CVE-2024-3400",
    "CVE-2019-0708",
    "CVE-2021-26855",
    "CVE-2014-0160",
    "CVE-2023-34362",
]
FIXTURE_PACKAGES = {
    ("org.apache.logging.log4j:log4j-core", "Maven"),
    ("org.springframework:spring-beans", "Maven"),
    ("Flask", "PyPI"),
    ("express", "npm"),
}
EXTRA_NVD = 25  # plain NVD CVEs from the incremental window


def read(path: Path):
    return json.loads(gzip.decompress(path.read_bytes()))


def latest_runs(lake: Path, source: str) -> list[Path]:
    runs = sorted((lake / "raw" / source).glob("ingest_date=*/run_id=*"), key=lambda p: p.name)
    if not runs:
        sys.exit(f"no raw runs for {source} under {lake}")
    return runs


def write(name: str, body) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(body, indent=1, ensure_ascii=False), encoding="utf-8")


def main(lake: Path) -> None:
    # --- CISA KEV ---------------------------------------------------------------------------
    kev = read(latest_runs(lake, "cisa_kev")[-1] / "catalog.json.gz")
    kev["vulnerabilities"] = [v for v in kev["vulnerabilities"] if v["cveID"] in KEEP_KEV]
    kev["count"] = len(kev["vulnerabilities"])
    write("cisa_kev.json", kev)

    # --- OSV --------------------------------------------------------------------------------
    osv_runs = latest_runs(lake, "osv")
    first_osv = osv_runs[0]  # the bootstrap run fetched every advisory detail
    manifest = json.loads((first_osv / "_manifest.json").read_text(encoding="utf-8"))
    batch_item = next(p for p in manifest["payloads"] if p["name"].startswith("querybatch"))
    queries = batch_item["request"]["body"]["queries"]
    results = read(first_osv / f"{batch_item['name']}.json.gz")["results"]
    kept_queries, kept_results, osv_ids = [], [], set()
    for q, r in zip(queries, results, strict=True):
        if (q["package"]["name"], q["package"]["ecosystem"]) in FIXTURE_PACKAGES:
            vulns = (r.get("vulns") or [])[:8]
            kept_queries.append(q)
            kept_results.append({"vulns": vulns})
            osv_ids.update(v["id"] for v in vulns)
    write("osv_querybatch.json", {"queries": kept_queries, "results": kept_results})
    details = {}
    for oid in sorted(osv_ids):
        path = first_osv / f"vuln_{oid}.json.gz"
        if path.exists():
            details[oid] = read(path)
    write("osv_vulns.json", details)
    alias_cves = sorted({a for d in details.values() for a in d.get("aliases", []) if a.startswith("CVE-")})

    # --- NVD --------------------------------------------------------------------------------
    wanted = set(KEEP_KEV) | set(alias_cves)
    cves, extra = {}, []
    for run in latest_runs(lake, "nvd"):
        for page in sorted(run.glob("*.json.gz")):
            for item in read(page).get("vulnerabilities", []):
                cid = item["cve"]["id"]
                if cid in wanted:
                    cves[cid] = item
                elif (
                    page.name.startswith("modified") and len(extra) < EXTRA_NVD and item["cve"].get("metrics")
                ):
                    extra.append(item)
    items = list(cves.values()) + extra
    for item in items:  # keep the fixture small: references are not used by the parser beyond counting
        item["cve"]["references"] = item["cve"].get("references", [])[:5]
        configs = item["cve"].get("configurations", [])[:2]
        for config in configs:
            for node in config.get("nodes", []):
                node["cpeMatch"] = node.get("cpeMatch", [])[:4]
        item["cve"]["configurations"] = configs
    write(
        "nvd_page.json",
        {
            "resultsPerPage": len(items),
            "startIndex": 0,
            "totalResults": len(items),
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-11-16T23:00:00.000",
            "vulnerabilities": items,
        },
    )

    # --- EPSS -------------------------------------------------------------------------------
    fixture_cves = {i["cve"]["id"] for i in items} | set(KEEP_KEV)
    rows = {}
    for run in latest_runs(lake, "epss"):
        for page in sorted(run.glob("batch_*.json.gz")):
            for row in read(page).get("data", []):
                if row["cve"] in fixture_cves and (row["cve"] not in rows or "time-series" in row):
                    rows[row["cve"]] = row
    write(
        "epss.json",
        {
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "access": "public",
            "total": len(rows),
            "offset": 0,
            "limit": 100,
            "data": list(rows.values()),
        },
    )
    print(
        f"fixtures written to {OUT}: {kev['count']} KEV, {len(items)} NVD, {len(details)} OSV, {len(rows)} EPSS"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "lake")
