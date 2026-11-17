# CyberSentinel — project proposal

## 1. Problem statement

Every day dozens of new software vulnerabilities (CVEs) are published, and thousands of existing
ones are re-scored or updated. The information a security team needs is spread across sources that
each answer a different question:

- **NVD** describes the vulnerability and its technical severity (CVSS),
- **CISA KEV** says whether it is *confirmed* to be exploited in the wild,
- **FIRST EPSS** *predicts* how likely exploitation is in the next 30 days,
- **OSV** says which open-source package versions are affected and which version fixes it.

Combining them by hand is slow and error-prone: the same CVE appears under several identifiers,
severities disagree, and nobody can tell when a number on a slide was last refreshed or where it
came from. Teams therefore fall back to "sort by CVSS", which ranks thousands of critical-looking
flaws that nobody exploits above medium-severity flaws that attackers actively use.

## 2. Solution

CyberSentinel is an automated data platform that, every day and without manual action:

1. collects the four sources through their official APIs;
2. keeps every original response (auditability);
3. validates the data against explicit contracts and quarantines bad records;
4. merges everything into one deduplicated vulnerability entity per CVE in a DuckDB warehouse;
5. matches vulnerabilities against a configurable software inventory (watchlist);
6. ranks every vulnerability with a transparent, configurable scoring engine that explains itself;
7. detects what is new or changed since the previous run and raises alerts;
8. publishes only audited data to a dashboard, with a page showing the health of every source.

## 3. Target users and objectives

| User | Need | Objective served |
|---|---|---|
| Security / vulnerability-management analyst | A short, defensible list of what to fix first | Q1, Q2, Q4 |
| Development team owning a service | Which of *my* dependencies are affected and which version fixes it | Q1 |
| Security manager | Trends, exposure by vendor/ecosystem, and whether the data is trustworthy | Q3, Q5, Q6, data health |
| Data/platform engineer | Pipeline failures and stale sources detected before users notice | Pipeline Health, alerts |

## 4. Business questions (measurable)

| # | Question | Measured by |
|---|---|---|
| Q1 | Which vulnerabilities affect the packages in our watchlist? | Count and list of (package, vulnerability) pairs with a verified version match, with fixed versions |
| Q2 | Which vulnerabilities have the highest remediation priority? | Priority score 0–100 and tier per vulnerability, with per-signal points |
| Q3 | Which vulnerabilities are new or changed since the previous ingestion? | Change events per run: new, KEV added, CVSS changed, priority changed, exposure changed, EPSS moves ≥ 0.10 |
| Q4 | Which vulnerabilities are confirmed as actively exploited? | KEV membership, KEV additions per week, ransomware flag |
| Q5 | How have EPSS scores changed over time? | Daily EPSS history per CVE, largest 30-day moves |
| Q6 | Which software ecosystems and vendors have the highest exposure? | Critical + High count per vendor; affected vulnerabilities per watched ecosystem |

## 5. Data sources

| Source | Endpoint | Auth | Volume handled | Refresh strategy |
|---|---|---|---|---|
| CISA KEV | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | ~1,800 entries, ~2 MB | Full catalog each run; changes detected in the warehouse; `count` field checked |
| NIST NVD CVE API 2.0 | `GET https://services.nvd.nist.gov/rest/json/cves/2.0` | Optional `apiKey` header (`NVD_API_KEY`) | ~11.6k CVEs after the first run | First run: 7 days of changes + all KEV CVEs (`hasKev`); then incremental on `lastModStartDate/EndDate` (≤ 120-day windows), 2,000 per page; 6 s between requests without key, 0.6 s with key |
| OSV | `POST https://api.osv.dev/v1/querybatch`, `GET /v1/vulns/{id}` | None | ~180 advisories for 10 demo packages | Query every run; download details only for new/modified advisories; follow `next_page_token` |
| FIRST EPSS | `GET https://api.first.org/data/v1/epss` | None | ~11k CVEs/day; 30-day history on first sight | Batches of 100 CVEs; `scope=time-series` for new CVEs; one row per CVE per day kept forever |

## 6. Architecture (summary)

See [architecture.md](architecture.md) and the diagram. Flow: API → raw object store → contract
validation → DuckDB raw schema (idempotent) → dbt staging / intermediate / snapshot / marts with
tests → atomic publication → dashboard and alerts. Prefect schedules it daily; GitHub Actions
checks every pull request.

## 7. Technology choices

| Need | Choice | Why (and why not the alternative) |
|---|---|---|
| Extraction | Python + `requests`, own small HTTP client | Four very different APIs (paged GET, POST batch, feed, CSV-like). A 100-line client with explicit retry/backoff/pacing is easier to explain and test than a framework; dlt was considered but its benefit (schema inference, loading) overlaps with our contracts and loader |
| Raw storage | S3 API (SeaweedFS locally, AWS S3 in the cloud), gzip JSON + Parquet | Immutable, cheap, replayable; same code locally and on AWS |
| Validation | ODCS contracts + Pandera (TP4/TP3) | Taught in the course; the contract is the single source of truth, also checked by `datacontract test` in CI |
| Warehouse | DuckDB | Taught in TP3; columnar, embedded, no server; enough for ~10⁵–10⁶ rows/day |
| Transformations | dbt-duckdb | Taught in TP3; versioned SQL, tests, snapshots, lineage |
| Orchestration | Prefect 3 | Plain Python flows, one extra container, a UI with run history; Airflow needs a scheduler, webserver, metadata DB and DAG files — more infrastructure for a single daily DAG |
| Dashboard | Streamlit + Plotly | Python-only, reads DuckDB directly, quick to build real filters and drill-downs |
| Packaging | Docker Compose | `docker compose up` requirement |
| CI | GitHub Actions | Required by the brief; offline fixtures make it deterministic |

## 8. What we add beyond the TPs

1. **Explainable prioritisation engine** — configurable points per signal (CVSS, KEV, EPSS,
   watchlist, fix availability), tiers and floors; every vulnerability carries a sentence explaining
   its score. Implemented once in Python, unit-tested, and run inside dbt as a Python model.
2. **Change detection** — a dbt snapshot (SCD type 2) of each vulnerability's risk state produces
   change events (new, KEV added, CVSS changed, priority escalated, exposure changed); EPSS moves
   come from the daily history.
3. **Write-audit-publish** — users only ever see a warehouse that passed every dbt test.
4. **Version re-verification** — OSV results are re-checked against the advisory's version ranges
   (PEP 440, SemVer, Maven) instead of being trusted blindly.
5. **Data-health page and deduplicated alerts** — live freshness per source, quarantine, errors;
   alerts with deterministic IDs so a re-run never re-alerts.
6. **Offline replay** — recorded real responses make CI deterministic and allow a demo without
   network.

## 9. First milestone — status

| Deliverable | Status |
|---|---|
| Proposal, problem, users, objectives, sources, endpoints, questions | This document |
| Architecture diagram | `docs/architecture.svg` |
| Technology choices with justification | §7 |
| Beyond the TPs | §8 |
| Clean repository | Ready for the team's first commit (no Git history created by the assistant) |
| Working extraction from real sources | Done, all four sources, verified live |
| Raw storage | Done (local disk and S3-compatible store) |
| Validation and contracts | Done, 8 contracts |
| DuckDB initialised | Done |
| dbt transformations | Done: 26 models, 1 snapshot, 68 data tests + 2 unit tests |
| Automated tests | 66 offline + 4 live |
| Docker Compose | Done (see architecture.md §8 for the verification) |
| README | Done |

## 10. Risks and limits

- NVD without an API key is slow (6 s per request). Mitigation: small backfill, incremental runs,
  capped look-ups; a free key gives 10× throughput.
- The scoring weights are our judgement, not a standard. Mitigation: they are configurable,
  documented, and every point is shown.
- OSV coverage depends on advisory databases; packages outside OSV's ecosystems are not supported.
- DuckDB is single-writer; fine for one daily batch, not for many concurrent writers.
