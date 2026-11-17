# Data dictionary

Schemas in the DuckDB warehouse (`data/warehouse/cybersentinel.duckdb`, published as
`data/published/cybersentinel.duckdb`) and in the ops database (`data/state/pipeline_state.duckdb`).
Raw-table columns are defined by the data contracts in `contracts/`; the contract is authoritative.

## raw (loaded by Python after contract validation)

Every raw table also has `_row_hash` (MD5 of the business columns, used for idempotent loading),
`_loaded_run_id` and `_loaded_at`.

| Table | Grain / key | Main columns |
|---|---|---|
| `raw.cisa_kev` | one row per CVE — `cve_id` | vendor_project, product, vulnerability_name, date_added, due_date, short_description, required_action, known_ransomware_campaign_use, notes, cwes, catalog_version, in_current_catalog |
| `raw.nvd_cves` | one row per CVE (latest version) — `cve_id` | published, last_modified, vuln_status, description (English), cvss_version, cvss_base_score (0–10), cvss_severity, cvss_vector, cvss_source, cwe_ids, reference_count, has_patch_reference |
| `raw.nvd_cpe_matches` | (cve_id, part, vendor, product) | vulnerable — vendor/product parsed from CPE 2.3 criteria |
| `raw.osv_vulnerabilities` | one row per OSV advisory — `osv_id` | cve_id (first CVE alias), aliases, summary, details, published, modified, withdrawn, severity_label, cvss_type, cvss_vector, affected_json (original `affected` array) |
| `raw.osv_affected_ranges` | one row per range segment | osv_id, ecosystem, package_name, range_type, range_index, introduced, fixed, last_affected |
| `raw.watchlist_packages` | (package_name, ecosystem, package_version) | owner, advisories_returned, checked_at |
| `raw.watchlist_matches` | (package_name, ecosystem, package_version, osv_id) | match_status (affected / not_affected / unverified), fixed_version, evidence, checked_at |
| `raw.epss_scores` | (cve_id, score_date) | epss (probability 0–1), percentile (0–1) — history is kept |

## staging (views, rename and cast only)

`stg_cisa_kev`, `stg_nvd_cves`, `stg_nvd_cpe_matches`, `stg_osv_vulnerabilities`,
`stg_osv_affected_ranges`, `stg_watchlist_packages`, `stg_watchlist_matches`, `stg_epss_scores`,
plus `stg_pipeline_runs` and `stg_source_runs` (tables copied from the ops database).

Notable derivations: `stg_cisa_kev.is_ransomware_related`, `stg_nvd_cves.is_rejected`,
`stg_osv_vulnerabilities.vulnerability_id = coalesce(cve_id, osv_id)`, `package_key = md5(ecosystem:name@version)`.

## intermediate

| Model | Grain | Purpose |
|---|---|---|
| `int_vulnerability_enrichment` | vulnerability_id | **Canonical entity**: union of CVE IDs from KEV, NVD and OSV; one row per CVE (or per OSV ID without CVE). Field precedence: title KEV > OSV > NVD; description NVD > KEV > OSV; vendor KEV > NVD CPE. Source flags in_nvd/in_kev/in_osv/in_epss |
| `int_affected_packages` | (package_key, vulnerability_id) | Merges duplicate advisories (GHSA + PYSEC) — affected > unverified > not_affected |
| `int_risk_signals` | vulnerability_id | The five scoring signals |
| `int_vulnerability_priority` (Python) | vulnerability_id | Signals + points per signal + priority_score, priority_tier, priority_rank, priority_reason |
| `int_vulnerability_state` (view) | vulnerability_id | Tracked fields + `observed_run_id`, input of the snapshot |
| `int_vulnerability_history` | version | Snapshot versions with the previous values (lag) |

## snapshots

`snapshots.snap_vulnerability_state` — SCD type 2 on `vulnerability_id`, check strategy on
cvss_base_score, cvss_severity, is_kev, watchlist_affected_count, fix_available, priority_tier.
A row is added only when one of these changes.

## marts

| Model | Grain | Key columns |
|---|---|---|
| `fct_vulnerabilities` | vulnerability_id | all signals, `points_*`, `priority_score`, `priority_tier`, `priority_rank`, `priority_reason`, source flags, `source_count`, `first_seen_at`, `first_seen_run_id`, `is_new_this_run`, `vendor_key` → dim_vendor |
| `dim_vulnerability` | vulnerability_id | title, description, dates, cvss_vector, cwe_ids, osv_ids, nvd_url, osv_url, sources |
| `dim_vendor` | vendor_key | vendor_name |
| `dim_package` | package_key | package_name, ecosystem, package_version, owner, last_checked_at |
| `dim_date` | date_day | year, quarter, month, year_month, iso_week, day_of_week, is_weekend |
| `fct_package_exposure` | exposure_id = package_key:vulnerability_id | match_status (affected/unverified), fixed_version, fix_available, priority fields |
| `fct_vulnerability_changes` | event_id | event_type (NEW_VULNERABILITY, KEV_ADDED, CVSS_CHANGED, PRIORITY_ESCALATED, PRIORITY_LOWERED, WATCHLIST_EXPOSURE_CHANGED, EPSS_INCREASE, EPSS_DECREASE), old_value, new_value, run_id, detected_at, is_baseline |
| `fct_epss_history` | epss_id = cve:date | epss_score, epss_percentile, epss_change_1d |
| `fct_priority_history` | run_id:tier | number of vulnerabilities per tier after each run |
| `fct_source_health` | source | last status, last success, records, rejected, API errors, latest error, at build time |

## ops database (`data/state/pipeline_state.duckdb`, schema `ops`)

| Table | Content |
|---|---|
| `pipeline_runs` | run_id, trigger, started/finished, status (running/success/partial/failed), published, is_baseline, duration, error, dbt summary |
| `source_runs` | per run and source: status (success/failed/blocked), extracted, valid, rejected, inserted, updated, unchanged, requests, API errors, schema warnings, error, source timestamp, raw location |
| `quarantine` | every rejected record: run, source, table, key, reasons, full record JSON |
| `ingestion_state` | incremental watermarks (NVD last-modified window end) |
| `nvd_lookup_misses` | CVE IDs NVD did not return (retried after 7 days) |
| `alerts` | alert_id (deterministic), type, severity, vulnerability, message, delivery channel |

## Raw object layout

```
raw/<source>/ingest_date=YYYY-MM-DD/run_id=<run>/<payload>.json.gz   original responses
raw/<source>/ingest_date=YYYY-MM-DD/run_id=<run>/_manifest.json      request params, byte counts, SHA-256
validated/<table>/ingest_date=…/run_id=…/data.parquet                rows that passed the contract
rejected/<table>/ingest_date=…/run_id=…/data.parquet                 rows that failed, with _reject_reasons
```
