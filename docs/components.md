# Component reference

For each component: responsibility, inputs, outputs, dependencies, key decisions, failure
scenarios, and how to test it.

## 1. HTTP client — `cybersentinel/http.py`

- **Responsibility**: every API call: timeout, retries, backoff, pacing, error counting.
- **Inputs**: method, URL, params/body. **Outputs**: `requests.Response` or `SourceUnavailableError`.
- **Decisions**: retry on network errors and 429/5xx (+403 for NVD, which throttles with 403);
  exponential backoff 2, 4, 8… s capped at 60 s; `Retry-After` honoured but never shorter than the
  backoff; 4xx other than these fail fast (retrying a 404 is pointless); error messages strip the
  query string so a key in a URL never reaches a log.
- **Failure**: after 5 attempts → `SourceUnavailableError` → the source is marked `failed`, the
  run continues with the other sources (status `partial`).
- **Test**: `tests/unit/test_http.py` (fake session, recorded sleeps).

## 2. Connectors — `cybersentinel/ingestion/{cisa,nvd,osv,epss}.py`

- **Responsibility**: fetch original payloads; parse them into flat tables; report schema drift and
  dataset-level problems.
- **Inputs**: API + context from the warehouse (watermark, known IDs, tracked CVEs).
- **Outputs**: `SourceBatch(payloads, tables, metadata, schema_warnings, critical_errors)`.
- **Decisions**: see module docstrings. NVD: watermark − 15 min overlap, 120-day windows, `hasKev`
  bootstrap, capped `cveId` look-ups, duplicates collapsed to the latest `lastModified`. OSV: details
  only for new/modified advisories, verdict per package re-computed by `versions.py`. EPSS: batches
  of 100, 30-day history the first time a CVE is seen. KEV: `count` must equal the number of records.
- **Failure**: unexpected structure or count mismatch → `critical_errors` → source `blocked`; new
  fields → warning only (the pipeline keeps working and the warning is visible on Pipeline Health).
- **Test**: `tests/unit/test_connectors.py`, `tests/unit/test_versions.py` on recorded responses;
  `tests/live/` against the real APIs.

## 3. Raw store — `cybersentinel/storage/raw_store.py`

- **Responsibility**: immutable storage of original payloads, validated and rejected Parquet.
- **Inputs**: payloads/DataFrames. **Outputs**: object keys; manifest with hashes.
- **Decisions**: run-partitioned keys, gzip JSON, refuse to overwrite; one interface for local disk
  and S3 (boto3; `S3_ENDPOINT_URL` selects SeaweedFS/MinIO, unset means AWS).
- **Failure**: storage unreachable → exception → the run fails before loading (nothing published).
- **Test**: `tests/unit/test_config_and_storage.py` (layout, no overwrite, replay).

## 4. Contracts and validator — `contracts/*.yaml`, `cybersentinel/validation/`

- **Responsibility**: decide which rows may enter the warehouse.
- **Inputs**: a DataFrame + its ODCS contract. **Outputs**: valid rows (typed), rejected rows with
  reasons, a report (critical/warnings).
- **Decisions**: the Pandera schema is generated from the contract (single source of truth);
  type coercion is done first so a single bad date rejects one row, not the table; PK duplicates
  keep the first row; `maxRejectRate` and `minRows` per contract decide when a whole table is
  blocked.
- **Failure**: missing column (schema change) or too many rejects → source blocked, its previous
  data stays in the warehouse, a `SOURCE_BLOCKED` alert is raised.
- **Test**: `tests/unit/test_validation.py`; CI `datacontract lint` + `datacontract test`.

## 5. Warehouse loader — `cybersentinel/loading/warehouse.py`

- **Responsibility**: idempotent writes into `raw.*`.
- **Decisions**: explicit DDL with primary keys; UPSERT with content hash (unchanged rows are not
  touched); NVD guard (older `lastModified` never overwrites newer); child tables replaced per parent
  only when the parent's rows changed; one transaction per table; table/column names checked
  against an allow-list (values are never formatted into SQL).
- **Test**: `tests/unit/test_loading.py`; idempotency end-to-end in `tests/integration`.

## 6. dbt project — `warehouse/`

- **Responsibility**: staging → intermediate → snapshot → marts, plus tests (the AUDIT).
- **Decisions**: layer schemas named `staging/intermediate/marts/snapshots`; scoring as a dbt Python
  model that imports the tested Python engine; `--no-partial-parse` so a changed env var is never
  served from cache; dbt runs as a subprocess because dbt-duckdb keeps connections open in-process.
- **Failure**: any test failure → `run_dbt` returns not-ok → no publication, run `failed`.
- **Test**: `dbt build` (68 data tests + 2 unit tests); CI job `dbt`.

## 7. Publisher — `cybersentinel/loading/publish.py`

- **Responsibility**: make the audited warehouse visible atomically.
- **Decisions**: `CHECKPOINT`, copy to a temp file, `os.replace` (atomic rename), retry on Windows
  file locks.
- **Test**: `test_failing_dbt_build_is_never_published`.

## 8. Ops store — `cybersentinel/loading/ops.py`

- **Responsibility**: runs, per-source results, quarantine, watermarks, alerts.
- **Decisions**: separate DuckDB file so failed runs are recorded even when nothing is published;
  short-lived connections with retry on locks.

## 9. Prioritisation — `cybersentinel/prioritization/`

See [prioritization.md](prioritization.md). Tests: `tests/unit/test_scoring.py`.

## 10. Alerts — `cybersentinel/alerts/alerts.py`

- **Responsibility**: turn change events and operational problems into alerts.
- **Decisions**: deterministic alert IDs (no duplicates on re-run); baseline run excluded; "new"
  alerts only for recently published/added CVEs or watchlist hits (prevents a flood after a
  backfill); one alert per vulnerability per run (most important reason wins); more than 50 → one
  summary alert; webhook optional, failure recorded in `delivered_to`.
- **Test**: `test_new_kev_entry_is_detected_and_alerted_once`, outage and failure tests.

## 11. Orchestration — `orchestration/`

- **Responsibility**: daily schedule, start-up run, visibility of each step.
- **Decisions**: the step order is defined once in `pipeline.run_steps`; Prefect wraps each step as a
  task (`NO_CACHE`, no automatic retries — retries are inside the HTTP client where they are safe);
  a failed run raises so the flow run is red in the Prefect UI.
- **Test**: run `python -m orchestration.flows`; in Docker, the Prefect UI at :4200.

## 12. Dashboard — `dashboard/`

- **Responsibility**: answer Q1–Q6 and show data health.
- **Decisions**: reads only the published warehouse (plus the live ops DB for health); read-only
  connections; cache keyed by file modification time; all filters are bound parameters; priority
  tiers use status colours **and** text labels.
- **Test**: open each page (manual); data correctness is covered by dbt tests on the marts.
