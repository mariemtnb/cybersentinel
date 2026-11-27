# Oral defence — likely questions and accurate answers

## The idea

**Why this subject?** Vulnerability data changes every day, comes from several APIs that disagree,
and a wrong or stale number has real consequences (patching the wrong thing). That matches the
brief exactly: automatic, reliable, reproducible, observable.

**What is new compared with "sort by CVSS"?** We combine *confirmed* exploitation (KEV), *predicted*
exploitation (EPSS), severity (CVSS) and our own exposure (watchlist) into an explained score. In our
live data, 756 CVSS-"CRITICAL" vulnerabilities are ranked Medium because nothing suggests they are
exploited or relevant to us.

**Is your score a standard?** No. It is a documented, configurable heuristic. We show every point so
anyone can disagree with a weight and change `config/scoring.yaml` without touching code.

**Why is EPSS separate from KEV?** EPSS is a prediction (probability over 30 days); KEV is observed
evidence. Mixing them would hide the difference between "likely" and "happening". They are separate
columns, separate points, and the dashboard labels EPSS as a prediction.

## Data and pipeline

**Show me that ingestion is incremental.** NVD: `ops.ingestion_state` holds the last window end; the
next run asks only `lastModStartDate = watermark − 15 min`. Second live run: 92 NVD rows instead of
11k. OSV: details are fetched only if `modified` changed (second run fetched 0). EPSS: 30-day history
only for never-seen CVEs.

**Why the 15-minute overlap?** Clocks and NVD's indexing are not perfectly aligned; overlap costs a few
duplicate rows, which the upsert absorbs, while a gap would lose data silently.

**How do you avoid duplicates?** Three levels: (1) connectors collapse duplicates within a run (same
CVE on two pages → latest `lastModified`); (2) every raw table has a primary key and loading is an
UPSERT with a content hash; (3) dbt builds one canonical row per CVE and a test
(`assert_one_canonical_row_per_cve`) fails the build otherwise. Integration test
`test_second_identical_run_is_idempotent` proves a second identical run inserts and updates 0 rows
and adds no history.

**The same CVE is in KEV, NVD, OSV (twice) and EPSS. What happens?** Each source keeps its own row in
staging (provenance). `int_vulnerability_enrichment` unions the IDs and picks each field from the most
authoritative source (description NVD > KEV > OSV, vendor KEV > NVD CPE). `source_count` says how
many sources know it. A dbt unit test checks this exact case.

**What if an API is down?** The HTTP client retries with backoff; if it still fails the source is
marked `failed`, its previous data stays, the other sources refresh, the run is `partial`, a
`SOURCE_FAILED` alert is raised, and Pipeline Health shows the source turning stale. Tested in
`test_api_outage_gives_partial_run_and_keeps_publishing`.

**What if an API returns garbage?** Structure checks (e.g. no `vulnerabilities` array, KEV `count`
mismatch) block the source. Row-level problems are quarantined with reasons. If the share of bad rows
exceeds the contract's `maxRejectRate`, the source is blocked. Tested with an EPSS response where
every score is 7.5.

**Do you silently drop invalid records?** Never. They go to `ops.quarantine` (full record + reasons)
and to `rejected/` in the lake, and appear on Pipeline Health. Example from a live run: two NVD CPE
entries with an empty product.

**How does a failed quality check stop bad data reaching the dashboard?** Write-audit-publish. The
pipeline writes to a working DuckDB file, `dbt build` audits it with 68 data tests + 2 unit tests, and
only then is the file copied atomically to the published location the dashboard reads. If dbt fails,
the dashboard keeps the previous version and `PIPELINE_FAILED` is raised. This actually happened during
development (a snapshot type error) and the published data was untouched.

**Why is the raw layer JSON and not Parquet?** The raw layer must be the *original* response, byte for
byte equivalent, to replay or audit. Parquet is used for the validated and rejected tables, where the
schema is known.

**How do you detect a schema change?** Each connector knows its expected fields: a new field is a
warning (stored per run, visible on Pipeline Health), a missing required field fails the contract.
A missing contract column blocks the source.

**Why does OSV re-check versions?** Because "OSV returned it" is not proof. We compare the exact
version with each advisory's ranges using PEP 440 (PyPI), SemVer (npm) and dotted numeric (Maven).
If the range format cannot be compared (e.g. GIT commit ranges) the verdict is `unverified`, never
`affected`. Unit tests include the classic trap "4.2.10" > "4.2.9".

**NVD without an API key?** Supported: 6 s between requests (5 per 30 s rolling window per NVD's
documentation), 403/429 retried with backoff. A key only changes the pacing to 0.6 s.

**Why not download the whole NVD?** ~300k CVEs at 2,000 per page with 6 s pacing is ~15 minutes of
requests and gigabytes of JSON for data we mostly do not need. We bootstrap the KEV CVEs and recent
changes, then follow changes. The backfill window is configurable.

**EPSS daily CSV vs API?** We looked at the official daily CSV (~400k CVEs). For ~11k tracked CVEs the
batched API (100 per call) is smaller, and its `time-series` scope gives 30 days of history on the
first run. If we tracked the whole CVE universe, the CSV would be the better choice.

## Warehouse and dbt

**Why DuckDB and not PostgreSQL?** Taught in TP3, embedded (no server), columnar, fast for our
volume (~200k EPSS rows, ~12k vulnerabilities), and the whole warehouse is one file we can publish
atomically. Limit: one writer at a time — fine for one daily batch.

**What are your layers?** staging (views: rename/cast), intermediate (canonical entity, signals,
Python scoring, history), snapshots (SCD2), marts (star schema: facts + dimensions).

**Why a dbt snapshot?** To answer "what changed since last time" without writing our own diff code:
a new version row appears only when a tracked field changes, so re-runs add nothing and history is
preserved. EPSS is excluded from the snapshot (it moves daily); its history is the EPSS table itself.

**Why is scoring a dbt Python model?** So the rule exists once: the same function is unit-tested by
pytest and executed by dbt. A SQL copy would be two implementations that can drift.

**Why run dbt in a subprocess?** dbt-duckdb keeps its database connection open for the lifetime of
the process, which would keep the warehouse file locked for the publish step.

**What do the dbt tests check?** Keys (unique/not null), relationships between facts and dimensions,
accepted values (tiers, event types, statuses), business rules (KEV ≥ High, KEV + watchlist =
Critical, score = sum of points, EPSS in [0, 1], every KEV entry published, one row per CVE).

## DataOps

**How is it scheduled?** Prefect: `orchestration/serve.py` runs once at start-up then serves a
deployment with cron `0 6 * * *` (UTC). Each step is a Prefect task, visible in the UI at :4200.

**Why Prefect and not Airflow?** Both are allowed. Prefect needs one server container and plain
Python; Airflow needs scheduler + webserver + metadata DB + DAG files for one daily DAG.

**What runs in CI?** Lint/format, unit tests, integration tests (whole pipeline on recorded responses,
including dbt build), `datacontract lint` + `test` on every contract, `dbt parse` + build on fixtures,
Docker image build. All offline, so an API outage never makes CI red; live checks are a separate
weekly workflow.

**Are the fixtures fake data?** No. They are trimmed copies of real responses captured by a live run
(`scripts/make_fixtures.py`); the only edits are the KEV `count` and NVD `totalResults` adjusted to
the trimmed size, documented in `tests/fixtures/README.md`. Replay data goes to `data-replay/` and the
dashboard labels it.

**Where are secrets?** In `.env` (git-ignored) locally, GitHub Secrets in CI; the logger masks the NVD
key and webhook URL; error messages strip query strings. `.env.example` has names only.

**Why SeaweedFS instead of MinIO?** MinIO no longer publishes community Docker images (the Docker Hub
repository no longer exists). SeaweedFS speaks the same S3 API; our code uses boto3 and only the
endpoint address changes — removing it targets AWS S3.

**How would you deploy to AWS?** `docs/deployment_aws.md`: budget alert first, S3 bucket, one EC2
instance running the same Compose file, image from GHCR, deploy through a manual GitHub workflow with
OIDC (no stored AWS keys). Not executed yet — it creates paid resources.

## Limits (be honest)

- Scoring weights are not statistically calibrated.
- The watchlist is a demonstration inventory; real use would import an SBOM.
- DuckDB is single-writer; scaling to many writers would need a server database or a lakehouse table format.
- The dashboard has no authentication; it is bound to localhost and must not be exposed publicly as is.
- Old raw snapshots are kept forever (no retention policy yet).
