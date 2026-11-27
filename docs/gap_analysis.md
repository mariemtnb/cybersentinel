# Audit and gap analysis — course material vs CyberSentinel

## 1. Material inspected

| Material | Status | What it contains |
|---|---|---|
| `Projet DataOps.pdf` (project brief, 4 pages, French) | Read in full | Mission, expected "vitrine", minimum requirements, AWS rules, team rules |
| `lab_solution-…zip` (TP solution, folder `lab_solution/`) | Extracted and read in full | One e-commerce project that accumulates TP1–TP4 |
| Python, Git, Docker | Checked | Python 3.12 / 3.13 installed (3.12 chosen, see §4), Git 2.55, Docker 29.8 |
| Existing project workspace | Empty apart from the two files above | Nothing to preserve or migrate; not yet a Git repository |

The zip is a single, cumulative solution (not four separate TP folders). Mapping its files to the TPs:

| TP | Topic (per brief) | Files in the solution |
|---|---|---|
| TP1 | Quality rules + pytest | `pipeline/{extract,transform,validate,load}.py`, `run_pipeline.py`, `tests/test_pipeline.py`, `naive_report.py` |
| TP2 | Git + DVC | `.dvcignore`, `data/raw.dvc`, `.gitignore` |
| TP3 | DuckDB + dbt | `load_raw.py`, `dbt_project.yml`, `profiles.yml`, `models/{staging,intermediate,marts}`, `data_tests/`, unit tests in `int_orders_checked.yml` |
| TP4 | Contracts + CI | `contracts/orders.yaml` (ODCS v3), `pipeline/schema.py` (Pandera), `report_md.py` (regression check). No CI workflow file is in the archive — the GitHub Actions part is implemented from the brief. |

Not in the archive: Prefect/Airflow, Docker, MinIO/S3, alerts, dlt. These are built from the brief.

## 2. What is reused (adapted, not copied)

| TP technique | Where it lives in CyberSentinel | How it was adapted |
|---|---|---|
| Separate extract / validate / transform / load modules (TP1) | `cybersentinel/ingestion`, `validation`, `loading`, `transform.py` | One connector per API instead of one CSV reader; fetch and parse are separate |
| "Reject, don't drop" quality rules with a reason column (TP1, `reject_reason`) | `validation/validate.py` → `_reject_reasons`, `ops.quarantine` | Reasons are stored with the full record and shown on the dashboard |
| Reject-rate threshold that stops the pipeline (TP1 `check_reject_rate`) | contract `maxRejectRate` → source *blocked* | Threshold per table, defined in the contract, not in code |
| "PIPELINE STOPPED — nothing was published" (TP1) | write-audit-publish (`loading/publish.py`) | Generalised: nothing is published unless dbt build + tests pass |
| Pandera schema checked before loading (TP3 `load_raw.py`) | `validation/validate.py` | The Pandera schema is **generated from the contract**, so the rules exist once |
| ODCS data contract (TP4 `contracts/orders.yaml`) | `contracts/*.yaml` (8 contracts) | Same format and version family; CI uses `datacontract test` as in TP4 |
| DuckDB raw schema + technical columns `_loaded_at`, `_row_number` (TP3) | `loading/warehouse.py` (`_row_hash`, `_loaded_run_id`, `_loaded_at`) | Append-only CSV replace → idempotent upsert with content hash |
| dbt layers staging (view) → intermediate → marts (table) (TP3) | `warehouse/models/` | Same layering and materialisations, plus a snapshot layer |
| dbt `unit_tests` with `given/expect` (TP3) | `warehouse/models/intermediate/_intermediate.yml` | Tests the deduplication rules |
| Singular data tests in SQL (TP3 `data_tests/`) | `warehouse/tests/*.sql` | Business rules (KEV ≥ High, one row per CVE, EPSS in [0,1]) |
| `accepted_values` with `arguments:` syntax (TP3, dbt ≥ 1.10) | marts/staging YAML | Same syntax |
| pytest with small builder helpers (TP1 `make_orders`) | `tests/unit/*` | Plus recorded real responses as fixtures |
| ruff in requirements (TP) | CI `quality` job | Lint and format enforced |
| Regression check that fails the run (TP4 `report_md.py`) | dbt tests + CI integration tests | Failure → non-zero exit → red CI |

## 3. Gaps the project had to fill

| Requirement (brief or project prompt) | In TPs? | Implemented in |
|---|---|---|
| At least one API source, ≥ 2 sources | CSV only | 4 API connectors |
| Incremental ingestion without duplicates | No | NVD watermark, OSV `modified` check, upserts + hashes |
| Daily scheduled execution (Airflow/Prefect) | No | Prefect flow + `serve()` with cron |
| Whole platform with `docker compose up` | No | `Dockerfile`, `docker-compose.yml` (4 services) |
| Platform health monitoring + an alert | No | ops DB, Pipeline Health page, `alerts/` |
| GitHub Actions CI that blocks a red PR | Not in archive | `.github/workflows/ci.yml` |
| No secret in the repository | Partially (`.user.yml` was committed in the TP) | `.env.example`, `.gitignore`, log masking |
| S3-compatible storage, deploy via CI to AWS | No | `storage/raw_store.py` (S3 backend), `deploy.yml` (disabled), `docs/deployment_aws.md` |
| Something beyond the course | — | Explainable prioritisation, change detection, write-audit-publish, version re-verification, replay mode |

## 4. Environment findings

- **Python 3.13 on Windows** crashed (access violation) when dbt-duckdb created an asyncio event
  loop for the dbt Python model, after native libraries were loaded. Python 3.12 does not have the
  problem and is what the Docker image and CI use, so the project standardises on 3.12.
- **MinIO**: the brief suggests MinIO. Its community Docker images are no longer published
  (`docker pull minio/minio` → "repository does not exist"; the quay.io mirror requires
  authentication). SeaweedFS, another S3-compatible server, is used instead; the pipeline only
  speaks the S3 API through boto3, so nothing in the code depends on the server brand.
- **DVC (TP2)** is not used: raw data is versioned by immutable, run-partitioned snapshots in the
  object store, which plays the same role for API data that changes daily.
