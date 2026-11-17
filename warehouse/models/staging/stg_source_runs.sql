{{ config(materialized='table') }}
-- Staging: per-source results of each run.
select
    run_id, source, started_at, finished_at, status,
    records_extracted, records_valid, records_rejected, records_inserted, records_updated, records_unchanged,
    requests, api_errors, schema_warnings, error, source_timestamp
from {{ source('ops', 'source_runs') }}
