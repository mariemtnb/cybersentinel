{{ config(materialized='table') }}
-- Staging: pipeline runs (copied as a table because the ops database is only attached during dbt runs).
select run_id, trigger, started_at, finished_at, status, published, is_baseline, duration_seconds, error
from {{ source('ops', 'pipeline_runs') }}
