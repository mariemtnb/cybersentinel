-- Mart: health of each source as of this build — last attempt, last success, volumes,
-- rejections and the latest error. (The dashboard also reads the live ops database so a
-- failed run that was never published is still visible.)
with ranked as (
    select
        *,
        row_number() over (partition by source order by started_at desc) as attempt_rank
    from {{ ref('stg_source_runs') }}
),

last_success as (
    select source, max(finished_at) as last_success_at, arg_max(run_id, finished_at) as last_success_run_id,
           arg_max(source_timestamp, finished_at) as last_source_timestamp
    from {{ ref('stg_source_runs') }}
    where status = 'success'
    group by source
),

totals as (
    select
        source,
        count(*)                                    as attempts,
        count(*) filter (where status = 'success')  as successes,
        sum(coalesce(records_rejected, 0))          as total_rejected,
        sum(coalesce(api_errors, 0))                as total_api_errors
    from {{ ref('stg_source_runs') }}
    group by source
)

select
    r.source,
    r.status                                                       as last_status,
    r.started_at                                                   as last_attempt_at,
    r.error                                                        as last_error,
    r.schema_warnings                                              as last_schema_warnings,
    r.records_extracted                                            as last_records_extracted,
    r.records_rejected                                             as last_records_rejected,
    r.records_inserted                                             as last_records_inserted,
    r.records_updated                                              as last_records_updated,
    s.last_success_at,
    s.last_success_run_id,
    s.last_source_timestamp,
    date_diff('minute', s.last_success_at, current_timestamp) / 60.0 as hours_since_success_at_build,
    t.attempts,
    t.successes,
    t.total_rejected,
    t.total_api_errors
from ranked as r
left join last_success as s on s.source = r.source
left join totals as t on t.source = r.source
where r.attempt_rank = 1
