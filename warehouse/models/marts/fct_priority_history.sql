-- Mart: how many vulnerabilities were in each priority tier after each pipeline run,
-- reconstructed from the snapshot validity intervals.
with runs as (
    select run_id, max(valid_from) as observed_at
    from {{ ref('int_vulnerability_history') }}
    group by run_id
)

select
    r.run_id || ':' || h.priority_tier  as priority_history_id,
    r.run_id,
    r.observed_at,
    h.priority_tier,
    count(*)                            as vulnerabilities
from runs as r
inner join {{ ref('int_vulnerability_history') }} as h
    on h.valid_from <= r.observed_at
   and (h.valid_to is null or h.valid_to > r.observed_at)
group by r.run_id, r.observed_at, h.priority_tier
