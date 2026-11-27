-- Mart: one row per canonical vulnerability with every signal, the priority and its explanation.
-- Answers: highest remediation priority (Q2), confirmed exploited (Q4), new since last run (Q3).
with first_seen as (
    select vulnerability_id, min(valid_from) as first_seen_at, arg_min(run_id, valid_from) as first_seen_run_id
    from {{ ref('int_vulnerability_history') }}
    group by vulnerability_id
),

latest_run as (
    select '{{ var("run_id") }}' as run_id
)

select
    v.vulnerability_id,
    v.cve_id,
    v.title,
    v.published_date,
    v.last_modified,
    md5(lower(coalesce(v.vendor, 'unknown')))                     as vendor_key,
    v.vendor,
    v.product,
    v.cvss_version,
    v.cvss_base_score,
    v.cvss_severity,
    v.osv_severity_label,
    v.is_kev,
    v.kev_date_added,
    v.kev_due_date,
    v.kev_ransomware,
    v.kev_required_action,
    v.epss_score,
    v.epss_percentile,
    v.epss_date,
    p.watchlist_affected_count,
    p.watchlist_unverified_count,
    p.fix_available,
    p.points_cvss,
    p.points_kev,
    p.points_epss,
    p.points_watchlist,
    p.points_fix,
    p.priority_score,
    p.priority_tier,
    p.priority_rank,
    p.priority_reason,
    v.in_nvd,
    v.in_kev,
    v.in_osv,
    v.in_epss,
    (v.in_nvd::int + v.in_kev::int + v.in_osv::int + v.in_epss::int) as source_count,
    f.first_seen_at,
    f.first_seen_run_id,
    f.first_seen_run_id = (select run_id from latest_run)            as is_new_this_run
from {{ ref('int_vulnerability_enrichment') }} as v
inner join {{ ref('int_vulnerability_priority') }} as p on p.vulnerability_id = v.vulnerability_id
left join first_seen as f on f.vulnerability_id = v.vulnerability_id
