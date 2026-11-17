-- Intermediate: the five prioritization signals, one row per vulnerability.
with exposure as (
    select
        vulnerability_id,
        count(*) filter (where match_status = 'affected')   as watchlist_affected_count,
        count(*) filter (where match_status = 'unverified') as watchlist_unverified_count,
        -- "fix available" only when EVERY affected watched package has a fixed version
        case
            when count(*) filter (where match_status = 'affected') = 0 then null
            else bool_and(fixed_version is not null) filter (where match_status = 'affected')
        end                                                 as fix_available
    from {{ ref('int_affected_packages') }}
    group by vulnerability_id
)

select
    v.vulnerability_id,
    v.cve_id,
    v.cvss_base_score,
    v.cvss_severity,
    v.osv_severity_label                      as severity_label,
    v.is_kev,
    v.kev_ransomware,
    v.epss_score,
    v.epss_percentile,
    coalesce(x.watchlist_affected_count, 0)   as watchlist_affected_count,
    coalesce(x.watchlist_unverified_count, 0) as watchlist_unverified_count,
    x.fix_available
from {{ ref('int_vulnerability_enrichment') }} as v
left join exposure as x on x.vulnerability_id = v.vulnerability_id
