-- Intermediate: which watched packages each vulnerability affects.
-- Grain: one row per (package, vulnerability). Two advisories for the same CVE (GHSA + PYSEC)
-- are merged; "affected" wins over "unverified", which wins over "not_affected".
with matches as (
    select
        m.package_key,
        o.vulnerability_id,
        m.osv_id,
        m.match_status,
        m.fixed_version,
        m.checked_at
    from {{ ref('stg_watchlist_matches') }} as m
    inner join {{ ref('stg_osv_vulnerabilities') }} as o on o.osv_id = m.osv_id
    where not o.is_withdrawn
)

select
    package_key,
    vulnerability_id,
    string_agg(osv_id, ';' order by osv_id)                                  as osv_ids,
    case
        when bool_or(match_status = 'affected') then 'affected'
        when bool_or(match_status = 'unverified') then 'unverified'
        else 'not_affected'
    end                                                                      as match_status,
    arg_min(fixed_version, osv_id) filter (where fixed_version is not null) as fixed_version,
    max(checked_at)                                                          as checked_at
from matches
group by package_key, vulnerability_id
