-- Mart: watched package × vulnerability that affects it (or could not be verified).
-- Answers Q1 "which vulnerabilities affect the packages in our watchlist?".
select
    a.package_key || ':' || a.vulnerability_id   as exposure_id,
    a.package_key,
    pkg.package_name,
    pkg.ecosystem,
    pkg.package_version,
    pkg.owner,
    a.vulnerability_id,
    a.osv_ids,
    a.match_status,
    a.fixed_version,
    a.fixed_version is not null                  as fix_available,
    f.title,
    f.cvss_base_score,
    f.cvss_severity,
    f.osv_severity_label,
    f.is_kev,
    f.epss_score,
    f.priority_score,
    f.priority_tier,
    f.priority_rank,
    a.checked_at
from {{ ref('int_affected_packages') }} as a
inner join {{ ref('stg_watchlist_packages') }} as pkg on pkg.package_key = a.package_key
inner join {{ ref('fct_vulnerabilities') }} as f on f.vulnerability_id = a.vulnerability_id
where a.match_status in ('affected', 'unverified')
