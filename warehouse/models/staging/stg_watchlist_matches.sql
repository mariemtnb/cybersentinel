-- Staging: our verdict for each (watched package, advisory) pair.
select
    md5(m.ecosystem || ':' || m.package_name || '@' || m.package_version) as package_key,
    m.package_name,
    m.ecosystem,
    m.package_version,
    m.osv_id,
    m.match_status,
    m.fixed_version,
    m.evidence,
    m.checked_at
from {{ source('raw', 'watchlist_matches') }} as m
