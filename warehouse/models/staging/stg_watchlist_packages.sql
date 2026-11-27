-- Staging: the configured watchlist (demonstration inventory).
select
    md5(ecosystem || ':' || package_name || '@' || package_version) as package_key,
    package_name,
    ecosystem,
    package_version,
    owner,
    advisories_returned,
    checked_at
from {{ source('raw', 'watchlist_packages') }}
