-- Mart: the watched packages (configured inventory), including those with no known advisory.
select
    package_key,
    package_name,
    ecosystem,
    package_version,
    owner,
    advisories_returned,
    checked_at as last_checked_at
from {{ ref('stg_watchlist_packages') }}
