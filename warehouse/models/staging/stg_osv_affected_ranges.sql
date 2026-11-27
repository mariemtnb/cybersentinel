-- Staging: OSV affected ranges ([introduced, fixed) or [introduced, last_affected]).
select
    osv_id,
    ecosystem,
    package_name,
    range_type,
    range_index,
    nullif(introduced, '0') as introduced,
    fixed,
    last_affected
from {{ source('raw', 'osv_affected_ranges') }}
