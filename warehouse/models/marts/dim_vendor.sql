-- Mart: vendors seen in KEV or in NVD CPE data (one row per vendor, case-insensitive).
select
    md5(lower(vendor_name))   as vendor_key,
    any_value(vendor_name)    as vendor_name
from (
    select vendor from {{ ref('int_vulnerability_enrichment') }}
    union all
    select 'unknown'
) as v(vendor_name)
where vendor_name is not null
group by lower(vendor_name)
