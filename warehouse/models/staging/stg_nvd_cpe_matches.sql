-- Staging: vendor/product per CVE from NVD CPE criteria. Only "vulnerable" entries count;
-- the others describe the platform a product runs on (e.g. the OS under an application).
select distinct
    cve_id,
    case part when 'a' then 'application' when 'o' then 'operating_system' when 'h' then 'hardware' end
                                          as cpe_part,
    lower(vendor)                         as vendor,
    lower(product)                        as product
from {{ source('raw', 'nvd_cpe_matches') }}
where vulnerable
  and vendor not in ('*', '-', '')
