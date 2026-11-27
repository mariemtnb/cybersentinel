-- Completeness: every entry of the current KEV catalog reaches the published fact table.
select k.cve_id
from {{ ref('stg_cisa_kev') }} as k
left join {{ ref('fct_vulnerabilities') }} as f on f.vulnerability_id = k.cve_id
where f.vulnerability_id is null
