-- Deduplication: a CVE present in several sources must produce exactly one canonical vulnerability.
select cve_id, count(*) as rows_for_cve
from {{ ref('fct_vulnerabilities') }}
where cve_id is not null
group by cve_id
having count(*) > 1
