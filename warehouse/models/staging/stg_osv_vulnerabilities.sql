-- Staging: OSV advisories. Advisories without a CVE alias keep their own ID (e.g. GHSA-…).
select
    osv_id,
    cve_id,
    coalesce(cve_id, osv_id)          as vulnerability_id,
    aliases,
    summary,
    details,
    published,
    modified,
    withdrawn is not null             as is_withdrawn,
    upper(severity_label)             as severity_label,
    cvss_type,
    cvss_vector,
    _loaded_run_id                    as loaded_run_id
from {{ source('raw', 'osv_vulnerabilities') }}
