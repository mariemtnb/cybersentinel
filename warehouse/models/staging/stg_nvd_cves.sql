-- Staging: NVD CVE records.
select
    cve_id,
    source_identifier,
    published,
    cast(published as date)          as published_date,
    last_modified,
    vuln_status,
    vuln_status = 'Rejected'         as is_rejected,
    description,
    cvss_version,
    cvss_base_score,
    upper(cvss_severity)             as cvss_severity,
    cvss_vector,
    cvss_source,
    cwe_ids,
    reference_count,
    has_patch_reference,
    _loaded_run_id                   as loaded_run_id
from {{ source('raw', 'nvd_cves') }}
