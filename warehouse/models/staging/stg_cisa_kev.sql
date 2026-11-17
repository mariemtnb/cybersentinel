-- Staging: CISA KEV. Rename/cast only; keeps entries still present in the latest catalog.
select
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added,
    due_date,
    short_description,
    required_action,
    known_ransomware_campaign_use = 'Known'  as is_ransomware_related,
    notes,
    cwes,
    catalog_version,
    _loaded_run_id                           as loaded_run_id
from {{ source('raw', 'cisa_kev') }}
where in_current_catalog
