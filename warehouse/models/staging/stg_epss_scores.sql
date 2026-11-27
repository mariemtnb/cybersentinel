-- Staging: EPSS daily history. epss = probability (0–1), percentile = rank among all CVEs.
select
    cve_id,
    score_date,
    epss              as epss_score,
    percentile        as epss_percentile,
    _loaded_run_id    as loaded_run_id
from {{ source('raw', 'epss_scores') }}
