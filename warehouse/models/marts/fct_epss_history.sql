-- Mart: daily EPSS history of tracked vulnerabilities with the day-over-day change.
-- Answers Q5 "how have EPSS scores changed over time?".
select
    e.cve_id || ':' || cast(e.score_date as varchar)                                    as epss_id,
    e.cve_id                                                                            as vulnerability_id,
    e.score_date,
    e.epss_score,
    e.epss_percentile,
    e.epss_score - lag(e.epss_score) over (partition by e.cve_id order by e.score_date) as epss_change_1d
from {{ ref('stg_epss_scores') }} as e
where e.cve_id in (select vulnerability_id from {{ ref('int_vulnerability_enrichment') }})
