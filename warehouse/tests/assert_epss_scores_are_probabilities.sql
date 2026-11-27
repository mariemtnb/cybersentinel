-- EPSS is a probability: score and percentile must stay in [0, 1].
select vulnerability_id, epss_score, epss_percentile
from {{ ref('fct_vulnerabilities') }}
where epss_score not between 0 and 1
   or epss_percentile not between 0 and 1
