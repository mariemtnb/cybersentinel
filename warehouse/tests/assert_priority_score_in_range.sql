-- The priority score is defined on 0-100, and equals the sum of its parts (capped at 100).
select vulnerability_id, priority_score
from {{ ref('fct_vulnerabilities') }}
where priority_score not between 0 and 100
   or abs(least(points_cvss + points_kev + points_epss + points_watchlist + points_fix, 100) - priority_score) > 0.11
