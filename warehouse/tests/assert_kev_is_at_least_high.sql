-- Business rule (config/scoring.yaml floors): a vulnerability confirmed exploited by CISA is
-- never ranked below High, and Critical when it also affects a watched package.
select vulnerability_id, priority_tier, is_kev, watchlist_affected_count
from {{ ref('fct_vulnerabilities') }}
where (is_kev and priority_tier in ('Medium', 'Low'))
   or (is_kev and watchlist_affected_count > 0 and priority_tier <> 'Critical')
