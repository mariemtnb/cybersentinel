-- Mart: calendar dimension covering every date used by the facts (publication, KEV addition, EPSS).
with bounds as (
    select
        least(
            coalesce((select min(published_date) from {{ ref('int_vulnerability_enrichment') }}), current_date),
            coalesce((select min(score_date) from {{ ref('stg_epss_scores') }}), current_date)
        ) as first_day,
        current_date as last_day
)

select
    cast(d as date)                  as date_day,
    year(d)                          as year,
    quarter(d)                       as quarter,
    month(d)                         as month,
    strftime(d, '%Y-%m')             as year_month,
    week(d)                          as iso_week,
    dayofweek(d)                     as day_of_week,
    dayofweek(d) in (0, 6)           as is_weekend
from bounds, generate_series(first_day, last_day, interval 1 day) as t(d)
