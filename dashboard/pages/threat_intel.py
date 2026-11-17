"""Threat Intelligence — what changed: KEV additions, EPSS movement, changes, alerts, priority over time."""

import plotly.graph_objects as go
import streamlit as st

from dashboard import data, ui

st.title("Threat Intelligence")
if not data.published_available():
    ui.no_data_notice()
    st.stop()

st.subheader("Recent CISA KEV additions")
st.caption("Confirmed exploitation in the wild, by date CISA added the CVE to the catalog (last 90 days).")
kev = data.query("""
    SELECT kev_date_added AS "Added", vulnerability_id AS "CVE", vendor AS "Vendor", product AS "Product",
           priority_tier AS "Priority", kev_ransomware AS "Ransomware", kev_due_date AS "CISA due date",
           watchlist_affected_count > 0 AS "Affects watchlist"
    FROM marts.fct_vulnerabilities
    WHERE is_kev AND kev_date_added >= current_date - INTERVAL 90 DAY
    ORDER BY kev_date_added DESC, vulnerability_id""")
weekly = data.query("""
    SELECT date_trunc('week', kev_date_added) AS week, count(*) n FROM marts.fct_vulnerabilities
    WHERE is_kev AND kev_date_added >= current_date - INTERVAL 365 DAY GROUP BY 1 ORDER BY 1""")
a, b = st.columns([2, 3])
with a:
    fig = go.Figure(
        go.Bar(
            x=weekly["week"],
            y=weekly["n"],
            marker={"color": "#d95926", "cornerradius": 3},
            hovertemplate="Week of %{x|%Y-%m-%d}: %{y} additions<extra></extra>",
        )
    )
    fig.update_layout(
        title={"text": "KEV additions per week (12 months)", "font": {"size": 13, "color": ui.MUTED}}
    )
    st.plotly_chart(ui.style_fig(fig, 300, legend=False), use_container_width=True)
with b:
    st.dataframe(
        kev,
        hide_index=True,
        use_container_width=True,
        height=300,
        column_config={
            "Added": st.column_config.DateColumn(format="YYYY-MM-DD"),
            "CISA due date": st.column_config.DateColumn(format="YYYY-MM-DD"),
        },
    )

st.subheader("EPSS trends")
st.caption(
    "EPSS is a daily prediction (probability of exploitation in the next 30 days), not proof of exploitation."
)
movers = data.query("""
    WITH ranked AS (
        SELECT vulnerability_id, score_date, epss_score,
               first_value(epss_score) OVER (PARTITION BY vulnerability_id ORDER BY score_date) AS first_score,
               last_value(epss_score) OVER (PARTITION BY vulnerability_id ORDER BY score_date
                   ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS last_score
        FROM marts.fct_epss_history WHERE score_date >= current_date - INTERVAL 30 DAY)
    SELECT DISTINCT vulnerability_id, first_score, last_score, last_score - first_score AS change
    FROM ranked ORDER BY abs(change) DESC, vulnerability_id LIMIT 15""")
watch_ids = data.query("""SELECT vulnerability_id FROM marts.fct_vulnerabilities
                          WHERE watchlist_affected_count > 0 ORDER BY priority_score DESC LIMIT 4""")
default = watch_ids["vulnerability_id"].tolist()[:3] or movers["vulnerability_id"].tolist()[:3]
options = sorted(set(movers["vulnerability_id"]) | set(watch_ids["vulnerability_id"]))
chosen = st.multiselect("CVEs to plot (up to 4)", options, default=default, max_selections=4)
c1, c2 = st.columns([3, 2])
with c1:
    if chosen:
        hist = data.query(
            f"""SELECT vulnerability_id, score_date, epss_score FROM marts.fct_epss_history
                              WHERE vulnerability_id IN ({", ".join("?" * len(chosen))})
                              ORDER BY score_date""",
            chosen,
        )
        fig = go.Figure()
        for i, cve in enumerate(chosen):  # colour follows the CVE's position in the selection
            h = hist[hist["vulnerability_id"] == cve]
            fig.add_scatter(
                x=h["score_date"],
                y=h["epss_score"],
                mode="lines",
                name=cve,
                line={"color": ui.SERIES[i], "width": 2},
                hovertemplate=cve + " %{x|%Y-%m-%d}: %{y:.2%}<extra></extra>",
            )
        fig.update_yaxes(tickformat=".0%", rangemode="tozero")
        st.plotly_chart(ui.style_fig(fig, 320), use_container_width=True)
with c2:
    st.caption("Largest EPSS moves over the last 30 days")
    st.dataframe(
        movers.rename(
            columns={
                "vulnerability_id": "CVE",
                "first_score": "30 days ago",
                "last_score": "Latest",
                "change": "Change",
            }
        ),
        hide_index=True,
        use_container_width=True,
        height=320,
        column_config={
            c: st.column_config.NumberColumn(c, format="percent") for c in ("30 days ago", "Latest", "Change")
        },
    )

st.subheader("Important changes since previous runs")
st.caption(
    "Detected by comparing each run with the previous state (dbt snapshot). The first full load is the "
    "baseline and is excluded."
)
changes = data.query("""
    SELECT detected_at AS "Detected", event_type AS "Event", vulnerability_id AS "Vulnerability",
           old_value AS "From", new_value AS "To", current_priority_tier AS "Priority now", title AS "Title"
    FROM marts.fct_vulnerability_changes
    WHERE NOT is_baseline
      AND (event_type <> 'NEW_VULNERABILITY' OR current_priority_tier IN ('Critical', 'High'))
    ORDER BY detected_at DESC LIMIT 300""")
if changes.empty:
    st.info(
        "No change detected after the baseline run yet. Changes appear from the second daily run onwards."
    )
else:
    st.dataframe(changes, hide_index=True, use_container_width=True, height=320)

st.subheader("Priority distribution over time")
ph = data.query(
    "SELECT observed_at, priority_tier, vulnerabilities FROM marts.fct_priority_history ORDER BY 1"
)
fig = go.Figure()
for tier in ui.TIERS:
    part = ph[ph["priority_tier"] == tier]
    fig.add_bar(
        x=part["observed_at"],
        y=part["vulnerabilities"],
        name=tier,
        marker={"color": ui.TIER_COLORS[tier], "line": {"color": ui.SURFACE, "width": 2}},
        hovertemplate="%{x|%Y-%m-%d %H:%M}: %{y:,} " + tier + "<extra></extra>",
    )
fig.update_layout(barmode="stack")
st.plotly_chart(ui.style_fig(fig, 300), use_container_width=True)
st.caption("One bar per pipeline run that changed at least one vulnerability's state.")

st.subheader("Alerts")
if data.ops_available():
    alerts = data.ops_query("""SELECT created_at AS "Created", severity AS "Severity", alert_type AS "Type",
                                      title AS "Alert", delivered_to AS "Delivered to"
                               FROM ops.alerts ORDER BY created_at DESC LIMIT 200""")
    if alerts.empty:
        st.info("No alert raised yet.")
    else:
        st.dataframe(alerts, hide_index=True, use_container_width=True, height=300)
