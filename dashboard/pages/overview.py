"""Overview — the headline numbers and where the risk concentrates."""

import plotly.graph_objects as go
import streamlit as st

from dashboard import data, ui

st.title("Overview")
if not data.published_available():
    ui.no_data_notice()
    st.stop()

k = data.query("""
    SELECT count(*)                                              AS total,
           count(*) FILTER (WHERE priority_tier = 'Critical')     AS critical,
           count(*) FILTER (WHERE priority_tier = 'High')         AS high,
           count(*) FILTER (WHERE is_kev)                         AS kev,
           count(*) FILTER (WHERE watchlist_affected_count > 0)   AS watch,
           count(*) FILTER (WHERE is_new_this_run)                AS new_run
    FROM marts.fct_vulnerabilities""").iloc[0]
run = data.last_published_run()

# Two rows of three tiles: readable from laptop to wide screens.
row1, row2 = st.columns(3), st.columns(3)
with row1[0]:
    ui.kpi("Tracked vulnerabilities", f"{k.total:,}", "canonical, deduplicated")
with row1[1]:
    ui.kpi("Critical priority", f"{k.critical:,}", "act now", ui.TIER_COLORS["Critical"])
with row1[2]:
    ui.kpi("High priority", f"{k.high:,}", "plan this cycle", ui.TIER_COLORS["High"])
with row2[0]:
    ui.kpi("Confirmed exploited", f"{k.kev:,}", "in CISA KEV")
with row2[1]:
    ui.kpi("Affect watched packages", f"{k.watch:,}", "verified version match")
with row2[2]:
    if run is not None and run["is_baseline"]:
        note = "first full load (baseline)"
    else:
        note = ui.age(run["finished_at"]) if run is not None else ""
    ui.kpi("New in latest run", f"{k.new_run:,}", note)

st.write("")
left, right = st.columns([3, 2])

with left:
    st.subheader("Watchlist exposure first")
    st.caption("Vulnerabilities that affect a watched package, highest priority first.")
    top = data.query("""
        SELECT vulnerability_id AS "Vulnerability", priority_tier AS "Priority", priority_score AS "Score",
               cvss_base_score AS "CVSS", epss_score AS "EPSS", is_kev AS "KEV",
               watchlist_affected_count AS "Packages", title AS "Title"
        FROM marts.fct_vulnerabilities WHERE watchlist_affected_count > 0
        ORDER BY priority_score DESC, vulnerability_id LIMIT 12""")
    st.dataframe(
        top,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.0f"),
            "EPSS": st.column_config.NumberColumn("EPSS", format="percent"),
            "KEV": st.column_config.CheckboxColumn("KEV"),
        },
    )

with right:
    st.subheader("Priority distribution")
    dist = data.query("SELECT priority_tier, count(*) n FROM marts.fct_vulnerabilities GROUP BY 1")
    dist = dist.set_index("priority_tier").reindex(ui.TIERS).fillna(0).reset_index()
    fig = go.Figure(
        go.Bar(
            x=dist["n"],
            y=dist["priority_tier"],
            orientation="h",
            marker={"color": [ui.TIER_COLORS[t] for t in dist["priority_tier"]], "cornerradius": 4},
            text=[f"{int(n):,}" for n in dist["n"]],
            textposition="outside",
            textfont={"color": ui.TEXT},
            hovertemplate="%{y}: %{x:,} vulnerabilities<extra></extra>",
        )
    )
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(ui.style_fig(fig, 240, legend=False), use_container_width=True)

    st.subheader("Source coverage")
    cov = data.query("""
        SELECT 'NVD' AS source, count(*) FILTER (WHERE in_nvd) n FROM marts.fct_vulnerabilities
        UNION ALL SELECT 'CISA KEV', count(*) FILTER (WHERE in_kev) FROM marts.fct_vulnerabilities
        UNION ALL SELECT 'OSV', count(*) FILTER (WHERE in_osv) FROM marts.fct_vulnerabilities
        UNION ALL SELECT 'EPSS', count(*) FILTER (WHERE in_epss) FROM marts.fct_vulnerabilities""")
    fig = go.Figure(
        go.Bar(
            x=cov["n"],
            y=cov["source"],
            orientation="h",
            marker={"color": [ui.SOURCE_COLORS[s] for s in cov["source"]], "cornerradius": 4},
            text=[f"{int(n):,}" for n in cov["n"]],
            textposition="outside",
            textfont={"color": ui.TEXT},
            hovertemplate="%{y}: %{x:,} vulnerabilities<extra></extra>",
        )
    )
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(ui.style_fig(fig, 200, legend=False), use_container_width=True)
    st.caption("A vulnerability can be in several sources; it is counted once in the total.")

st.subheader("Why not just sort by CVSS?")
st.caption(
    "Rows: NVD CVSS severity. Columns: CyberSentinel priority. Many CVSS 'CRITICAL' flaws are neither "
    "exploited nor predicted to be, so they land lower; exploited medium-severity flaws move up."
)
cross = data.query("""
    SELECT coalesce(cvss_severity, 'NO CVSS') AS "CVSS severity",
           count(*) FILTER (WHERE priority_tier = 'Critical') AS "Critical",
           count(*) FILTER (WHERE priority_tier = 'High')     AS "High",
           count(*) FILTER (WHERE priority_tier = 'Medium')   AS "Medium",
           count(*) FILTER (WHERE priority_tier = 'Low')      AS "Low"
    FROM marts.fct_vulnerabilities GROUP BY 1
    ORDER BY CASE "CVSS severity" WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3
                                  WHEN 'LOW' THEN 4 ELSE 5 END""")
st.dataframe(cross, hide_index=True, use_container_width=True)

st.subheader("Where exposure concentrates")
v_col, e_col = st.columns(2)
with v_col:
    st.caption("Vendors with the most Critical + High vulnerabilities")
    vendors = data.query("""
        SELECT coalesce(vendor, 'unknown') AS vendor,
               count(*) FILTER (WHERE priority_tier = 'Critical') AS critical,
               count(*) FILTER (WHERE priority_tier = 'High') AS high
        FROM marts.fct_vulnerabilities GROUP BY 1
        HAVING count(*) FILTER (WHERE priority_tier IN ('Critical', 'High')) > 0
        ORDER BY critical + high DESC LIMIT 10""")
    fig = go.Figure()
    for tier in ("Critical", "High"):
        fig.add_bar(
            y=vendors["vendor"],
            x=vendors[tier.lower()],
            name=tier,
            orientation="h",
            marker={"color": ui.TIER_COLORS[tier], "line": {"color": ui.SURFACE, "width": 2}},
            hovertemplate="%{y}: %{x} " + tier + "<extra></extra>",
        )
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(ui.style_fig(fig, 340), use_container_width=True)
with e_col:
    st.caption("Watched ecosystems: affected vulnerabilities by priority")
    eco = data.query("""
        SELECT ecosystem, priority_tier, count(DISTINCT vulnerability_id) n
        FROM marts.fct_package_exposure WHERE match_status = 'affected' GROUP BY 1, 2""")
    fig = go.Figure()
    for tier in ui.TIERS:
        part = eco[eco["priority_tier"] == tier]
        fig.add_bar(
            x=part["ecosystem"],
            y=part["n"],
            name=tier,
            marker={"color": ui.TIER_COLORS[tier], "line": {"color": ui.SURFACE, "width": 2}},
            hovertemplate="%{x}: %{y} " + tier + "<extra></extra>",
        )
    fig.update_layout(barmode="stack")
    st.plotly_chart(ui.style_fig(fig, 340), use_container_width=True)
