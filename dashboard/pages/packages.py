"""Package Exposure — the configured watchlist and what affects each package."""

import streamlit as st

from dashboard import data, ui

st.title("Package Exposure")
st.caption(
    "Watchlist from config/watchlist.yaml (demonstration inventory). A package counts as affected only "
    "when its exact version falls inside an advisory's affected range, re-checked by CyberSentinel."
)
if not data.published_available():
    ui.no_data_notice()
    st.stop()

summary = data.query("""
    SELECT p.package_name AS "Package", p.ecosystem AS "Ecosystem", p.package_version AS "Version",
           p.owner AS "Owner",
           count(e.vulnerability_id) FILTER (WHERE e.match_status = 'affected')     AS "Known vulnerabilities",
           count(e.vulnerability_id) FILTER (WHERE e.match_status = 'unverified')   AS "Unverified",
           CASE max(e.priority_rank) FILTER (WHERE e.match_status = 'affected')
                WHEN 4 THEN 'Critical' WHEN 3 THEN 'High' WHEN 2 THEN 'Medium' WHEN 1 THEN 'Low' ELSE '—' END
                                                                                    AS "Highest priority",
           count(*) FILTER (WHERE e.match_status = 'affected' AND e.fix_available)  AS "With fix",
           count(*) FILTER (WHERE e.match_status = 'affected' AND e.is_kev)         AS "In KEV",
           p.last_checked_at                                                       AS "Last checked"
    FROM marts.dim_package p
    LEFT JOIN marts.fct_package_exposure e USING (package_key)
    GROUP BY ALL
    ORDER BY max(e.priority_rank) FILTER (WHERE e.match_status = 'affected') DESC NULLS LAST,
             "Known vulnerabilities" DESC""")

c = st.columns(4)
with c[0]:
    ui.kpi("Watched packages", len(summary))
with c[1]:
    ui.kpi("Packages with known vulnerabilities", int((summary["Known vulnerabilities"] > 0).sum()))
with c[2]:
    ui.kpi(
        "Packages with a Critical issue",
        int((summary["Highest priority"] == "Critical").sum()),
        "",
        ui.TIER_COLORS["Critical"],
    )
with c[3]:
    ui.kpi("Exposures with a fix available", int(summary["With fix"].sum()))

st.write("")
st.dataframe(
    summary,
    hide_index=True,
    use_container_width=True,
    column_config={"Last checked": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm")},
)

st.subheader("Detail per package")
choice = st.selectbox("Package", summary["Package"] + " " + summary["Version"])
name, version = choice.rsplit(" ", 1)
detail = data.query(
    """
    SELECT vulnerability_id AS "Vulnerability", priority_tier AS "Priority", priority_score AS "Score",
           match_status AS "Verdict", fixed_version AS "Fixed in", cvss_base_score AS "CVSS",
           epss_score AS "EPSS", is_kev AS "KEV", title AS "Title", osv_ids AS "Advisories"
    FROM marts.fct_package_exposure WHERE package_name = ? AND package_version = ?
    ORDER BY priority_score DESC""",
    [name, version],
)
if detail.empty:
    st.success("No advisory affects this exact version.")
else:
    fixes = detail["Fixed in"].dropna()
    if len(fixes):
        st.caption(
            "Fixed versions listed per advisory; upgrading to a version at or above all of them resolves the "
            "listed issues (check each advisory for branch-specific fixes)."
        )
    st.dataframe(
        detail,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.0f"),
            "EPSS": st.column_config.NumberColumn("EPSS", format="percent"),
            "KEV": st.column_config.CheckboxColumn("KEV"),
        },
    )
