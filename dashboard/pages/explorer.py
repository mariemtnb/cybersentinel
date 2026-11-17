"""Vulnerability Explorer — search, filter, and open one vulnerability to see why it is ranked."""

import html

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard import data, ui


def show(value):
    """Display helper: a missing value (None / NaN / NaT) becomes an em dash."""
    return "—" if value is None or pd.isna(value) else value


st.title("Vulnerability Explorer")
if not data.published_available():
    ui.no_data_notice()
    st.stop()

opts = data.query("""
    SELECT min(published_date) AS first_day, max(published_date) AS last_day FROM marts.fct_vulnerabilities""").iloc[
    0
]
vendors = data.query(
    "SELECT DISTINCT vendor FROM marts.fct_vulnerabilities WHERE vendor IS NOT NULL ORDER BY 1"
)
ecosystems = data.query("SELECT DISTINCT ecosystem FROM marts.fct_package_exposure ORDER BY 1")
packages = data.query("SELECT DISTINCT package_name FROM marts.fct_package_exposure ORDER BY 1")

f1, f2, f3, f4 = st.columns([2, 2, 2, 2])
search = f1.text_input("CVE / advisory ID or text", placeholder="e.g. CVE-2021-44228 or log4j")
tiers = f2.multiselect("Priority", ui.TIERS, default=[])
severities = f3.multiselect("CVSS severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], default=[])
kev = f4.selectbox("CISA KEV", ["Any", "Only KEV", "Not in KEV"])
g1, g2, g3, g4, g5 = st.columns([2, 2, 2, 2, 2])
vendor = g1.selectbox("Vendor", ["Any", *vendors["vendor"].tolist()])
product = g2.text_input("Product contains", "")
ecosystem = g3.selectbox("Ecosystem (watchlist)", ["Any", *ecosystems["ecosystem"].tolist()])
package = g4.selectbox("Affected package", ["Any", *packages["package_name"].tolist()])
epss_range = g5.slider("EPSS range", 0.0, 1.0, (0.0, 1.0), step=0.01)
date_from, date_to = (
    st.slider(
        "Publication date",
        min_value=opts.first_day.date(),
        max_value=opts.last_day.date(),
        value=(opts.first_day.date(), opts.last_day.date()),
        format="YYYY-MM-DD",
    )
    if opts.first_day is not None and opts.first_day == opts.first_day
    else (None, None)
)

# Build a parameterised WHERE clause: user input is only ever passed as bound parameters.
where, params = ["1 = 1"], []
if search:
    where.append(
        "(f.vulnerability_id ILIKE ? OR f.title ILIKE ? OR d.description ILIKE ? OR d.osv_ids ILIKE ?)"
    )
    params += [f"%{search}%"] * 4
if tiers:
    where.append(f"f.priority_tier IN ({', '.join('?' * len(tiers))})")
    params += tiers
if severities:
    where.append(f"f.cvss_severity IN ({', '.join('?' * len(severities))})")
    params += severities
if kev != "Any":
    where.append("f.is_kev" if kev == "Only KEV" else "NOT f.is_kev")
if vendor != "Any":
    where.append("f.vendor = ?")
    params.append(vendor)
if product:
    where.append("f.product ILIKE ?")
    params.append(f"%{product}%")
if ecosystem != "Any" or package != "Any":
    sub, sub_params = ["1 = 1"], []
    if ecosystem != "Any":
        sub.append("ecosystem = ?")
        sub_params.append(ecosystem)
    if package != "Any":
        sub.append("package_name = ?")
        sub_params.append(package)
    where.append(
        f"f.vulnerability_id IN (SELECT vulnerability_id FROM marts.fct_package_exposure "
        f"WHERE {' AND '.join(sub)})"
    )
    params += sub_params
if epss_range != (0.0, 1.0):
    where.append("f.epss_score BETWEEN ? AND ?")
    params += list(epss_range)
if date_from is not None and (date_from, date_to) != (opts.first_day.date(), opts.last_day.date()):
    where.append("f.published_date BETWEEN ? AND ?")
    params += [date_from, date_to]

total = data.query(
    f"""
    SELECT count(*) AS n FROM marts.fct_vulnerabilities f JOIN marts.dim_vulnerability d USING (vulnerability_id)
    WHERE {" AND ".join(where)}""",
    params,
).iloc[0]["n"]
results = data.query(
    f"""
    SELECT f.vulnerability_id AS "ID", f.priority_tier AS "Priority", f.priority_score AS "Score",
           f.cvss_base_score AS "CVSS", f.cvss_severity AS "Severity", f.epss_score AS "EPSS",
           f.is_kev AS "KEV", f.watchlist_affected_count AS "Watched pkgs", f.vendor AS "Vendor",
           f.product AS "Product", f.published_date AS "Published", f.title AS "Title"
    FROM marts.fct_vulnerabilities f JOIN marts.dim_vulnerability d USING (vulnerability_id)
    WHERE {" AND ".join(where)}
    ORDER BY f.priority_score DESC, f.vulnerability_id
    LIMIT 2000""",
    params,
)

st.caption(
    f"{total:,} vulnerabilities match (showing the {len(results):,} highest priority). "
    "Select a row to open its detail."
)
event = st.dataframe(
    results,
    hide_index=True,
    use_container_width=True,
    height=380,
    on_select="rerun",
    selection_mode="single-row",
    column_config={
        "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.0f"),
        "EPSS": st.column_config.NumberColumn("EPSS", format="percent"),
        "KEV": st.column_config.CheckboxColumn("KEV"),
    },
)
rows = event.selection.rows if event and event.selection else []
if not rows:
    st.stop()

vid = results.iloc[rows[0]]["ID"]
v = (
    data.query(
        """SELECT * FROM marts.fct_vulnerabilities f JOIN marts.dim_vulnerability d USING (vulnerability_id)
                  WHERE vulnerability_id = ?""",
        [vid],
    )
    .iloc[0]
    .to_dict()
)

st.divider()
st.markdown(f"## {html.escape(vid)} &nbsp; {ui.tier_pill(v['priority_tier'])}", unsafe_allow_html=True)
st.markdown(f"**{html.escape(str(v['title'] or ''))}**")
st.write(v["description"] or "No description available.")

a, b = st.columns([3, 2])
with a:
    st.markdown("#### Why this priority")
    st.caption("Each signal contributes points independently (config/scoring.yaml). Total capped at 100.")
    parts = [
        ("CVSS severity", v["points_cvss"]),
        ("CISA KEV", v["points_kev"]),
        ("EPSS", v["points_epss"]),
        ("Watchlist", v["points_watchlist"]),
        ("Fix available", v["points_fix"]),
    ]
    fig = go.Figure(
        go.Bar(
            x=[p[1] for p in parts],
            y=[p[0] for p in parts],
            orientation="h",
            marker={"color": "#3987e5", "cornerradius": 4},
            text=[f"{p[1]:g} pts" for p in parts],
            textposition="outside",
            textfont={"color": ui.TEXT},
            hovertemplate="%{y}: %{x} points<extra></extra>",
        )
    )
    fig.update_xaxes(range=[0, 40])
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(ui.style_fig(fig, 230, legend=False), use_container_width=True)
    st.info(v["priority_reason"])
with b:
    st.markdown("#### Signals by source")
    epss = (
        "—"
        if v["epss_score"] != v["epss_score"] or v["epss_score"] is None
        else f"{v['epss_score']:.2%} (percentile {v['epss_percentile']:.0%}, {v['epss_date']:%Y-%m-%d})"
    )
    rows_md = [
        (
            "NVD CVSS",
            f"{v['cvss_base_score']} {v['cvss_severity']} (v{v['cvss_version']})"
            if v["cvss_base_score"] == v["cvss_base_score"] and v["cvss_base_score"] is not None
            else "not scored",
        ),
        (
            "CISA KEV",
            f"Yes — added {v['kev_date_added']:%Y-%m-%d}, due {v['kev_due_date']:%Y-%m-%d}"
            + (", ransomware use known" if v["kev_ransomware"] else "")
            if v["is_kev"]
            else "No",
        ),
        ("EPSS (prediction)", epss),
        ("OSV advisories", show(v["osv_ids"])),
        ("Vendor / product", f"{show(v['vendor'])} / {show(v['product'])}"),
        ("Published", ui.fmt_ts(v["published_at"])),
        ("CWE", show(v["cwe_ids"])),
        ("Sources", v["sources"]),
        ("First seen", ui.fmt_ts(v["first_seen_at"])),
    ]
    st.table({"Signal": [r[0] for r in rows_md], "Value": [str(r[1]) for r in rows_md]})
    links = [
        f"[NVD]({v['nvd_url']})" if v["nvd_url"] else None,
        f"[OSV]({v['osv_url']})" if v["osv_url"] else None,
    ]
    st.markdown(" · ".join(x for x in links if x))
    if v["is_kev"] and v["kev_required_action"]:
        st.caption(f"CISA required action: {v['kev_required_action']}")

pk = data.query(
    """SELECT package_name AS "Package", ecosystem AS "Ecosystem", package_version AS "Version",
                          match_status AS "Verdict", fixed_version AS "Fixed in", osv_ids AS "Advisories"
                   FROM marts.fct_package_exposure WHERE vulnerability_id = ?""",
    [vid],
)
if not pk.empty:
    st.markdown("#### Affected watched packages")
    st.dataframe(pk, hide_index=True, use_container_width=True)

hist = data.query(
    """SELECT score_date, epss_score FROM marts.fct_epss_history
                     WHERE vulnerability_id = ? ORDER BY score_date""",
    [vid],
)
if len(hist) > 1:
    st.markdown("#### EPSS history")
    fig = go.Figure(
        go.Scatter(
            x=hist["score_date"],
            y=hist["epss_score"],
            mode="lines",
            line={"color": "#3987e5", "width": 2},
            hovertemplate="%{x|%Y-%m-%d}: %{y:.2%}<extra></extra>",
        )
    )
    fig.update_yaxes(tickformat=".0%", rangemode="tozero")
    st.plotly_chart(ui.style_fig(fig, 220, legend=False), use_container_width=True)

changes = data.query(
    """SELECT detected_at AS "Detected", event_type AS "Event", old_value AS "From",
                               new_value AS "To", run_id AS "Run"
                        FROM marts.fct_vulnerability_changes WHERE vulnerability_id = ? ORDER BY detected_at DESC""",
    [vid],
)
if not changes.empty:
    st.markdown("#### Change history")
    st.dataframe(changes, hide_index=True, use_container_width=True)
