"""Pipeline Health — freshness, run history, volumes, validation failures and errors (live ops database)."""

import plotly.graph_objects as go
import streamlit as st

from dashboard import data, ui

FRESH_HOURS = 30  # daily schedule + margin
SOURCES = {"cisa_kev": "CISA KEV", "nvd": "NVD", "osv": "OSV", "epss": "EPSS"}

st.title("Pipeline Health")
st.caption("Read live from the operational database: includes runs that failed and were not published.")
if not data.ops_available():
    st.info("The pipeline has not run yet.")
    st.stop()

runs = data.ops_query("""SELECT run_id, trigger, started_at, finished_at, status, published, is_baseline,
                                duration_seconds, error FROM ops.pipeline_runs ORDER BY started_at DESC""")
last_ok = runs[runs["published"] == True]  # noqa: E712 - pandas boolean mask

c = st.columns(4)
with c[0]:
    latest = runs.iloc[0] if len(runs) else None
    ui.kpi(
        "Latest run",
        latest["status"] if latest is not None else "—",
        ui.age(latest["started_at"]) if latest is not None else "",
        ui.STATUS_COLORS.get(latest["status"]) if latest is not None else None,
    )
with c[1]:
    ui.kpi(
        "Last successful publication",
        ui.age(last_ok.iloc[0]["finished_at"]) if len(last_ok) else "never",
        ui.fmt_ts(last_ok.iloc[0]["finished_at"]) if len(last_ok) else "",
    )
with c[2]:
    done = runs.dropna(subset=["duration_seconds"])
    ui.kpi("Last run duration", f"{done.iloc[0]['duration_seconds'] / 60:.1f} min" if len(done) else "—")
with c[3]:
    rate = (runs.head(20)["status"].isin(["success", "partial"])).mean() if len(runs) else 0
    ui.kpi("Runs published (last 20)", f"{rate:.0%}")

st.subheader("Source freshness")
src = data.ops_query("""
    WITH last AS (SELECT *, row_number() OVER (PARTITION BY source ORDER BY started_at DESC) rn FROM ops.source_runs),
         ok AS (SELECT source, max(finished_at) last_success FROM ops.source_runs WHERE status = 'success' GROUP BY 1)
    SELECT l.source, l.status, l.started_at, ok.last_success, l.records_extracted, l.records_rejected,
           l.records_inserted, l.records_updated, l.requests, l.source_timestamp, l.error, l.schema_warnings
    FROM last l LEFT JOIN ok USING (source) WHERE rn = 1""").set_index("source")
cols = st.columns(4)
for col, (key, label) in zip(cols, SOURCES.items(), strict=True):
    with col:
        if key not in src.index:
            ui.kpi(label, "no run yet")
            continue
        r = src.loc[key]
        stale = ui.hours_since(r.last_success) > FRESH_HOURS
        hours_note = f"last success {ui.age(r.last_success)}"
        status = "stale" if stale else r.status
        color = ui.STATUS_COLORS["failed"] if stale else ui.STATUS_COLORS.get(r.status)
        ui.kpi(label, status, hours_note, color)
        st.caption(
            f"Extracted {int(r.records_extracted or 0):,} · rejected {int(r.records_rejected or 0):,} · "
            f"inserted {int(r.records_inserted or 0):,} · updated {int(r.records_updated or 0):,} · "
            f"{int(r.requests or 0)} requests"
        )
        if r.source_timestamp:
            st.caption(f"Source timestamp: {r.source_timestamp}")
st.caption(
    f"A source is shown as stale when it has not been refreshed successfully for more than {FRESH_HOURS} h "
    "(alerts fire after 48 h)."
)

st.subheader("Execution history")
table = runs.assign(duration_min=(runs["duration_seconds"] / 60).round(1)).drop(columns=["duration_seconds"])
st.dataframe(
    table.head(50),
    hide_index=True,
    use_container_width=True,
    column_config={
        "started_at": st.column_config.DatetimeColumn("Started", format="YYYY-MM-DD HH:mm"),
        "finished_at": st.column_config.DatetimeColumn("Finished", format="YYYY-MM-DD HH:mm"),
        "duration_min": st.column_config.NumberColumn("Minutes"),
    },
)

st.subheader("Records processed per run")
vol = data.ops_query("""SELECT r.started_at, s.source, coalesce(s.records_inserted, 0) + coalesce(s.records_updated, 0)
                               AS changed, coalesce(s.records_extracted, 0) AS extracted
                        FROM ops.source_runs s JOIN ops.pipeline_runs r USING (run_id)
                        ORDER BY r.started_at""")
metric = st.radio(
    "Measure",
    ["extracted", "changed"],
    horizontal=True,
    captions=["rows received and validated", "rows inserted or updated"],
)
fig = go.Figure()
for i, (key, label) in enumerate(SOURCES.items()):
    part = vol[vol["source"] == key]
    fig.add_scatter(
        x=part["started_at"],
        y=part[metric],
        name=label,
        mode="lines+markers",
        line={"color": ui.SERIES[i], "width": 2},
        marker={"size": 8},
        hovertemplate=label + " %{x|%Y-%m-%d %H:%M}: %{y:,}<extra></extra>",
    )
fig.update_yaxes(type="log", title=None)
st.plotly_chart(ui.style_fig(fig, 300), use_container_width=True)
st.caption("Logarithmic scale: EPSS rows outnumber the other sources by orders of magnitude.")

st.subheader("Validation failures (quarantine)")
q = data.ops_query("""SELECT source, table_name, reasons, count(*) n, max(quarantined_at) last_seen
                      FROM ops.quarantine GROUP BY ALL ORDER BY last_seen DESC LIMIT 100""")
if q.empty:
    st.success("No record has been rejected by a data contract.")
else:
    st.dataframe(q, hide_index=True, use_container_width=True)
    with st.expander("Rejected records (latest 50)"):
        st.dataframe(
            data.ops_query("""SELECT quarantined_at, source, table_name, record_key, reasons, record_json
                                      FROM ops.quarantine ORDER BY quarantined_at DESC LIMIT 50"""),
            hide_index=True,
            use_container_width=True,
        )

st.subheader("Latest errors and warnings")
errs = data.ops_query("""
    SELECT started_at, run_id, source, status, error, schema_warnings FROM ops.source_runs
    WHERE error IS NOT NULL OR schema_warnings IS NOT NULL
    UNION ALL
    SELECT started_at, run_id, 'pipeline', status, error, NULL FROM ops.pipeline_runs WHERE error IS NOT NULL
    ORDER BY started_at DESC LIMIT 30""")
if errs.empty:
    st.success("No error or schema warning recorded.")
else:
    st.dataframe(errs, hide_index=True, use_container_width=True)
