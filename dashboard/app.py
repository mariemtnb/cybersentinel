"""CyberSentinel dashboard — entry point (`streamlit run dashboard/app.py`)."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `import dashboard.*`

from dashboard import data, ui  # noqa: E402

st.set_page_config(page_title="CyberSentinel", page_icon=":material/shield:", layout="wide")
ui.apply_css()

pages = [
    st.Page("pages/overview.py", title="Overview", icon=":material/dashboard:", default=True),
    st.Page("pages/explorer.py", title="Vulnerability Explorer", icon=":material/search:"),
    st.Page("pages/packages.py", title="Package Exposure", icon=":material/inventory_2:"),
    st.Page("pages/threat_intel.py", title="Threat Intelligence", icon=":material/radar:"),
    st.Page("pages/health.py", title="Pipeline Health", icon=":material/monitor_heart:"),
]
nav = st.navigation(pages)

with st.sidebar:
    st.markdown("### CyberSentinel")
    st.caption("Vulnerability intelligence and prioritisation")
    run = data.last_published_run()
    if run is not None:
        st.markdown(
            f"<div class='cs-muted'>Data published {ui.age(run['finished_at'])}<br>"
            f"run <code>{run['run_id']}</code></div>",
            unsafe_allow_html=True,
        )
        if run["trigger"] == "replay":
            st.warning("Offline replay data (recorded API responses), not a live refresh.")
    else:
        st.markdown("<div class='cs-muted'>No published run yet</div>", unsafe_allow_html=True)
    st.caption("Sources: CISA KEV · NIST NVD · OSV · FIRST EPSS")

nav.run()
