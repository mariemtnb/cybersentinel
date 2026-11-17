"""Shared visual language: colours, chart template and small components.

Priority tiers are an ordered *state*, so they use the reserved status colours
(critical / serious / warning / neutral) and are always shown with their text label —
colour is never the only carrier of meaning. Sources use the first categorical slots.
"""

from __future__ import annotations

import html

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

TIERS = ["Critical", "High", "Medium", "Low"]
TIER_COLORS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#7c7b75"}
SOURCE_COLORS = {"NVD": "#3987e5", "CISA KEV": "#d95926", "OSV": "#199e70", "EPSS": "#c98500"}
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
STATUS_COLORS = {
    "success": "#0ca30c",
    "partial": "#fab219",
    "failed": "#d03b3b",
    "blocked": "#ec835a",
    "running": "#3987e5",
}

SURFACE = "#141413"
TEXT = "#f0efec"
MUTED = "#a3a29b"
GRID = "#2b2b29"

CSS = """
<style>
  .block-container {padding-top: 2.2rem; max-width: 1400px;}
  h1, h2, h3 {letter-spacing: -0.01em;}
  .cs-kpi {border: 1px solid #2b2b29; border-radius: 8px; padding: 12px 14px; background: #1a1a19; min-width: 0;
           margin-bottom: 10px;}
  .cs-kpi .label {color: #a3a29b; font-size: 0.72rem; line-height: 1.25; text-transform: uppercase; letter-spacing: .05em;}
  .cs-kpi .value {font-size: clamp(1.15rem, 1.9vw, 1.75rem); font-weight: 600; font-variant-numeric: tabular-nums;
                  margin-top: 2px; white-space: nowrap;}
  .cs-kpi .note {color: #a3a29b; font-size: 0.8rem; margin-top: 2px; white-space: nowrap; overflow: hidden;
                 text-overflow: ellipsis;}
  .cs-pill {display:inline-block; padding: 1px 9px; border-radius: 999px; font-size: .78rem; font-weight: 600;
            border: 1px solid currentColor;}
  .cs-muted {color: #a3a29b; font-size: .85rem;}
  .cs-banner {border-left: 3px solid #fab219; background:#1f1d17; padding: 8px 12px; border-radius: 4px;
              margin-bottom: 12px; font-size: .9rem;}
</style>
"""


def apply_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def kpi(label: str, value, note: str = "", accent: str | None = None) -> None:
    style = f' style="color:{accent}"' if accent else ""
    st.markdown(
        f'<div class="cs-kpi"><div class="label">{html.escape(label)}</div>'
        f'<div class="value"{style}>{html.escape(str(value))}</div>'
        f'<div class="note">{html.escape(note)}</div></div>',
        unsafe_allow_html=True,
    )


def pill(text: str, color: str) -> str:
    return f'<span class="cs-pill" style="color:{color}">{html.escape(text)}</span>'


def tier_pill(tier: str) -> str:
    return pill(tier, TIER_COLORS.get(tier, MUTED))


def style_fig(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height,
        margin={"l": 8, "r": 48, "t": 30, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT, "size": 12},
        showlegend=legend,
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "x": 0,
            "font": {"color": MUTED},
            "traceorder": "normal",
        },
        hoverlabel={"bgcolor": "#262624", "font": {"color": TEXT}},
        bargap=0.25,
    )
    fig.update_traces(cliponaxis=False, selector={"type": "bar"})  # outside value labels stay visible
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont={"color": MUTED})
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont={"color": MUTED})
    return fig


def fmt_ts(value) -> str:
    if value is None or pd.isna(value):
        return "—"
    ts = pd.Timestamp(value)
    if ts.tzinfo is not None:
        ts = ts.tz_convert("UTC")
    return ts.strftime("%Y-%m-%d %H:%M UTC")


def hours_since(value) -> float:
    if value is None or pd.isna(value):
        return float("inf")
    ts = pd.Timestamp(value)
    ts = ts.tz_convert("UTC") if ts.tzinfo else ts.tz_localize("UTC")
    return (pd.Timestamp.now(tz="UTC") - ts).total_seconds() / 3600


def age(value) -> str:
    hours = hours_since(value)
    if hours == float("inf"):
        return "never"
    if hours < 1:
        return f"{int(hours * 60)} min ago"
    if hours < 48:
        return f"{hours:.0f} h ago"
    return f"{hours / 24:.0f} days ago"


def no_data_notice() -> None:
    st.info(
        "No published data yet. The pipeline publishes the warehouse after its first successful run "
        "(about 10 minutes on a fresh start without an NVD API key). Pipeline progress is visible on "
        "the Pipeline Health page."
    )
