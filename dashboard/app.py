import json
import os
import html
from datetime import date, datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
API_URL = (
    os.getenv("PI_API_URL") or os.getenv("OSINT_API_URL") or "http://localhost:8000"
).rstrip("/")
API_KEY = (os.getenv("PI_API_KEY") or os.getenv("OSINT_API_KEY") or "").strip()


def _hdrs():
    return {"X-API-Key": API_KEY} if API_KEY else {}


def _get(path, params=None, timeout=20):
    r = requests.get(f"{API_URL}{path}", params=params, headers=_hdrs(), timeout=timeout)
    r.raise_for_status()
    return r.json()


def _post(path, payload=None, timeout=30):
    r = requests.post(f"{API_URL}{path}", json=payload, headers=_hdrs(), timeout=timeout)
    r.raise_for_status()
    return r.json()


def _patch(path, payload=None, timeout=20):
    kw = {"headers": _hdrs(), "timeout": timeout}
    if payload is not None:
        kw["json"] = payload
    r = requests.patch(f"{API_URL}{path}", **kw)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Cached API wrappers
# ---------------------------------------------------------------------------
@st.cache_data(ttl=120, show_spinner=False)
def fetch_summary():
    return _get("/alerts/summary", params={"include_demo": 0})

@st.cache_data(ttl=300, show_spinner=False)
def fetch_pois():
    return _get("/pois")

@st.cache_data(ttl=300, show_spinner=False)
def fetch_threat_subjects():
    return _get("/threat-subjects")

@st.cache_data(ttl=120, show_spinner=False)
def fetch_alerts(severity="All", status="All", min_score=0, limit=100):
    params = {"limit": limit, "sort_by": "risk_score", "include_demo": 0}
    if severity != "All":
        params["severity"] = severity
    if status == "Unreviewed":
        params["reviewed"] = 0
    elif status == "Reviewed":
        params["reviewed"] = 1
    if min_score > 0:
        params["min_score"] = min_score
    return _get("/alerts", params=params)

@st.cache_data(ttl=600, show_spinner=False)
def fetch_daily_report(date_str):
    return _get("/intelligence/daily", params={"date": date_str, "include_demo": 0})

@st.cache_data(ttl=300, show_spinner=False)
def fetch_map_data(days=7, min_ors=0):
    return _get("/analytics/map", params={"days": days, "min_ors": min_ors, "include_demo": 0})

@st.cache_data(ttl=300, show_spinner=False)
def fetch_graph_data(days=7, min_score=40, limit=200):
    return _get(
        "/analytics/graph",
        params={"days": days, "min_score": min_score, "limit_alerts": limit, "include_demo": 0},
    )

@st.cache_data(ttl=120, show_spinner=False)
def fetch_spikes(threshold=1.5):
    return _get("/analytics/spikes", params={"threshold": threshold})

@st.cache_data(ttl=600, show_spinner=False)
def fetch_poi_assessment(poi_id, window_days=14):
    return _get(f"/pois/{poi_id}/assessment", params={"window_days": window_days})

@st.cache_data(ttl=300, show_spinner=False)
def fetch_escalation_tiers():
    return _get("/analytics/escalation-tiers")

@st.cache_data(ttl=300, show_spinner=False)
def fetch_locations():
    return _get("/locations/protected")

@st.cache_data(ttl=300, show_spinner=False)
def fetch_keywords():
    return _get("/keywords")

@st.cache_data(ttl=300, show_spinner=False)
def fetch_sources():
    return _get("/sources", params={"include_demo": 0})

@st.cache_data(ttl=120, show_spinner=False)
def fetch_sitreps(status=None, limit=20):
    params = {"limit": limit}
    if status and status != "All":
        params["status"] = status
    return _get("/sitreps", params=params)

@st.cache_data(ttl=300, show_spinner=False)
def fetch_poi_hits(poi_id, days=14):
    return _get(f"/pois/{poi_id}/hits", params={"days": days})

@st.cache_data(ttl=300, show_spinner=False)
def fetch_subject_detail(subject_id):
    return _get(f"/threat-subjects/{subject_id}")


# ---------------------------------------------------------------------------
# Plotly dark template
# ---------------------------------------------------------------------------
PI_TEMPLATE = go.layout.Template(
    layout=dict(
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(family="Inter, system-ui, sans-serif", color="#94a3b8", size=12),
        title=dict(font=dict(color="#e2e8f0", size=14)),
        xaxis=dict(gridcolor="#1e293b", zerolinecolor="#1e293b", tickfont=dict(color="#94a3b8")),
        yaxis=dict(gridcolor="#1e293b", zerolinecolor="#1e293b", tickfont=dict(color="#94a3b8")),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#94a3b8"), bordercolor="#1e3a5f"),
        margin=dict(l=40, r=20, t=48, b=32),
        colorway=["#3b82f6", "#06b6d4", "#8b5cf6", "#f97316", "#ec4899", "#22c55e"],
    )
)
pio.templates["pi_dark"] = PI_TEMPLATE
pio.templates.default = "pi_dark"
ACTIVE_TEMPLATE_NAME = "pi_dark"


def _style(fig, height=None):
    fig.update_layout(template=ACTIVE_TEMPLATE_NAME)
    if height:
        fig.update_layout(height=height)
    return fig


# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
TIER_COLORS = {"CRITICAL": "#ef4444", "ELEVATED": "#f97316", "ROUTINE": "#eab308", "LOW": "#22c55e"}

SEV_CSS = {
    "critical": "background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.3)",
    "high": "background:rgba(249,115,22,0.15);color:#f97316;border:1px solid rgba(249,115,22,0.3)",
    "medium": "background:rgba(234,179,8,0.15);color:#eab308;border:1px solid rgba(234,179,8,0.3)",
    "low": "background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid rgba(34,197,94,0.3)",
}
TIER_CSS = {
    "CRITICAL": SEV_CSS["critical"],
    "ELEVATED": SEV_CSS["high"],
    "ROUTINE": SEV_CSS["medium"],
    "LOW": SEV_CSS["low"],
}


def _badge(label, css_style):
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:4px;'
        f'font-weight:700;font-size:0.72rem;letter-spacing:0.04em;{css_style}">'
        f'{html.escape(str(label), quote=True)}</span>'
    )


def _sev_badge(sev):
    return _badge(sev.upper(), SEV_CSS.get(sev, SEV_CSS["low"]))


def _tier_badge(tier):
    return _badge(tier, TIER_CSS.get(tier, TIER_CSS["LOW"]))


def _empty(msg, icon="\u2014"):
    st.markdown(
        f'<div style="text-align:center;padding:32px 20px;color:#64748b;font-size:0.88rem;'
        f'border:1px dashed #1e3a5f;border-radius:8px;background:rgba(17,24,39,0.5);">'
        f'<div style="font-size:1.4rem;margin-bottom:6px;opacity:0.4;">{icon}</div>'
        f'{msg}</div>',
        unsafe_allow_html=True,
    )


def _esc(value):
    return html.escape(str(value), quote=True)


def _safe_id_set(value):
    if value is None:
        return set()
    items = value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return set()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = [part.strip() for part in text.split(",") if part.strip()]
        items = parsed if isinstance(parsed, list) else [parsed]
    elif not isinstance(value, list):
        items = [value]

    ids = set()
    for item in items:
        try:
            ids.add(int(item))
        except (TypeError, ValueError):
            continue
    return ids


# ---------------------------------------------------------------------------
# Page config & CSS
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Protective Intelligence Console", page_icon="\U0001F6E1\uFE0F", layout="wide")

theme_base = (st.get_option("theme.base") or "dark").lower()
if theme_base == "light":
    ACTIVE_TEMPLATE_NAME = "pi_light"
    pio.templates["pi_light"] = go.layout.Template(
        layout=dict(
            paper_bgcolor="#f8fafc",
            plot_bgcolor="#ffffff",
            font=dict(family="Inter, system-ui, sans-serif", color="#334155", size=12),
            title=dict(font=dict(color="#0f172a", size=14)),
            xaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0", tickfont=dict(color="#334155")),
            yaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0", tickfont=dict(color="#334155")),
            legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#334155"), bordercolor="#cbd5e1"),
            margin=dict(l=40, r=20, t=48, b=32),
            colorway=["#2563eb", "#0284c7", "#7c3aed", "#ea580c", "#db2777", "#16a34a"],
        )
    )
    pio.templates.default = "pi_light"

IS_LIGHT_THEME = theme_base == "light"
UI_TEXT_PRIMARY = "#0f172a" if IS_LIGHT_THEME else "#e2e8f0"
UI_TEXT_SECONDARY = "#475569" if IS_LIGHT_THEME else "#94a3b8"
UI_PANEL_BG = "#ffffff" if IS_LIGHT_THEME else "#111827"
UI_BORDER = "#cbd5e1" if IS_LIGHT_THEME else "#1e3a5f"
UI_GRID = "#cbd5e1" if IS_LIGHT_THEME else "#1e293b"
UI_MAP_STYLE = "carto-positron" if IS_LIGHT_THEME else "carto-darkmatter"
UI_MAP_BG = "#f8fafc" if IS_LIGHT_THEME else "#0b1120"

st.markdown(
    """
<style>
:root {
    --bg-deep: #0b1120; --bg-surface: #111827; --bg-elevated: #1e293b;
    --border: #1e3a5f; --border-subtle: #162032;
    --text-primary: #e2e8f0; --text-secondary: #94a3b8; --text-muted: #64748b;
    --accent: #3b82f6; --accent-dim: #1e40af;
}
.stApp { background: var(--bg-deep); color: var(--text-primary); }
section[data-testid="stSidebar"] { background: var(--bg-surface); }

/* Metric cards */
[data-testid="stMetric"] {
    background: var(--bg-surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 12px 16px;
}
[data-testid="stMetricValue"] { font-size: 1.7rem !important; font-weight: 700 !important; color: var(--text-primary) !important; }
[data-testid="stMetricLabel"] { font-size: 0.72rem !important; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary) !important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 0; background: var(--bg-surface); border-radius: 8px; padding: 4px; border: 1px solid var(--border);
}
.stTabs [data-baseweb="tab"] {
    flex-grow: 1; justify-content: center; border-radius: 6px; color: var(--text-secondary) !important;
    font-weight: 600; font-size: 0.82rem; letter-spacing: 0.02em; white-space: nowrap;
}
.stTabs [aria-selected="true"] { background: var(--bg-elevated) !important; color: var(--text-primary) !important; }

/* Dataframes */
[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }

/* Expanders */
[data-testid="stExpander"] { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 8px; }

/* Header bar */
.ops-header {
    background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
    border: 1px solid var(--border); border-radius: 10px; padding: 14px 24px; margin-bottom: 10px;
}
.ops-kicker { color: #3b82f6; font-size: 0.7rem; letter-spacing: 0.1em; text-transform: uppercase; font-weight: 600; margin-bottom: 2px; }
.ops-title { color: #e2e8f0; font-size: 1.35rem; font-weight: 700; margin: 0; }
.ops-subtitle { color: #94a3b8; font-size: 0.82rem; margin-top: 2px; margin-bottom: 0; }

/* Escalation card */
.esc-card {
    padding: 10px 14px; border-radius: 6px; margin-bottom: 6px; font-size: 0.85rem;
}
.esc-immediate { background: rgba(239,68,68,0.12); border-left: 3px solid #ef4444; color: #fca5a5; }
.esc-high { background: rgba(249,115,22,0.12); border-left: 3px solid #f97316; color: #fdba74; }
.esc-medium { background: rgba(59,130,246,0.10); border-left: 3px solid #3b82f6; color: #93c5fd; }

/* Forms */
.stForm { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }

/* Hide Streamlit branding */
#MainMenu {visibility: hidden;} footer {visibility: hidden;}
header[data-testid="stHeader"] { background: var(--bg-deep); }
</style>
""",
    unsafe_allow_html=True,
)

if theme_base == "light":
    st.markdown(
        """
<style>
:root {
    --bg-deep: #f8fafc; --bg-surface: #ffffff; --bg-elevated: #e2e8f0;
    --border: #cbd5e1; --border-subtle: #e2e8f0;
    --text-primary: #0f172a; --text-secondary: #334155; --text-muted: #64748b;
    --accent: #2563eb; --accent-dim: #1d4ed8;
}
.ops-header { background: linear-gradient(135deg, #ffffff 0%, #f1f5f9 100%); }
.ops-title { color: #0f172a; }
.ops-subtitle { color: #475569; }
</style>
""",
        unsafe_allow_html=True,
    )

# Header
st.markdown(
    """
<section class="ops-header">
  <div class="ops-kicker">Operations Console</div>
  <h1 class="ops-title">Protective Intelligence & Executive Protection</h1>
  <p class="ops-subtitle">Threat assessment \u2022 Protectee monitoring \u2022 Travel security \u2022 Escalation management</p>
</section>
""",
    unsafe_allow_html=True,
)

# API health check
try:
    requests.get(f"{API_URL}/", headers=_hdrs(), timeout=3).raise_for_status()
except requests.RequestException:
    st.error("\u26A0\uFE0F Cannot connect to API. Start the server: `make api`")
    st.stop()


# ---------------------------------------------------------------------------
# TAB LAYOUT (5 tabs)
# ---------------------------------------------------------------------------
tabs = st.tabs([
    "Situation Overview",
    "Alert Triage",
    "Protectee Risk",
    "Intelligence Analysis",
    "Administration",
])

# ============================================================
# TAB 1: SITUATION OVERVIEW
# ============================================================
with tabs[0]:
    try:
        summary = fetch_summary()
        st.caption(f"Updated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

        # --- KPI Row ---
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Unreviewed Alerts", summary.get("unreviewed", 0))
        k2.metric("Critical", summary.get("by_severity", {}).get("critical", 0))
        k3.metric("Avg ORS", f"{summary.get('avg_risk_score', 0):.1f}")
        k4.metric("Active Spikes", summary.get("active_spikes", 0))

        # --- Escalation Recommendations + Executive Summary ---
        try:
            report = fetch_daily_report(date.today().strftime("%Y-%m-%d"))
        except requests.RequestException:
            report = {}

        col_esc, col_exec = st.columns([3, 2])

        with col_esc:
            st.markdown("##### Escalation Recommendations")
            escalations = report.get("escalation_recommendations", [])
            if escalations:
                for esc in escalations[:6]:
                    priority = esc.get("priority", "MEDIUM")
                    css_class = {
                        "IMMEDIATE": "esc-immediate",
                        "HIGH": "esc-high",
                    }.get(priority, "esc-medium")
                    action = esc.get("action", esc.get("why", ""))
                    st.markdown(
                        f'<div class="esc-card {css_class}">'
                        f'<strong>[{_esc(priority)}]</strong> {_esc(action)}</div>',
                        unsafe_allow_html=True,
                    )
            else:
                _empty("No escalation items at this time. Run scraper to ingest alerts.")

        with col_exec:
            st.markdown("##### Executive Summary")
            exec_summary = report.get("executive_summary", "")
            if exec_summary:
                st.markdown(
                    f'<div style="background:{UI_PANEL_BG};border:1px solid {UI_BORDER};border-radius:8px;'
                    f'padding:14px 18px;font-size:0.88rem;color:{UI_TEXT_SECONDARY};line-height:1.55;">'
                    f'{_esc(exec_summary).replace(chr(10), "<br>")}</div>',
                    unsafe_allow_html=True,
                )
            else:
                _empty("Executive summary will appear after alerts are ingested and scored.")

        st.markdown("")

        # --- Geospatial Map ---
        st.markdown("##### Geospatial Common Operating Picture")
        try:
            map_data = fetch_map_data(days=14, min_ors=0)
            locs = map_data.get("protected_locations", [])
            alert_pins = map_data.get("alerts", [])
            valid_locs = [loc for loc in locs if loc.get("lat") is not None and loc.get("lon") is not None]
            valid_alerts = [a for a in alert_pins if a.get("lat") is not None and a.get("lon") is not None]

            if valid_locs or valid_alerts:
                fig = go.Figure()
                if valid_locs:
                    fig.add_trace(go.Scattermapbox(
                        lat=[loc["lat"] for loc in valid_locs],
                        lon=[loc["lon"] for loc in valid_locs],
                        mode="markers+text",
                        marker=dict(size=14, color="#3b82f6", symbol="circle"),
                        text=[_esc(loc["name"]) for loc in valid_locs],
                        textposition="top center",
                        textfont=dict(color="#e2e8f0", size=10),
                        name="Protected Sites",
                    ))
                if valid_alerts:
                    colors = [SEVERITY_COLORS.get(a.get("severity", "low"), "#64748b") for a in valid_alerts]
                    sizes = [max(7, min(18, (a.get("ors_score") or 0) / 6)) for a in valid_alerts]
                    fig.add_trace(go.Scattermapbox(
                        lat=[a["lat"] for a in valid_alerts],
                        lon=[a["lon"] for a in valid_alerts],
                        mode="markers",
                        marker=dict(size=sizes, color=colors),
                        text=[f"{_esc(a['title'][:50])} (ORS:{a.get('ors_score', 0):.0f})" for a in valid_alerts],
                        name="Alert Locations",
                    ))
                all_lats = [loc["lat"] for loc in valid_locs] + [a["lat"] for a in valid_alerts]
                all_lons = [loc["lon"] for loc in valid_locs] + [a["lon"] for a in valid_alerts]
                center_lat = sum(all_lats) / len(all_lats)
                center_lon = sum(all_lons) / len(all_lons)
                fig.update_layout(
                    mapbox=dict(
                        style=UI_MAP_STYLE,
                        center=dict(lat=center_lat, lon=center_lon),
                        zoom=3,
                    ),
                    height=450, margin=dict(l=0, r=0, t=0, b=0),
                    showlegend=True, legend=dict(x=0, y=1, font=dict(color=UI_TEXT_PRIMARY)),
                    paper_bgcolor=UI_MAP_BG,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                _empty(
                    "Protected locations will appear here. Run <code>make scrape</code> to ingest geocoded alerts.",
                    "\U0001F30D",
                )
        except requests.RequestException:
            _empty("Geospatial data loading...", "\U0001F30D")

        # --- Analytics Row ---
        c_sev, c_kw, c_themes = st.columns(3)

        with c_sev:
            st.markdown("##### Severity Distribution")
            by_sev = summary.get("by_severity", {})
            if by_sev:
                sev_df = pd.DataFrame(list(by_sev.items()), columns=["Severity", "Count"])
                order = ["critical", "high", "medium", "low"]
                sev_df["Severity"] = pd.Categorical(sev_df["Severity"], categories=order, ordered=True)
                sev_df = sev_df.sort_values("Severity")
                fig = px.bar(sev_df, x="Severity", y="Count", color="Severity", color_discrete_map=SEVERITY_COLORS)
                fig.update_layout(showlegend=False)
                _style(fig, 280)
                st.plotly_chart(fig, use_container_width=True)
            else:
                _empty("No severity data yet.")

        with c_kw:
            st.markdown("##### Top Keywords")
            top_kw = summary.get("top_keywords", {})
            if top_kw:
                kw_df = pd.DataFrame(list(top_kw.items()), columns=["Keyword", "Count"])
                kw_df = kw_df.sort_values("Count", ascending=True).tail(10)
                fig = px.bar(kw_df, x="Count", y="Keyword", orientation="h", color_discrete_sequence=["#3b82f6"])
                fig.update_layout(showlegend=False)
                _style(fig, 280)
                st.plotly_chart(fig, use_container_width=True)
            else:
                _empty("Keywords populate after scraping.")

        with c_themes:
            st.markdown("##### Emerging Themes")
            themes = report.get("emerging_themes", [])
            if themes:
                th_df = pd.DataFrame(themes)
                y_col = "term" if "term" in th_df.columns else "keyword" if "keyword" in th_df.columns else None
                x_col = "spike_ratio" if "spike_ratio" in th_df.columns else "z_score" if "z_score" in th_df.columns else None
                if y_col and x_col:
                    fig = px.bar(th_df, x=x_col, y=y_col, orientation="h", color_discrete_sequence=["#06b6d4"])
                    fig.update_layout(showlegend=False)
                    _style(fig, 280)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    _empty("Themes data format pending.")
            else:
                _empty("Spike detection needs 3+ days of data.")

        # --- Escalation Tiers ---
        try:
            tiers_data = fetch_escalation_tiers()
            tier_list = tiers_data.get("tiers", [])
            if tier_list:
                tier_html = '<div style="display:flex;gap:10px;margin-top:8px;">'
                for tier in tier_list:
                    label = tier["label"]
                    css = TIER_CSS.get(label, TIER_CSS["LOW"])
                    window = tier.get("response_window", "N/A")
                    notify = ", ".join(tier.get("notify", [])) or "\u2014"
                    tier_html += (
                        f'<div style="flex:1;{css};border-radius:6px;padding:10px 14px;text-align:center;">'
                        f'<div style="font-weight:700;font-size:0.85rem;">{_esc(label)}</div>'
                        f'<div style="font-size:0.72rem;opacity:0.8;">Score {tier["threshold"]}+ \u2022 {_esc(window)}</div>'
                        f'<div style="font-size:0.68rem;opacity:0.6;">Notify: {_esc(notify)}</div>'
                        f'</div>'
                    )
                tier_html += "</div>"
                st.markdown(tier_html, unsafe_allow_html=True)
        except requests.RequestException:
            _empty("Escalation tiers unavailable.")

    except requests.RequestException as e:
        st.error(f"Cannot load overview: {e}")


# ============================================================
# TAB 2: ALERT TRIAGE
# ============================================================
with tabs[1]:
    st.markdown("##### Alert Triage Queue")

    fc1, fc2, fc3, fc4 = st.columns([1, 1, 1.5, 1])
    severity_filter = fc1.selectbox("Severity", ["All", "critical", "high", "medium", "low"], key="triage_sev")
    review_filter = fc2.selectbox("Status", ["All", "Unreviewed", "Reviewed"], key="triage_status")
    min_score = fc3.slider("Min ORS", 0.0, 100.0, 0.0, 5.0, key="triage_ors")
    alert_limit = fc4.selectbox("Show", [50, 100, 200], index=1, key="triage_limit")

    try:
        alerts = fetch_alerts(severity_filter, review_filter, min_score, alert_limit)

        if alerts:
            # Build table
            triage_left, triage_right = st.columns([3, 2])

            with triage_left:
                rows = []
                for a in alerts:
                    ors = a.get("ors_score") or a.get("risk_score") or 0
                    tas = a.get("tas_score") or 0
                    rows.append({
                        "ID": a["id"],
                        "Severity": a["severity"].upper(),
                        "Title": a["title"][:70],
                        "ORS": round(ors, 1),
                        "TAS": round(tas, 1),
                        "Source": a.get("source_name", "?")[:20],
                        "Keyword": (a.get("matched_term") or "")[:20],
                        "Status": "\u2705" if a.get("reviewed") else "\U0001F7E0",
                    })
                alert_df = pd.DataFrame(rows)
                event = st.dataframe(
                    alert_df,
                    use_container_width=True,
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key="alert_table",
                )

            with triage_right:
                selected_rows = event.selection.rows if event and event.selection else []
                if selected_rows:
                    sel_idx = selected_rows[0]
                    sel_alert = alerts[sel_idx]
                    sel_id = sel_alert["id"]
                    ors_val = sel_alert.get("ors_score") or sel_alert.get("risk_score") or 0
                    tas_val = sel_alert.get("tas_score") or 0

                    st.markdown(
                        f'{_sev_badge(sel_alert["severity"])} '
                        f'<span style="color:{UI_TEXT_PRIMARY};font-weight:600;"> {_esc(sel_alert["title"][:80])}</span>',
                        unsafe_allow_html=True,
                    )
                    if sel_alert.get("url"):
                        st.caption(sel_alert["url"])
                    if sel_alert.get("content"):
                        st.markdown(
                            f'<div style="color:{UI_TEXT_SECONDARY};font-size:0.82rem;margin:6px 0 10px 0;">'
                            f'{_esc(sel_alert["content"][:400]).replace(chr(10), "<br>")}</div>',
                            unsafe_allow_html=True,
                        )

                    # Score decomposition
                    try:
                        score_data = _get(f"/alerts/{sel_id}/score", params={"uncertainty": 1, "n": 500})
                        st.markdown("**Score Decomposition**")
                        s1, s2, s3 = st.columns(3)
                        s1.metric("Keyword Wt", f"{score_data.get('keyword_weight', 0):.1f}")
                        s2.metric("Credibility", f"{score_data.get('source_credibility', 0):.2f}")
                        s3.metric("Frequency", f"{score_data.get('frequency_factor', 0):.1f}x")
                        s4, s5, s6 = st.columns(3)
                        s4.metric("Recency", f"{score_data.get('recency_factor', 0):.2f}")
                        s5.metric("Proximity", f"{score_data.get('proximity_factor', 0):.2f}")
                        s6.metric("POI Factor", f"{score_data.get('poi_factor', 0):.2f}")

                        unc = score_data.get("uncertainty")
                        if unc:
                            st.markdown(
                                f'<div style="background:{UI_PANEL_BG};border:1px solid {UI_BORDER};border-radius:6px;'
                                f'padding:8px 12px;font-size:0.78rem;color:{UI_TEXT_SECONDARY};margin-top:6px;">'
                                f'\U0001F3AF <strong style="color:{UI_TEXT_PRIMARY};">Monte Carlo</strong> (n={unc.get("n", 500)}) '
                                f'| Mean: {unc.get("mean", 0):.1f} '
                                f'| P5: {unc.get("p05", unc.get("p5", 0)):.1f} '
                                f'| P95: {unc.get("p95", 0):.1f} '
                                f'| Std: {unc.get("std", 0):.2f}</div>',
                                unsafe_allow_html=True,
                            )
                    except requests.RequestException:
                        st.caption("Score decomposition unavailable.")

                    # Action buttons
                    st.markdown("")
                    b1, b2, b3 = st.columns(3)
                    if not sel_alert.get("reviewed"):
                        if b1.button("\u2705 Reviewed", key=f"rev_{sel_id}"):
                            _patch(f"/alerts/{sel_id}/review")
                            st.cache_data.clear()
                            st.rerun()
                        if b2.button("\u2714 True Pos", key=f"tp_{sel_id}"):
                            _patch(f"/alerts/{sel_id}/classify", payload={"classification": "true_positive"})
                            st.cache_data.clear()
                            st.rerun()
                        if b3.button("\u2718 False Pos", key=f"fp_{sel_id}"):
                            _patch(f"/alerts/{sel_id}/classify", payload={"classification": "false_positive"})
                            st.cache_data.clear()
                            st.rerun()
                    else:
                        st.markdown(
                            '<span style="color:#22c55e;font-weight:600;">\u2705 Already reviewed</span>',
                            unsafe_allow_html=True,
                        )
                else:
                    _empty("Select an alert from the table to view details and score decomposition.", "\u2190")

            # ORS Distribution
            st.markdown("##### Risk Score Distribution")
            scores = [a.get("risk_score") or a.get("ors_score") or 0 for a in alerts if (a.get("risk_score") or a.get("ors_score"))]
            if scores:
                fig = px.histogram(x=scores, nbins=25, color_discrete_sequence=["#3b82f6"],
                                   labels={"x": "ORS", "y": "Count"})
                fig.add_vline(x=85, line_dash="dash", line_color="#ef4444", annotation_text="CRITICAL",
                              annotation=dict(font_color="#ef4444"))
                fig.add_vline(x=65, line_dash="dash", line_color="#f97316", annotation_text="ELEVATED",
                              annotation=dict(font_color="#f97316"))
                fig.update_layout(xaxis_title="Operational Risk Score", yaxis_title="Alert Count")
                _style(fig, 260)
                st.plotly_chart(fig, use_container_width=True)
        else:
            _empty("No alerts match your filters. Adjust severity or ORS thresholds, or run the scraper.", "\U0001F50D")

    except requests.RequestException as e:
        st.error(f"Cannot load alerts: {e}")


# ============================================================
# TAB 3: PROTECTEE RISK
# ============================================================
with tabs[2]:
    st.markdown("##### Protectee Risk Assessment")

    try:
        pois = fetch_pois()
        if pois:
            # Build roster table
            roster_rows = []
            for poi in pois:
                sensitivity = min(poi.get("sensitivity", 3), 5)
                sens_map = {1: "LOW", 2: "GUARDED", 3: "ELEVATED", 4: "HIGH", 5: "CRITICAL"}
                roster_rows.append({
                    "ID": poi["id"],
                    "Name": poi["name"],
                    "Organization": poi.get("org", ""),
                    "Role": poi.get("role", ""),
                    "Sensitivity": sens_map.get(sensitivity, "N/A"),
                    "TAS": "\u2014",
                    "Tier": "\u2014",
                })
            roster_df = pd.DataFrame(roster_rows)
            poi_event = st.dataframe(
                roster_df, use_container_width=True, hide_index=True,
                on_select="rerun", selection_mode="single-row", key="poi_table",
            )

            # Detail panel
            selected_poi_rows = poi_event.selection.rows if poi_event and poi_event.selection else []
            if selected_poi_rows:
                sel_poi = pois[selected_poi_rows[0]]
                poi_id = sel_poi["id"]
                aliases = [a["alias"] for a in sel_poi.get("aliases", [])]

                st.markdown(f"---")
                st.markdown(
                    f'##### {_esc(sel_poi["name"])} '
                    f'<span style="color:{UI_TEXT_SECONDARY};font-size:0.85rem;">| {_esc(sel_poi.get("org", ""))} | {_esc(sel_poi.get("role", ""))}</span>',
                    unsafe_allow_html=True,
                )
                if aliases:
                    st.caption(f"Aliases: {', '.join(aliases)}")

                panel_tas, panel_subj, panel_activity = st.columns(3)

                # Left: TAS Assessment
                with panel_tas:
                    st.markdown("**Threat Assessment**")
                    try:
                        assessment = fetch_poi_assessment(poi_id)
                        if assessment and assessment.get("tas_score") is not None:
                            tas_val = assessment["tas_score"]

                            # Gauge
                            fig = go.Figure(go.Indicator(
                                mode="gauge+number",
                                value=tas_val,
                                number={"font": {"color": UI_TEXT_PRIMARY, "size": 36}},
                                gauge={
                                    "axis": {
                                        "range": [0, 100],
                                        "tickcolor": UI_TEXT_SECONDARY,
                                        "tickfont": {"color": UI_TEXT_SECONDARY},
                                    },
                                    "bar": {"color": "#3b82f6"},
                                    "bgcolor": UI_PANEL_BG,
                                    "bordercolor": UI_BORDER,
                                    "steps": [
                                        {"range": [0, 40], "color": "rgba(34,197,94,0.1)"},
                                        {"range": [40, 65], "color": "rgba(234,179,8,0.1)"},
                                        {"range": [65, 85], "color": "rgba(249,115,22,0.1)"},
                                        {"range": [85, 100], "color": "rgba(239,68,68,0.1)"},
                                    ],
                                    "threshold": {"line": {"color": "#ef4444", "width": 3}, "thickness": 0.8, "value": 85},
                                },
                            ))
                            fig.update_layout(height=220, margin=dict(l=20, r=20, t=20, b=10), paper_bgcolor=UI_PANEL_BG)
                            st.plotly_chart(fig, use_container_width=True)

                            # TRAP-lite flags
                            flags_html = '<div style="display:flex;gap:8px;flex-wrap:wrap;">'
                            for flag_name in ["fixation", "energy_burst", "leakage", "pathway", "targeting_specificity"]:
                                active = assessment.get(flag_name)
                                color = "#ef4444" if active else "#334155"
                                icon = "\u25CF" if active else "\u25CB"
                                label = flag_name.replace("_", " ").title()
                                flags_html += (
                                    f'<span style="color:{color};font-size:0.78rem;font-weight:600;">'
                                    f'{icon} {label}</span>'
                                )
                            flags_html += "</div>"
                            st.markdown(flags_html, unsafe_allow_html=True)

                            # Escalation info
                            esc = assessment.get("escalation", {})
                            if esc:
                                esc_tier = esc.get("escalation_tier", esc.get("tier", {}).get("label", ""))
                                if esc_tier:
                                    st.markdown(f"{_tier_badge(esc_tier)}", unsafe_allow_html=True)
                                actions = esc.get("recommended_actions", [])
                                for act in actions[:3]:
                                    st.markdown(
                                        f'<span style="color:{UI_TEXT_SECONDARY};font-size:0.78rem;">\u2022 {_esc(act)}</span>',
                                        unsafe_allow_html=True,
                                    )
                        else:
                            _empty("No threat data. Ingest alerts mentioning this protectee.")
                    except requests.RequestException:
                        _empty("Assessment unavailable.")

                # Center: Linked Threat Subjects
                with panel_subj:
                    st.markdown("**Linked Threat Subjects**")
                    try:
                        subjects = fetch_threat_subjects()
                        linked = [s for s in subjects if s.get("linked_poi_id") == poi_id]
                        if linked:
                            for subj in linked[:3]:
                                score = subj.get("latest_pathway_score") or 0
                                tier = subj.get("risk_tier", "LOW")
                                st.markdown(
                                    f'{_tier_badge(tier)} **{_esc(subj["name"])}** \u2014 Score: {score:.1f}',
                                    unsafe_allow_html=True,
                                )
                                # Mini radar
                                try:
                                    detail = fetch_subject_detail(subj["id"])
                                    history = detail.get("assessment_history", [])
                                    if history:
                                        latest = history[0]
                                        labels = ["Grievance", "Fixation", "ID", "Aggression", "Energy", "Leakage", "Last Resort", "Direct"]
                                        keys = ["grievance_level", "fixation_level", "identification_level", "novel_aggression",
                                                "energy_burst", "leakage", "last_resort", "directly_communicated_threat"]
                                        vals = [float(latest.get(k, 0)) for k in keys]
                                        vals_c = vals + [vals[0]]
                                        labels_c = labels + [labels[0]]
                                        fig = go.Figure(go.Scatterpolar(
                                            r=vals_c, theta=labels_c, fill="toself",
                                            fillcolor="rgba(239,68,68,0.12)", line=dict(color="#ef4444", width=2),
                                        ))
                                        fig.update_layout(
                                            polar=dict(
                                                bgcolor=UI_PANEL_BG,
                                                radialaxis=dict(
                                                    visible=True,
                                                    range=[0, 1],
                                                    gridcolor=UI_GRID,
                                                    tickfont=dict(color=UI_TEXT_SECONDARY, size=8),
                                                ),
                                                angularaxis=dict(gridcolor=UI_GRID, tickfont=dict(color=UI_TEXT_SECONDARY, size=8)),
                                            ),
                                            showlegend=False, height=240,
                                            margin=dict(l=40, r=40, t=20, b=20), paper_bgcolor=UI_PANEL_BG,
                                        )
                                        st.plotly_chart(fig, use_container_width=True)
                                except requests.RequestException:
                                    pass
                        else:
                            _empty("No threat subjects linked to this protectee.")
                    except requests.RequestException:
                        _empty("Threat subjects unavailable.")

                # Right: Recent Activity
                with panel_activity:
                    st.markdown("**Recent Activity**")
                    try:
                        hits = fetch_poi_hits(poi_id)
                        if hits:
                            for h in hits[:8]:
                                sev = h.get("severity", "low")
                                st.markdown(
                                    f'{_sev_badge(sev)} '
                                    f'<span style="color:{UI_TEXT_PRIMARY};font-size:0.8rem;">{_esc(h.get("title", "")[:55])}</span>',
                                    unsafe_allow_html=True,
                                )
                        else:
                            _empty("No alert hits in the last 14 days.")
                    except requests.RequestException:
                        _empty("Hit data unavailable.")

                    # SITREPs
                    st.markdown("**SITREPs**")
                    try:
                        sitreps = fetch_sitreps()
                        poi_sitreps = [
                            s for s in sitreps if poi_id in _safe_id_set(s.get("affected_protectees", []))
                        ]
                        if poi_sitreps:
                            for sit in poi_sitreps[:3]:
                                tier = sit.get("escalation_tier", "")
                                st.markdown(
                                    f'{_tier_badge(tier) if tier else ""} '
                                    f'<span style="color:{UI_TEXT_PRIMARY};font-size:0.8rem;">{_esc(sit.get("title", "")[:50])}</span>',
                                    unsafe_allow_html=True,
                                )
                        else:
                            _empty("No SITREPs for this protectee.")
                    except requests.RequestException:
                        _empty("SITREP data unavailable.")

                    if st.button("\U0001F4DD Generate SITREP", key=f"gen_sitrep_{poi_id}"):
                        try:
                            sitrep = _post(f"/sitreps/generate/poi/{poi_id}")
                            st.success(f"SITREP: {sitrep.get('title', 'Generated')}")
                            st.cache_data.clear()
                            st.rerun()
                        except requests.RequestException as e:
                            st.warning(f"Could not generate: {e}")

                # Travel Security
                st.markdown("---")
                st.markdown("##### Travel Security")
                with st.form(f"travel_{poi_id}"):
                    tb1, tb2, tb3 = st.columns(3)
                    destination = tb1.text_input("Destination", key=f"dest_{poi_id}")
                    start_dt = tb2.date_input("Start", value=date.today(), key=f"start_{poi_id}")
                    end_dt = tb3.date_input("End", value=date.today(), key=f"end_{poi_id}")
                    if st.form_submit_button("Generate Travel Brief") and destination:
                        try:
                            brief = _post("/briefs/travel", payload={
                                "destination": destination,
                                "start_dt": start_dt.strftime("%Y-%m-%d"),
                                "end_dt": end_dt.strftime("%Y-%m-%d"),
                                "poi_id": poi_id,
                            })
                            st.success(f"Brief generated for {destination}")
                            st.markdown(brief.get("content_md", ""))
                        except requests.RequestException as e:
                            st.error(f"Error: {e}")
        else:
            _empty("No protectees configured. Add them in Administration or define in config/watchlist.yaml.", "\U0001F6E1")

    except requests.RequestException as e:
        st.error(f"Cannot load protectees: {e}")


# ============================================================
# TAB 4: INTELLIGENCE ANALYSIS
# ============================================================
with tabs[3]:
    st.markdown("##### Intelligence Analysis")

    # Keyword Spikes + Forecast
    col_spike, col_forecast = st.columns(2)

    with col_spike:
        st.markdown("**Keyword Frequency Spikes**")
        try:
            spikes = fetch_spikes(threshold=1.5)
            if spikes:
                spike_df = pd.DataFrame(spikes)
                fig = px.bar(spike_df, x="term", y="spike_ratio", color="today_count",
                             color_continuous_scale=[[0, "#1e3a5f"], [1, "#3b82f6"]],
                             labels={"term": "Keyword", "spike_ratio": "Spike Ratio", "today_count": "Today"})
                _style(fig, 320)
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(spike_df, use_container_width=True, hide_index=True)
            else:
                _empty("No keyword spikes above threshold. Needs 3+ days of scraping history.", "\U0001F4C8")
        except requests.RequestException:
            _empty("Spike data unavailable.", "\U0001F4C8")

    with col_forecast:
        st.markdown("**Keyword Trend & Forecast**")
        try:
            keywords = fetch_keywords()
            if keywords:
                kw_map = {k["term"]: k["id"] for k in keywords}
                selected_kw = st.selectbox("Keyword", list(kw_map.keys()), key="fc_kw")
                if selected_kw:
                    kw_id = kw_map[selected_kw]
                    try:
                        fc_data = _get(f"/analytics/forecast/keyword/{kw_id}", params={"horizon": 7})
                        history = fc_data.get("history", [])
                        forecast = fc_data.get("forecast", [])
                        method = fc_data.get("method", "unknown")
                        quality = fc_data.get("quality", {})

                        if history or forecast:
                            fig = go.Figure()
                            if history:
                                fig.add_trace(go.Scatter(
                                    x=[h["date"] for h in history], y=[h["count"] for h in history],
                                    mode="lines+markers", name="Historical", line=dict(color="#3b82f6", width=2),
                                    marker=dict(size=5),
                                ))
                            if forecast:
                                fig.add_trace(go.Scatter(
                                    x=[f["date"] for f in forecast], y=[f["yhat"] for f in forecast],
                                    mode="lines+markers", name="Forecast", line=dict(color="#f97316", width=2, dash="dash"),
                                    marker=dict(size=5),
                                ))
                                fig.add_trace(go.Scatter(
                                    x=[f["date"] for f in forecast] + [f["date"] for f in reversed(forecast)],
                                    y=[f["hi"] for f in forecast] + [f["lo"] for f in reversed(forecast)],
                                    fill="toself", fillcolor="rgba(249,115,22,0.08)",
                                    line=dict(width=0), name="95% CI",
                                ))
                            fig.update_layout(title=f"7-Day Forecast ({method})")
                            _style(fig, 300)
                            st.plotly_chart(fig, use_container_width=True)
                            smape = quality.get("smape")
                            if smape is not None:
                                st.caption(f"Model: {method} | sMAPE: {smape:.1f}% | Training: {quality.get('n_train_days', 0)}d")
                        else:
                            _empty("Insufficient data for forecasting.")
                    except requests.RequestException:
                        _empty("Forecasting requires historical frequency data.")
        except requests.RequestException:
            _empty("Keyword data unavailable.")

    st.markdown("---")

    # Link Analysis Graph
    st.markdown("**Link Analysis Network**")
    try:
        graph_data = fetch_graph_data(days=14, min_score=40, limit=200)
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if nodes:
            type_groups = {}
            for node in nodes[:60]:
                base_type = node["type"].split(":")[0]
                type_groups.setdefault(base_type, []).append(node)

            x_pos = {"source": 0, "keyword": 1, "ioc": 2, "entity": 2}
            type_colors = {"source": "#3b82f6", "keyword": "#f97316", "ioc": "#8b5cf6", "entity": "#22c55e"}
            positions = {}
            for ntype, group in type_groups.items():
                x = x_pos.get(ntype, 1.5)
                for i, node in enumerate(group):
                    jitter = (hash(node["id"]) % 100) / 300
                    y = i - len(group) / 2
                    positions[node["id"]] = (x + jitter, y)

            fig = go.Figure()
            edge_x, edge_y = [], []
            for edge in edges[:120]:
                src, tgt = edge["source"], edge["target"]
                if src in positions and tgt in positions:
                    x0, y0 = positions[src]
                    x1, y1 = positions[tgt]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
            if edge_x:
                fig.add_trace(go.Scatter(
                    x=edge_x, y=edge_y, mode="lines",
                    line=dict(width=0.4, color="rgba(59,130,246,0.15)"),
                    hoverinfo="none", showlegend=False,
                ))
            for ntype, group in type_groups.items():
                valid = [n for n in group if n["id"] in positions]
                if not valid:
                    continue
                fig.add_trace(go.Scatter(
                    x=[positions[n["id"]][0] for n in valid],
                    y=[positions[n["id"]][1] for n in valid],
                    mode="markers+text",
                    text=[n["label"] for n in valid], textposition="top center",
                    textfont=dict(size=9, color="#94a3b8"),
                    marker=dict(
                        size=[max(8, min(25, n["weight"] / 10)) for n in valid],
                        color=type_colors.get(ntype, "#64748b"),
                    ),
                    name=ntype.title(),
                ))
            fig.update_layout(
                height=500,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )
            _style(fig, 500)
            st.plotly_chart(fig, use_container_width=True)
            st.caption(f"{len(nodes)} nodes, {len(edges)} edges (top 60 nodes shown)")
        else:
            _empty("Link analysis requires scored alerts with extracted entities.", "\U0001F517")
    except requests.RequestException:
        _empty("Link analysis data unavailable.", "\U0001F517")

    st.markdown("---")

    # Source Credibility + Model Backtest
    col_cred, col_bt = st.columns(2)

    with col_cred:
        st.markdown("**Source Credibility (Bayesian)**")
        try:
            sources = fetch_sources()
            if sources:
                src_df = pd.DataFrame(sources)
                if "credibility_score" in src_df.columns:
                    src_df = src_df.sort_values("credibility_score", ascending=True)
                    fig = px.bar(
                        src_df, x="credibility_score", y="name", orientation="h",
                        color="credibility_score",
                        color_continuous_scale=[[0, "#ef4444"], [0.5, "#eab308"], [1, "#22c55e"]],
                        range_color=[0, 1],
                        labels={"credibility_score": "Credibility", "name": "Source"},
                    )
                    _style(fig, 320)
                    st.plotly_chart(fig, use_container_width=True)
        except requests.RequestException:
            _empty("Source data unavailable.")

    with col_bt:
        st.markdown("**Scoring Model Backtest**")
        try:
            backtest = _get("/analytics/backtest")
            if backtest and backtest.get("cases"):
                bt1, bt2, bt3 = st.columns(3)
                bt1.metric("Multi-factor", f"{backtest.get('multifactor_accuracy', 0):.1%}")
                bt2.metric("Naive Baseline", f"{backtest.get('naive_accuracy', 0):.1%}")
                bt3.metric("Improvement", f"{backtest.get('improvement', 0):.1%}")
                bt_df = pd.DataFrame(backtest["cases"])
                cols = [c for c in ["title", "expected_severity", "predicted_severity", "score", "correct"] if c in bt_df.columns]
                if cols:
                    st.dataframe(bt_df[cols], use_container_width=True, hide_index=True)
            else:
                _empty("Backtest requires golden dataset cases.")
        except requests.RequestException:
            _empty("Backtest data unavailable.")


# ============================================================
# TAB 5: ADMINISTRATION
# ============================================================
with tabs[4]:
    st.markdown("##### System Administration")

    admin1, admin2 = st.columns(2)

    # --- Keyword Management ---
    with admin1:
        st.markdown("**Keyword Management**")
        with st.form("add_keyword"):
            kc1, kc2 = st.columns(2)
            new_term = kc1.text_input("New Keyword")
            new_cat = kc2.selectbox("Category", ["protective_intel", "travel_risk", "protest_disruption", "insider_workplace", "general"])
            new_weight = st.slider("Threat Weight", 0.1, 5.0, 1.0, 0.1, key="kw_weight")
            if st.form_submit_button("Add Keyword") and new_term:
                try:
                    _post("/keywords", payload={"term": new_term, "category": new_cat, "weight": new_weight})
                    st.success(f"Added: {new_term}")
                    st.cache_data.clear()
                    st.rerun()
                except requests.RequestException:
                    st.error("Keyword exists or error occurred.")

        try:
            keywords = fetch_keywords()
            if keywords:
                kw_df = pd.DataFrame(keywords)
                cols = [c for c in ["id", "term", "category", "weight", "active"] if c in kw_df.columns]
                st.dataframe(kw_df[cols], use_container_width=True, hide_index=True)
        except requests.RequestException:
            st.caption("Keyword table unavailable.")

    # --- Protected Locations ---
    with admin2:
        st.markdown("**Protected Locations**")
        try:
            locations = fetch_locations()
            if locations:
                loc_df = pd.DataFrame(locations)
                cols = [c for c in ["name", "type", "lat", "lon", "radius_miles"] if c in loc_df.columns]
                st.dataframe(loc_df[cols], use_container_width=True, hide_index=True)
        except requests.RequestException:
            st.caption("Protected locations unavailable.")

        st.markdown("**Add Location**")
        with st.form("add_location"):
            lc1, lc2 = st.columns(2)
            loc_name = lc1.text_input("Name")
            loc_type = lc2.selectbox("Type", ["hq", "office", "residence", "venue", "other"])
            use_coords = st.checkbox("Provide Coordinates", value=False)
            lc3, lc4, lc5 = st.columns(3)
            loc_lat = lc3.number_input("Lat", value=0.0, format="%.6f", disabled=not use_coords)
            loc_lon = lc4.number_input("Lon", value=0.0, format="%.6f", disabled=not use_coords)
            loc_radius = lc5.slider("Radius (mi)", 1.0, 50.0, 5.0, 1.0)
            if st.form_submit_button("Add Location") and loc_name:
                try:
                    _post("/locations/protected", payload={
                        "name": loc_name, "type": loc_type,
                        "lat": loc_lat if use_coords else None,
                        "lon": loc_lon if use_coords else None,
                        "radius_miles": loc_radius,
                    })
                    st.success(f"Added: {loc_name}")
                    st.cache_data.clear()
                    st.rerun()
                except requests.RequestException as e:
                    st.error(f"Error: {e}")

    st.markdown("---")

    admin3, admin4 = st.columns(2)

    # --- Register Protectee ---
    with admin3:
        st.markdown("**Register New Protectee**")
        with st.form("add_poi"):
            pc1, pc2 = st.columns(2)
            poi_name = pc1.text_input("Name")
            poi_org = pc2.text_input("Organization")
            pc3, pc4 = st.columns(2)
            poi_role = pc3.text_input("Role")
            poi_sens = pc4.slider("Sensitivity", 1, 5, 3)
            poi_aliases = st.text_input("Aliases (comma-separated)")
            if st.form_submit_button("Register Protectee") and poi_name:
                alias_list = [a.strip() for a in poi_aliases.split(",") if a.strip()] if poi_aliases else []
                try:
                    _post("/pois", payload={"name": poi_name, "org": poi_org, "role": poi_role, "sensitivity": poi_sens, "aliases": alias_list})
                    st.success(f"Registered: {poi_name}")
                    st.cache_data.clear()
                    st.rerun()
                except requests.RequestException as e:
                    st.error(f"Error: {e}")

    # --- Register Threat Subject ---
    with admin4:
        st.markdown("**Register New Threat Subject**")
        with st.form("add_subject"):
            ts1, ts2 = st.columns(2)
            ts_name = ts1.text_input("Subject Name")
            ts_aliases = ts2.text_input("Aliases (comma-separated)")
            try:
                poi_list = fetch_pois()
                poi_opts = {"None": None}
                poi_opts.update({p["name"]: p["id"] for p in poi_list})
                linked_poi = st.selectbox("Link to Protectee", list(poi_opts.keys()))
            except requests.RequestException:
                linked_poi = "None"
                poi_opts = {"None": None}
            ts_notes = st.text_input("Notes")
            if st.form_submit_button("Register Subject") and ts_name:
                alias_list = [a.strip() for a in ts_aliases.split(",") if a.strip()] if ts_aliases else []
                try:
                    _post("/threat-subjects", payload={
                        "name": ts_name, "aliases": alias_list,
                        "linked_poi_id": poi_opts[linked_poi], "notes": ts_notes,
                    })
                    st.success(f"Registered: {ts_name}")
                    st.cache_data.clear()
                    st.rerun()
                except requests.RequestException as e:
                    st.error(f"Error: {e}")

    st.markdown("---")

    # --- Source Credibility + Escalation Tiers + Rescore ---
    admin5, admin6 = st.columns(2)

    with admin5:
        st.markdown("**Source Credibility**")
        try:
            sources = fetch_sources()
            if sources:
                for src in sources:
                    cred = src.get("credibility_score", 0.5)
                    tp = src.get("true_positives", 0)
                    fp = src.get("false_positives", 0)
                    bar_w = int(cred * 100)
                    bar_color = "#22c55e" if cred >= 0.7 else "#eab308" if cred >= 0.4 else "#ef4444"
                    st.markdown(
                        f'<div style="margin-bottom:6px;">'
                        f'<span style="color:{UI_TEXT_PRIMARY};font-size:0.82rem;font-weight:600;">{_esc(src["name"])}</span> '
                        f'<span style="color:{UI_TEXT_SECONDARY};font-size:0.72rem;">({_esc(src["source_type"])}) TP:{tp} FP:{fp}</span>'
                        f'<div style="background:#1e293b;border-radius:3px;height:6px;margin-top:3px;">'
                        f'<div style="background:{bar_color};width:{bar_w}%;height:100%;border-radius:3px;"></div>'
                        f'</div></div>',
                        unsafe_allow_html=True,
                    )
        except requests.RequestException:
            st.caption("Source credibility data unavailable.")

    with admin6:
        st.markdown("**Escalation Tiers**")
        try:
            tiers_data = fetch_escalation_tiers()
            for tier in tiers_data.get("tiers", []):
                label = tier["label"]
                notify = ", ".join(tier.get("notify", [])) or "\u2014"
                st.markdown(
                    f'{_tier_badge(label)} '
                    f'<span style="color:{UI_TEXT_SECONDARY};font-size:0.8rem;">'
                    f'Score {tier["threshold"]}+ \u2022 {_esc(tier.get("response_window", "N/A"))} \u2022 Notify: {_esc(notify)}'
                    f'</span>',
                    unsafe_allow_html=True,
                )
        except requests.RequestException:
            st.caption("Escalation tiers unavailable.")

        st.markdown("---")
        st.markdown("**Re-score Alerts**")
        st.markdown(
            f'<span style="color:{UI_TEXT_SECONDARY};font-size:0.82rem;">Recalculate ORS/TAS for all unreviewed alerts.</span>',
            unsafe_allow_html=True,
        )
        if st.button("\U0001F504 Re-score All Unreviewed"):
            try:
                result = _post("/alerts/rescore")
                st.success(f"Rescored {result['alerts_rescored']} alerts.")
                st.cache_data.clear()
            except requests.RequestException as e:
                st.error(f"Error: {e}")
