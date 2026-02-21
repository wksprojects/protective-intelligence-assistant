import json
import os
from datetime import date, datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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


def _style(fig, height=None):
    fig.update_layout(
        template="plotly_white",
        margin=dict(l=24, r=20, t=40, b=24),
        paper_bgcolor="white",
        plot_bgcolor="white",
        font=dict(family="Inter, system-ui, sans-serif"),
    )
    if height:
        fig.update_layout(height=height)
    return fig


# ---------------------------------------------------------------------------
# Page config & theme
# ---------------------------------------------------------------------------
st.set_page_config(page_title="Protective Intelligence Console", page_icon="PI", layout="wide")

SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#c2410c",
    "medium": "#b08900",
    "low": "#1d7a46",
}
SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
TIER_COLORS = {
    "CRITICAL": "#b42318",
    "ELEVATED": "#c2410c",
    "ROUTINE": "#b08900",
    "LOW": "#1d7a46",
}

st.markdown(
    """
<style>
:root {
    --bg: #f3f5f8; --panel: #ffffff; --ink: #0f172a; --muted: #475569;
    --line: #dbe2ea; --accent: #0f4c81;
}
.stApp {
    background:
        radial-gradient(circle at 8% 8%, #e7eef7 0%, transparent 35%),
        radial-gradient(circle at 92% 0%, #edf6f2 0%, transparent 30%),
        var(--bg);
    color: var(--ink);
}
.stApp p, .stApp span, .stApp label, .stApp div,
.stApp h1, .stApp h2, .stApp h3, .stApp h4 { color: var(--ink) !important; }
.stApp a { color: var(--accent) !important; }
.stTabs [data-baseweb="tab"] { color: var(--ink) !important; }
.stDataFrame * { color: var(--ink) !important; }
.stTextInput input, .stTextArea textarea,
.stSelectbox [data-baseweb="select"], .stSlider { color: var(--ink) !important; }
.ops-header {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 14px; padding: 18px 22px; margin-bottom: 14px;
}
.ops-kicker {
    color: var(--accent); font-size: 0.76rem; letter-spacing: 0.08em;
    text-transform: uppercase; font-weight: 600; margin-bottom: 6px;
}
.ops-title { color: var(--ink); font-size: 1.5rem; font-weight: 700; margin: 0; }
.ops-subtitle { color: var(--muted); margin-top: 6px; margin-bottom: 0; }
.tier-badge {
    display: inline-block; padding: 3px 10px; border-radius: 4px;
    font-weight: 700; font-size: 0.8rem; letter-spacing: 0.04em; color: white;
}
.tier-critical { background: #b42318; }
.tier-elevated { background: #c2410c; }
.tier-routine { background: #b08900; }
.tier-low { background: #1d7a46; }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<section class="ops-header">
  <div class="ops-kicker">Operations Console</div>
  <h1 class="ops-title">Protective Intelligence & Executive Protection</h1>
  <p class="ops-subtitle">Threat assessment, protectee monitoring, travel security, and escalation management.</p>
</section>
""",
    unsafe_allow_html=True,
)

# --- API health check ---
try:
    requests.get(f"{API_URL}/", headers=_hdrs(), timeout=3).raise_for_status()
except requests.RequestException:
    st.error("Cannot connect to API. Start the API server on port 8000.")
    st.stop()

# --- Tab layout ---
tabs = st.tabs([
    "Command Center",
    "Protectees",
    "Threat Subjects",
    "Daily Briefing",
    "Alert Queue",
    "Travel Security",
    "SITREPs",
    "Analytics",
    "Configuration",
])

# ============================================================
# TAB 1: COMMAND CENTER
# ============================================================
with tabs[0]:
    try:
        summary = _get("/alerts/summary", params={"include_demo": 0})
        st.caption(f"Updated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

        # KPI Row 1
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Total Alerts", summary["total_alerts"])
        k2.metric("Unreviewed", summary["unreviewed"])
        k3.metric("Critical", summary["by_severity"].get("critical", 0))
        k4.metric("High", summary["by_severity"].get("high", 0))

        # KPI Row 2
        k5, k6, k7, k8 = st.columns(4)
        k5.metric("Avg ORS", f"{summary.get('avg_risk_score', 0):.1f}")
        k6.metric("Active Spikes", summary.get("active_spikes", 0))
        try:
            pois_count = len(_get("/pois"))
            subjects_count = len(_get("/threat-subjects"))
        except Exception:
            pois_count = 0
            subjects_count = 0
        k7.metric("Active Protectees", pois_count)
        k8.metric("Threat Subjects", subjects_count)

        # Escalation Tiers
        st.markdown("#### Escalation Tiers")
        try:
            tiers_data = _get("/analytics/escalation-tiers")
            tier_list = tiers_data.get("tiers", [])
            tier_cols = st.columns(len(tier_list)) if tier_list else []
            for i, tier in enumerate(tier_list):
                label = tier["label"]
                css = f"tier-{label.lower()}"
                window = tier.get("response_window", "N/A")
                notify = ", ".join(tier.get("notify", [])) or "—"
                tier_cols[i].markdown(
                    f'<span class="tier-badge {css}">{label}</span><br>'
                    f'<small>Score {tier["threshold"]}+ | {window}<br>Notify: {notify}</small>',
                    unsafe_allow_html=True,
                )
        except Exception:
            pass

        st.divider()

        # Charts row
        c_left, c_mid, c_right = st.columns(3)
        with c_left:
            st.subheader("Severity Distribution")
            if summary["by_severity"]:
                sev_df = pd.DataFrame(
                    list(summary["by_severity"].items()), columns=["Severity", "Count"]
                )
                order = ["critical", "high", "medium", "low"]
                sev_df["Severity"] = pd.Categorical(
                    sev_df["Severity"], categories=order, ordered=True
                )
                sev_df = sev_df.sort_values("Severity")
                fig = px.bar(
                    sev_df, x="Severity", y="Count", color="Severity",
                    color_discrete_map=SEVERITY_COLORS,
                )
                fig.update_layout(showlegend=False)
                _style(fig, 300)
                st.plotly_chart(fig, use_container_width=True)

        with c_mid:
            st.subheader("Intelligence Sources")
            if summary["by_source"]:
                src_df = pd.DataFrame(
                    list(summary["by_source"].items()), columns=["Source", "Count"]
                )
                fig = px.pie(src_df, values="Count", names="Source", hole=0.4)
                _style(fig, 300)
                st.plotly_chart(fig, use_container_width=True)

        with c_right:
            st.subheader("Top Keywords")
            if summary["top_keywords"]:
                kw_df = pd.DataFrame(
                    list(summary["top_keywords"].items()), columns=["Keyword", "Count"]
                )
                kw_df = kw_df.sort_values("Count", ascending=True)
                fig = px.bar(kw_df, x="Count", y="Keyword", orientation="h")
                _style(fig, 300)
                st.plotly_chart(fig, use_container_width=True)

        # Geospatial Map
        st.subheader("Geospatial Overview")
        try:
            map_data = _get("/analytics/map", params={"days": 7, "min_ors": 40})
            locs = map_data.get("protected_locations", [])
            alert_pins = map_data.get("alerts", [])
            valid_locs = [loc for loc in locs if loc.get("lat") and loc.get("lon")]
            valid_alerts = [a for a in alert_pins if a.get("lat") and a.get("lon")]

            if valid_locs or valid_alerts:
                fig = go.Figure()
                if valid_locs:
                    fig.add_trace(go.Scattermapbox(
                        lat=[loc["lat"] for loc in valid_locs],
                        lon=[loc["lon"] for loc in valid_locs],
                        mode="markers+text",
                        marker=dict(size=14, color="#0f4c81", symbol="circle"),
                        text=[loc["name"] for loc in valid_locs],
                        textposition="top center",
                        name="Protected Sites",
                    ))
                if valid_alerts:
                    colors = [
                        SEVERITY_COLORS.get(a.get("severity", "low"), "#64748b")
                        for a in valid_alerts
                    ]
                    fig.add_trace(go.Scattermapbox(
                        lat=[a["lat"] for a in valid_alerts],
                        lon=[a["lon"] for a in valid_alerts],
                        mode="markers",
                        marker=dict(size=9, color=colors),
                        text=[
                            f"{a['title'][:60]} (ORS: {a.get('ors_score', 0):.0f})"
                            for a in valid_alerts
                        ],
                        name="Alert Locations",
                    ))
                all_lats = (
                    [loc["lat"] for loc in valid_locs]
                    + [a["lat"] for a in valid_alerts]
                )
                all_lons = (
                    [loc["lon"] for loc in valid_locs]
                    + [a["lon"] for a in valid_alerts]
                )
                center_lat = sum(all_lats) / len(all_lats)
                center_lon = sum(all_lons) / len(all_lons)
                fig.update_layout(
                    mapbox=dict(
                        style="open-street-map",
                        center=dict(lat=center_lat, lon=center_lon),
                        zoom=3,
                    ),
                    height=400,
                    margin=dict(l=0, r=0, t=0, b=0),
                    showlegend=True,
                    legend=dict(x=0, y=1),
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(
                    "No geospatial data available. Protected locations and "
                    "geocoded alerts will appear here once ingested."
                )
        except Exception:
            st.info("Geospatial data will appear once alerts with locations are ingested.")

        # Risk Score Distribution
        st.subheader("Risk Score Distribution")
        alerts_dist = _get("/alerts", params={"limit": 500, "include_demo": 0})
        if alerts_dist:
            scores = [a["risk_score"] for a in alerts_dist if a.get("risk_score")]
            if scores:
                fig = px.histogram(
                    x=scores, nbins=20,
                    labels={"x": "ORS", "y": "Count"},
                    color_discrete_sequence=["#0f4c81"],
                )
                fig.update_layout(
                    xaxis_title="Operational Risk Score",
                    yaxis_title="Alert Count",
                )
                _style(fig, 280)
                st.plotly_chart(fig, use_container_width=True)

    except requests.RequestException as e:
        st.error(f"Cannot load overview: {e}")


# ============================================================
# TAB 2: PROTECTEES
# ============================================================
with tabs[1]:
    st.subheader("Protectee Management")

    try:
        pois = _get("/pois")
        if pois:
            for poi in pois:
                sensitivity = min(poi.get("sensitivity", 3), 5)
                sens_labels = ["", "LOW", "GUARDED", "ELEVATED", "HIGH", "CRITICAL"]
                sens_label = sens_labels[sensitivity]
                aliases = [a["alias"] for a in poi.get("aliases", [])]

                with st.expander(
                    f"**{poi['name']}** -- {poi.get('org', 'N/A')} | "
                    f"{poi.get('role', 'N/A')} | Sensitivity: {sens_label}"
                ):
                    mc1, mc2, mc3 = st.columns(3)
                    mc1.write(f"**Organization:** {poi.get('org', 'N/A')}")
                    mc2.write(f"**Role:** {poi.get('role', 'N/A')}")
                    mc3.write(f"**Aliases:** {', '.join(aliases) if aliases else 'None'}")

                    # TAS Assessment
                    st.markdown("**Threat Assessment (TAS)**")
                    try:
                        assessment = _get(
                            f"/pois/{poi['id']}/assessment",
                            params={"window_days": 14},
                        )
                        if assessment and assessment.get("tas_score") is not None:
                            tas = assessment["tas_score"]
                            ac1, ac2, ac3, ac4, ac5 = st.columns(5)
                            ac1.metric("TAS Score", f"{tas:.1f}")
                            ac2.metric(
                                "Fixation",
                                "YES" if assessment.get("fixation") else "no",
                            )
                            ac3.metric(
                                "Energy Burst",
                                "YES" if assessment.get("energy_burst") else "no",
                            )
                            ac4.metric(
                                "Leakage",
                                "YES" if assessment.get("leakage") else "no",
                            )
                            ac5.metric(
                                "Pathway",
                                "YES" if assessment.get("pathway") else "no",
                            )

                            esc = assessment.get("escalation", {})
                            if esc and esc.get("tier"):
                                tier = esc["tier"]
                                css = f"tier-{tier.lower()}"
                                st.markdown(
                                    f'<span class="tier-badge {css}">{tier}</span> '
                                    f'{esc.get("reason", "")}',
                                    unsafe_allow_html=True,
                                )
                                actions = esc.get("recommended_actions", [])
                                if actions:
                                    for action in actions:
                                        st.write(f"- {action}")
                        else:
                            st.info(
                                "No assessment data. Alerts must be ingested and "
                                "matched to this protectee."
                            )
                    except Exception:
                        st.info("No assessment available.")

                    # Recent Hits
                    st.markdown("**Recent Alert Hits (14 days)**")
                    try:
                        hits = _get(
                            f"/pois/{poi['id']}/hits", params={"days": 14}
                        )
                        if hits:
                            hits_df = pd.DataFrame(hits)
                            cols = [
                                c
                                for c in [
                                    "title", "severity", "ors_score",
                                    "match_value", "timestamp",
                                ]
                                if c in hits_df.columns
                            ]
                            st.dataframe(
                                hits_df[cols],
                                use_container_width=True,
                                hide_index=True,
                            )
                        else:
                            st.info("No alert hits in the last 14 days.")
                    except Exception:
                        st.info("No hit data available.")

                    # Generate SITREP
                    if st.button(
                        "Generate SITREP", key=f"sitrep_poi_{poi['id']}"
                    ):
                        try:
                            sitrep = _post(
                                f"/sitreps/generate/poi/{poi['id']}"
                            )
                            st.success(
                                f"SITREP generated: {sitrep.get('title', 'N/A')}"
                            )
                        except Exception as e:
                            st.warning(f"Could not generate SITREP: {e}")
        else:
            st.info(
                "No protectees configured. Add one below or define in "
                "config/watchlist.yaml."
            )

        # Add POI form
        st.divider()
        st.markdown("#### Register New Protectee")
        with st.form("add_poi"):
            pc1, pc2, pc3, pc4 = st.columns(4)
            poi_name = pc1.text_input("Name")
            poi_org = pc2.text_input("Organization")
            poi_role = pc3.text_input("Role")
            poi_sens = pc4.slider("Sensitivity", 1, 5, 3)
            poi_aliases = st.text_input("Aliases (comma-separated)")
            if st.form_submit_button("Register Protectee") and poi_name:
                alias_list = (
                    [a.strip() for a in poi_aliases.split(",") if a.strip()]
                    if poi_aliases
                    else []
                )
                try:
                    _post(
                        "/pois",
                        payload={
                            "name": poi_name,
                            "org": poi_org,
                            "role": poi_role,
                            "sensitivity": poi_sens,
                            "aliases": alias_list,
                        },
                    )
                    st.success(f"Registered: {poi_name}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

    except requests.RequestException as e:
        st.error(f"Cannot load protectee data: {e}")


# ============================================================
# TAB 3: THREAT SUBJECTS
# ============================================================
with tabs[2]:
    st.subheader("Behavioral Threat Assessment")
    st.caption(
        "Pathway-to-violence model with 8 weighted indicators tracking "
        "escalation risk over time."
    )

    try:
        subjects = _get("/threat-subjects")

        if subjects:
            for subj in subjects:
                score = subj.get("latest_pathway_score") or 0
                tier = subj.get("risk_tier", "LOW")
                trend = subj.get("latest_trend", "stable")
                css = f"tier-{tier.lower()}"

                with st.expander(
                    f"**{subj['name']}** | Score: {score:.1f} | {tier} | "
                    f"Trend: {trend}"
                ):
                    sc1, sc2, sc3, sc4 = st.columns(4)
                    sc1.metric("Pathway Score", f"{score:.1f}")
                    sc2.markdown(
                        f'<span class="tier-badge {css}">{tier}</span>',
                        unsafe_allow_html=True,
                    )
                    sc3.write(f"**Trend:** {trend}")
                    linked = subj.get("linked_poi_id")
                    sc4.write(f"**Linked POI ID:** {linked or 'None'}")

                    # Assessment detail
                    try:
                        detail = _get(f"/threat-subjects/{subj['id']}")
                        history = detail.get("assessment_history", [])
                        if history:
                            latest = history[0]
                            indicators = [
                                "Grievance", "Fixation", "Identification",
                                "Novel Aggression", "Energy Burst", "Leakage",
                                "Last Resort", "Direct Threat",
                            ]
                            indicator_keys = [
                                "grievance_level", "fixation_level",
                                "identification_level", "novel_aggression",
                                "energy_burst", "leakage", "last_resort",
                                "directly_communicated_threat",
                            ]
                            values = [
                                float(latest.get(k, 0)) for k in indicator_keys
                            ]
                            values_closed = values + [values[0]]
                            indicators_closed = indicators + [indicators[0]]

                            radar_col, trend_col = st.columns(2)
                            with radar_col:
                                fig = go.Figure()
                                fig.add_trace(
                                    go.Scatterpolar(
                                        r=values_closed,
                                        theta=indicators_closed,
                                        fill="toself",
                                        fillcolor="rgba(180, 35, 24, 0.15)",
                                        line=dict(color="#b42318", width=2),
                                        name="Current",
                                    )
                                )
                                fig.update_layout(
                                    polar=dict(
                                        radialaxis=dict(
                                            visible=True, range=[0, 1]
                                        ),
                                        bgcolor="white",
                                    ),
                                    showlegend=False,
                                    title="Behavioral Indicator Profile",
                                    height=380,
                                    margin=dict(l=60, r=60, t=50, b=40),
                                )
                                st.plotly_chart(fig, use_container_width=True)

                            with trend_col:
                                if len(history) > 1:
                                    hist_df = pd.DataFrame(history)
                                    hist_df = hist_df.sort_values(
                                        "assessment_date"
                                    )
                                    fig = px.line(
                                        hist_df,
                                        x="assessment_date",
                                        y="pathway_score",
                                        title="Pathway Score Trend",
                                        markers=True,
                                    )
                                    fig.add_hline(
                                        y=75, line_dash="dash",
                                        line_color="#b42318",
                                        annotation_text="CRITICAL",
                                    )
                                    fig.add_hline(
                                        y=50, line_dash="dash",
                                        line_color="#c2410c",
                                        annotation_text="ELEVATED",
                                    )
                                    fig.add_hline(
                                        y=25, line_dash="dash",
                                        line_color="#b08900",
                                        annotation_text="ROUTINE",
                                    )
                                    _style(fig, 380)
                                    st.plotly_chart(
                                        fig, use_container_width=True
                                    )
                                else:
                                    st.info(
                                        "Submit additional assessments to "
                                        "view the trend chart."
                                    )

                            if latest.get("evidence_summary"):
                                st.markdown(
                                    f"**Evidence:** {latest['evidence_summary']}"
                                )
                            if latest.get("analyst_notes"):
                                st.markdown(
                                    f"**Analyst Notes:** "
                                    f"{latest['analyst_notes']}"
                                )
                    except Exception:
                        pass

                    # Assessment form
                    st.markdown("**Submit New Assessment**")
                    with st.form(f"assess_{subj['id']}"):
                        f1, f2, f3, f4 = st.columns(4)
                        grievance = f1.slider(
                            "Grievance", 0.0, 1.0, 0.0, 0.05,
                            key=f"g_{subj['id']}",
                        )
                        fixation = f2.slider(
                            "Fixation", 0.0, 1.0, 0.0, 0.05,
                            key=f"f_{subj['id']}",
                        )
                        identification = f3.slider(
                            "Identification", 0.0, 1.0, 0.0, 0.05,
                            key=f"i_{subj['id']}",
                        )
                        novel_agg = f4.slider(
                            "Novel Aggression", 0.0, 1.0, 0.0, 0.05,
                            key=f"n_{subj['id']}",
                        )
                        f5, f6, f7, f8 = st.columns(4)
                        energy = f5.slider(
                            "Energy Burst", 0.0, 1.0, 0.0, 0.05,
                            key=f"e_{subj['id']}",
                        )
                        leak = f6.slider(
                            "Leakage", 0.0, 1.0, 0.0, 0.05,
                            key=f"l_{subj['id']}",
                        )
                        last_resort = f7.slider(
                            "Last Resort", 0.0, 1.0, 0.0, 0.05,
                            key=f"lr_{subj['id']}",
                        )
                        direct_threat = f8.slider(
                            "Direct Threat", 0.0, 1.0, 0.0, 0.05,
                            key=f"d_{subj['id']}",
                        )
                        evidence = st.text_area(
                            "Evidence Summary", key=f"ev_{subj['id']}"
                        )
                        notes = st.text_input(
                            "Analyst Notes", key=f"an_{subj['id']}"
                        )

                        if st.form_submit_button("Submit Assessment"):
                            try:
                                result = _post(
                                    f"/threat-subjects/{subj['id']}/assess",
                                    payload={
                                        "grievance_level": grievance,
                                        "fixation_level": fixation,
                                        "identification_level": identification,
                                        "novel_aggression": novel_agg,
                                        "energy_burst": energy,
                                        "leakage": leak,
                                        "last_resort": last_resort,
                                        "directly_communicated_threat": direct_threat,
                                        "evidence_summary": evidence,
                                        "analyst_notes": notes,
                                    },
                                )
                                st.success(
                                    f"Assessment saved. Score: "
                                    f"{result['pathway_score']:.1f} "
                                    f"({result['risk_tier']}) -- "
                                    f"Trend: {result['escalation_trend']}"
                                )
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error: {e}")
        else:
            st.info("No threat subjects registered. Add one below.")

        # Register new subject
        st.divider()
        st.markdown("#### Register New Threat Subject")
        with st.form("add_subject"):
            ts1, ts2 = st.columns(2)
            ts_name = ts1.text_input("Subject Name")
            ts_aliases = ts2.text_input("Aliases (comma-separated)")
            ts3, ts4 = st.columns(2)
            try:
                poi_list = _get("/pois")
                poi_opts = {"None": None}
                poi_opts.update({p["name"]: p["id"] for p in poi_list})
                linked_poi = ts3.selectbox(
                    "Link to Protectee", list(poi_opts.keys())
                )
            except Exception:
                linked_poi = "None"
                poi_opts = {"None": None}
            ts_notes = ts4.text_input("Notes")

            if st.form_submit_button("Register Subject") and ts_name:
                alias_list = (
                    [a.strip() for a in ts_aliases.split(",") if a.strip()]
                    if ts_aliases
                    else []
                )
                try:
                    _post(
                        "/threat-subjects",
                        payload={
                            "name": ts_name,
                            "aliases": alias_list,
                            "linked_poi_id": poi_opts[linked_poi],
                            "notes": ts_notes,
                        },
                    )
                    st.success(f"Registered: {ts_name}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")

    except requests.RequestException as e:
        st.error(f"Cannot load threat subjects: {e}")


# ============================================================
# TAB 4: DAILY BRIEFING
# ============================================================
with tabs[3]:
    st.subheader("Daily Intelligence Briefing")
    report_date = st.date_input("Report Date", value=date.today())

    try:
        report = _get(
            "/intelligence/daily",
            params={
                "date": report_date.strftime("%Y-%m-%d"),
                "include_demo": 0,
            },
        )

        st.markdown("### Executive Summary")
        st.info(report.get("executive_summary", "No data available for this date."))

        stats = report.get("stats", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total", stats.get("total_alerts", 0))
        c2.metric("Critical", stats.get("critical_count", 0))
        c3.metric("High", stats.get("high_count", 0))
        c4.metric("Medium", stats.get("medium_count", 0))

        st.divider()

        # Escalation Recommendations
        escalations = report.get("escalation_recommendations", [])
        st.markdown("### Escalation Recommendations")
        if escalations:
            for esc in escalations:
                priority = esc.get("priority", "MEDIUM")
                if priority == "IMMEDIATE":
                    st.error(f"**[{priority}]** {esc.get('action', '')}")
                elif priority == "HIGH":
                    st.warning(f"**[{priority}]** {esc.get('action', '')}")
                else:
                    st.info(f"**[{priority}]** {esc.get('action', '')}")
        else:
            st.success("No escalation items at this time.")

        st.divider()

        # Top Risks
        top_risks = report.get("top_risks", [])
        st.markdown("### Top Risks")
        if top_risks:
            risk_df = pd.DataFrame(top_risks)
            cols = [
                c
                for c in ["title", "risk_score", "severity", "source_name", "keyword"]
                if c in risk_df.columns
            ]
            if cols:
                st.dataframe(
                    risk_df[cols].rename(
                        columns={
                            "title": "Title",
                            "risk_score": "ORS",
                            "severity": "Severity",
                            "source_name": "Source",
                            "keyword": "Keyword",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
        else:
            st.info("No alerts found for this date.")

        st.divider()

        # Emerging Themes
        themes = report.get("emerging_themes", [])
        st.markdown("### Emerging Themes (Frequency Spikes)")
        if themes:
            themes_df = pd.DataFrame(themes)
            fig = px.bar(
                themes_df, x="term", y="spike_ratio",
                color="spike_ratio", color_continuous_scale="Blues",
                labels={"term": "Keyword", "spike_ratio": "Spike Ratio (vs 7d avg)"},
            )
            _style(fig, 350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info(
                "No keyword spikes detected. Spike detection requires "
                "3+ days of scraping data."
            )

    except requests.RequestException as e:
        st.error(f"Cannot connect to API: {e}")
    except Exception as e:
        st.error(f"Error generating report: {e}")


# ============================================================
# TAB 5: ALERT QUEUE
# ============================================================
with tabs[4]:
    st.subheader("Alert Queue")

    fc1, fc2, fc3 = st.columns(3)
    severity_filter = fc1.selectbox(
        "Severity", ["All", "critical", "high", "medium", "low"]
    )
    review_filter = fc2.selectbox("Status", ["All", "Unreviewed", "Reviewed"])
    min_score = fc3.slider("Min ORS", 0.0, 100.0, 0.0, 5.0)

    params = {"limit": 100, "sort_by": "risk_score", "include_demo": 0}
    if severity_filter != "All":
        params["severity"] = severity_filter
    if review_filter == "Unreviewed":
        params["reviewed"] = 0
    elif review_filter == "Reviewed":
        params["reviewed"] = 1
    if min_score > 0:
        params["min_score"] = min_score

    try:
        alerts = _get("/alerts", params=params)

        if alerts:
            for alert in alerts:
                sev = alert["severity"]
                tag = SEVERITY_LABELS.get(sev, sev.upper())
                reviewed = "REVIEWED" if alert["reviewed"] else "OPEN"
                ors = alert.get("ors_score") or alert.get("risk_score") or 0
                tas = alert.get("tas_score") or 0

                with st.expander(
                    f"[{tag} ORS:{ors:.0f}] "
                    f"{alert['title'][:100]} ({reviewed})"
                ):
                    m1, m2, m3, m4, m5 = st.columns(5)
                    m1.metric("ORS", f"{ors:.1f}")
                    m2.metric("TAS", f"{tas:.1f}")
                    m3.write(
                        f"**Source:** {alert.get('source_name', 'Unknown')}"
                    )
                    m4.write(
                        f"**Keyword:** {alert.get('matched_term', 'N/A')}"
                    )
                    m5.write(f"**Time:** {alert['created_at']}")

                    if alert.get("url"):
                        st.write(f"**URL:** {alert['url']}")
                    if alert.get("content"):
                        st.write(f"**Content:** {alert['content'][:500]}...")

                    # Score breakdown with uncertainty
                    try:
                        score_data = _get(
                            f"/alerts/{alert['id']}/score",
                            params={"uncertainty": 1, "n": 500},
                        )
                        if "keyword_weight" in score_data:
                            st.markdown("**Score Decomposition:**")
                            s1, s2, s3, s4, s5, s6 = st.columns(6)
                            s1.metric(
                                "Keyword Wt",
                                f"{score_data['keyword_weight']:.1f}",
                            )
                            s2.metric(
                                "Credibility",
                                f"{score_data['source_credibility']:.2f}",
                            )
                            s3.metric(
                                "Frequency",
                                f"{score_data['frequency_factor']:.1f}x",
                            )
                            s4.metric(
                                "Recency",
                                f"{score_data['recency_factor']:.2f}",
                            )
                            s5.metric(
                                "Proximity",
                                f"{score_data.get('proximity_factor', 0):.2f}",
                            )
                            s6.metric(
                                "POI Factor",
                                f"{score_data.get('poi_factor', 0):.2f}",
                            )

                            unc = score_data.get("uncertainty")
                            if unc:
                                st.markdown(
                                    f"**Monte Carlo Interval** (n="
                                    f"{unc.get('n', 500)}): "
                                    f"Mean={unc.get('mean', 0):.1f} | "
                                    f"P5={unc.get('p5', 0):.1f} | "
                                    f"P95={unc.get('p95', 0):.1f} | "
                                    f"Std={unc.get('std', 0):.2f}"
                                )
                    except Exception:
                        pass

                    # Action buttons
                    btn1, btn2, btn3 = st.columns(3)
                    if not alert["reviewed"]:
                        if btn1.button(
                            "Mark Reviewed", key=f"rev_{alert['id']}"
                        ):
                            _patch(f"/alerts/{alert['id']}/review")
                            st.rerun()
                        if btn2.button(
                            "True Positive", key=f"tp_{alert['id']}"
                        ):
                            _patch(
                                f"/alerts/{alert['id']}/classify",
                                payload={
                                    "classification": "true_positive"
                                },
                            )
                            st.success(
                                "Classified as TP. Source credibility updated."
                            )
                            st.rerun()
                        if btn3.button(
                            "False Positive", key=f"fp_{alert['id']}"
                        ):
                            _patch(
                                f"/alerts/{alert['id']}/classify",
                                payload={
                                    "classification": "false_positive"
                                },
                            )
                            st.success(
                                "Classified as FP. Source credibility updated."
                            )
                            st.rerun()
        else:
            st.info("No alerts match your filters.")

    except requests.RequestException as e:
        st.error(f"Cannot load alerts: {e}")


# ============================================================
# TAB 6: TRAVEL SECURITY
# ============================================================
with tabs[5]:
    st.subheader("Travel Security Briefings")

    st.markdown("#### Generate Travel Brief")
    with st.form("travel_brief"):
        tb1, tb2, tb3 = st.columns(3)
        destination = tb1.text_input("Destination (city, country)")
        start_dt = tb2.date_input("Start Date", value=date.today())
        end_dt = tb3.date_input("End Date", value=date.today())

        tb4, tb5 = st.columns(2)
        try:
            poi_list = _get("/pois")
            poi_opts = {"None": None}
            poi_opts.update({p["name"]: p["id"] for p in poi_list})
            travel_poi = tb4.selectbox(
                "Linked Protectee", list(poi_opts.keys())
            )
        except Exception:
            travel_poi = "None"
            poi_opts = {"None": None}
        try:
            loc_list = _get("/locations/protected")
            loc_opts = {"None": None}
            loc_opts.update({loc["name"]: loc["id"] for loc in loc_list})
            travel_loc = tb5.selectbox(
                "Linked Facility", list(loc_opts.keys())
            )
        except Exception:
            travel_loc = "None"
            loc_opts = {"None": None}

        if st.form_submit_button("Generate Brief") and destination:
            try:
                brief = _post(
                    "/briefs/travel",
                    payload={
                        "destination": destination,
                        "start_dt": start_dt.strftime("%Y-%m-%d"),
                        "end_dt": end_dt.strftime("%Y-%m-%d"),
                        "poi_id": poi_opts.get(travel_poi),
                        "protected_location_id": loc_opts.get(travel_loc),
                    },
                )
                st.success(f"Travel brief generated for {destination}.")
                st.markdown("---")
                st.markdown(brief.get("content_md", "No content generated."))
            except Exception as e:
                st.error(f"Error generating brief: {e}")

    st.divider()

    st.markdown("#### Previous Briefs")
    try:
        briefs = _get("/briefs/travel", params={"limit": 20})
        if briefs:
            for brief in briefs:
                st.write(
                    f"**{brief['destination']}** | "
                    f"{brief['start_dt']} to {brief['end_dt']} | "
                    f"Generated: {brief['created_at']}"
                )
        else:
            st.info("No travel briefs generated yet.")
    except Exception:
        pass


# ============================================================
# TAB 7: SITREPs
# ============================================================
with tabs[6]:
    st.subheader("Situation Reports")

    sitrep_status = st.selectbox(
        "Filter by Status", ["All", "draft", "issued"]
    )

    try:
        sitrep_params = {"limit": 20}
        if sitrep_status != "All":
            sitrep_params["status"] = sitrep_status
        sitreps = _get("/sitreps", params=sitrep_params)

        if sitreps:
            for sit in sitreps:
                status_tag = (
                    "[DRAFT]"
                    if sit.get("status") == "draft"
                    else "[ISSUED]"
                )
                tier = sit.get("escalation_tier", "N/A")
                with st.expander(
                    f"{status_tag} [{sit.get('severity', 'N/A').upper()}] "
                    f"{sit.get('title', 'Untitled')}"
                ):
                    try:
                        detail = _get(f"/sitreps/{sit['id']}")
                        dc1, dc2, dc3 = st.columns(3)
                        dc1.write(
                            f"**Trigger:** {detail.get('trigger_type', 'N/A')}"
                        )
                        dc2.write(
                            f"**Severity:** "
                            f"{detail.get('severity', 'N/A').upper()}"
                        )
                        if tier in TIER_COLORS:
                            css = f"tier-{tier.lower()}"
                            dc3.markdown(
                                f'**Tier:** '
                                f'<span class="tier-badge {css}">{tier}</span>',
                                unsafe_allow_html=True,
                            )

                        if detail.get("situation_summary"):
                            st.markdown(
                                f"**Situation:** "
                                f"{detail['situation_summary']}"
                            )
                        if detail.get("threat_assessment"):
                            st.markdown(
                                f"**Assessment:** "
                                f"{detail['threat_assessment']}"
                            )

                        protectees = detail.get("affected_protectees", [])
                        if protectees and isinstance(protectees, list):
                            st.write(
                                f"**Affected Protectees:** "
                                f"{', '.join(str(p) for p in protectees)}"
                            )

                        locations = detail.get("affected_locations", [])
                        if locations and isinstance(locations, list):
                            st.write(
                                f"**Affected Locations:** "
                                f"{', '.join(str(loc) for loc in locations)}"
                            )

                        actions = detail.get("recommended_actions", [])
                        if actions and isinstance(actions, list):
                            st.markdown("**Recommended Actions:**")
                            for action in actions:
                                st.write(f"- {action}")

                        notify = detail.get("escalation_notify", [])
                        if notify and isinstance(notify, list):
                            st.write(
                                f"**Notify:** "
                                f"{', '.join(str(n) for n in notify)}"
                            )

                        if detail.get("status") == "draft":
                            if st.button(
                                "Issue SITREP", key=f"issue_{sit['id']}"
                            ):
                                _patch(f"/sitreps/{sit['id']}/issue")
                                st.success("SITREP issued.")
                                st.rerun()
                    except Exception as e:
                        st.error(f"Cannot load detail: {e}")
        else:
            st.info(
                "No SITREPs generated yet. Generate them from the "
                "Protectees tab or via API."
            )

    except requests.RequestException as e:
        st.error(f"Cannot load SITREPs: {e}")


# ============================================================
# TAB 8: ANALYTICS
# ============================================================
with tabs[7]:
    st.subheader("Intelligence Analytics")

    # Keyword Spikes
    st.markdown("### Keyword Frequency Spikes")
    try:
        spikes = _get("/analytics/spikes", params={"threshold": 1.5})
        if spikes:
            spike_df = pd.DataFrame(spikes)
            fig = px.bar(
                spike_df, x="term", y="spike_ratio",
                color="today_count", color_continuous_scale="Blues",
                labels={
                    "term": "Keyword",
                    "spike_ratio": "Spike Ratio",
                    "today_count": "Today",
                },
                title="Active Keyword Spikes (vs 7-day average)",
            )
            _style(fig, 350)
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(spike_df, use_container_width=True, hide_index=True)
        else:
            st.info(
                "No keyword spikes above threshold. "
                "Requires 3+ days of scraping history."
            )
    except Exception:
        pass

    st.divider()

    # Keyword Trend + Forecast
    st.markdown("### Keyword Trend & Forecast")
    try:
        keywords = _get("/keywords")
        if keywords:
            kw_map = {k["term"]: k["id"] for k in keywords}
            selected_kw = st.selectbox(
                "Select Keyword", list(kw_map.keys())
            )
            if selected_kw:
                kw_id = kw_map[selected_kw]
                trend_col, forecast_col = st.columns(2)

                with trend_col:
                    trend = _get(
                        f"/analytics/keyword-trend/{kw_id}",
                        params={"days": 14},
                    )
                    if trend:
                        trend_df = pd.DataFrame(trend)
                        fig = px.line(
                            trend_df, x="date", y="count",
                            title=f"14-Day Frequency: {selected_kw}",
                            markers=True,
                        )
                        _style(fig, 320)
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info(
                            "No frequency data. Run the scraper to populate."
                        )

                with forecast_col:
                    try:
                        fc_data = _get(
                            f"/analytics/forecast/keyword/{kw_id}",
                            params={"horizon": 7},
                        )
                        history = fc_data.get("history", [])
                        forecast = fc_data.get("forecast", [])
                        method = fc_data.get("method", "unknown")
                        quality = fc_data.get("quality", {})

                        if history or forecast:
                            fig = go.Figure()
                            if history:
                                fig.add_trace(
                                    go.Scatter(
                                        x=[h["date"] for h in history],
                                        y=[h["count"] for h in history],
                                        mode="lines+markers",
                                        name="Historical",
                                        line=dict(color="#0f4c81"),
                                    )
                                )
                            if forecast:
                                fig.add_trace(
                                    go.Scatter(
                                        x=[f["date"] for f in forecast],
                                        y=[f["yhat"] for f in forecast],
                                        mode="lines+markers",
                                        name="Forecast",
                                        line=dict(
                                            color="#c2410c", dash="dash"
                                        ),
                                    )
                                )
                                fig.add_trace(
                                    go.Scatter(
                                        x=(
                                            [f["date"] for f in forecast]
                                            + [
                                                f["date"]
                                                for f in reversed(forecast)
                                            ]
                                        ),
                                        y=(
                                            [f["hi"] for f in forecast]
                                            + [
                                                f["lo"]
                                                for f in reversed(forecast)
                                            ]
                                        ),
                                        fill="toself",
                                        fillcolor="rgba(194, 65, 12, 0.1)",
                                        line=dict(width=0),
                                        name="95% CI",
                                    )
                                )
                            fig.update_layout(
                                title=f"7-Day Forecast ({method})"
                            )
                            _style(fig, 320)
                            st.plotly_chart(fig, use_container_width=True)

                            smape = quality.get("smape")
                            if smape is not None:
                                st.caption(
                                    f"Model: {method} | "
                                    f"sMAPE: {smape:.1f}% | "
                                    f"Training: "
                                    f"{quality.get('n_train_days', 0)}d"
                                )
                        else:
                            st.info("Insufficient data for forecasting.")
                    except Exception:
                        st.info("Forecasting requires historical data.")
    except Exception:
        pass

    st.divider()

    # Link Analysis Graph
    st.markdown("### Link Analysis Graph")
    try:
        graph_data = _get(
            "/analytics/graph",
            params={"days": 7, "min_score": 60, "limit_alerts": 200},
        )
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if nodes:
            # Group by type and assign positions (column layout)
            type_groups = {}
            for node in nodes[:50]:
                base_type = node["type"].split(":")[0]
                type_groups.setdefault(base_type, []).append(node)

            x_pos = {
                "source": 0, "keyword": 1, "ioc": 2, "entity": 2,
            }
            type_colors = {
                "source": "#0f4c81", "keyword": "#c2410c",
                "ioc": "#6b21a8", "entity": "#1d7a46",
            }
            positions = {}
            for ntype, group in type_groups.items():
                x = x_pos.get(ntype, 1.5)
                for i, node in enumerate(group):
                    jitter = (hash(node["id"]) % 100) / 300
                    y = i - len(group) / 2
                    positions[node["id"]] = (x + jitter, y)

            fig = go.Figure()

            # Edges
            edge_x, edge_y = [], []
            for edge in edges[:100]:
                src = edge["source"]
                tgt = edge["target"]
                if src in positions and tgt in positions:
                    x0, y0 = positions[src]
                    x1, y1 = positions[tgt]
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
            if edge_x:
                fig.add_trace(
                    go.Scatter(
                        x=edge_x, y=edge_y, mode="lines",
                        line=dict(width=0.5, color="#cbd5e1"),
                        hoverinfo="none", showlegend=False,
                    )
                )

            # Nodes
            for ntype, group in type_groups.items():
                valid = [n for n in group if n["id"] in positions]
                xs = [positions[n["id"]][0] for n in valid]
                ys = [positions[n["id"]][1] for n in valid]
                labels = [n["label"] for n in valid]
                sizes = [
                    max(8, min(25, n["weight"] / 10)) for n in valid
                ]
                fig.add_trace(
                    go.Scatter(
                        x=xs, y=ys, mode="markers+text",
                        text=labels, textposition="top center",
                        textfont=dict(size=9),
                        marker=dict(
                            size=sizes,
                            color=type_colors.get(ntype, "#64748b"),
                        ),
                        name=ntype.title(),
                    )
                )

            fig.update_layout(
                height=500,
                xaxis=dict(
                    showgrid=False, zeroline=False, showticklabels=False
                ),
                yaxis=dict(
                    showgrid=False, zeroline=False, showticklabels=False
                ),
                title="Alert-Keyword-Entity Relationship Graph",
            )
            _style(fig, 500)
            st.plotly_chart(fig, use_container_width=True)
            st.caption(
                f"{len(nodes)} nodes, {len(edges)} edges "
                f"(top 50 nodes shown)"
            )
        else:
            st.info(
                "No graph data available. High-risk alerts with entities "
                "are needed."
            )
    except Exception:
        st.info("Link analysis requires scored alerts with extracted entities.")

    st.divider()

    # Source Credibility
    st.markdown("### Source Credibility (Bayesian-Updated)")
    try:
        sources = _get("/sources")
        if sources:
            src_df = pd.DataFrame(sources)
            if "credibility_score" in src_df.columns:
                src_df = src_df.sort_values(
                    "credibility_score", ascending=True
                )
                fig = px.bar(
                    src_df, x="credibility_score", y="name",
                    orientation="h",
                    color="credibility_score",
                    color_continuous_scale="Blues",
                    labels={
                        "credibility_score": "Credibility",
                        "name": "Source",
                    },
                    title="Intelligence Source Credibility",
                )
                _style(fig, 350)
                st.plotly_chart(fig, use_container_width=True)
    except Exception:
        pass

    st.divider()

    # Model Backtest
    st.markdown("### Scoring Model Backtest")
    try:
        backtest = _get("/analytics/backtest")
        if backtest and backtest.get("cases"):
            bt1, bt2, bt3 = st.columns(3)
            bt1.metric(
                "Multi-factor Accuracy",
                f"{backtest.get('multifactor_accuracy', 0):.1%}",
            )
            bt2.metric(
                "Naive Baseline",
                f"{backtest.get('naive_accuracy', 0):.1%}",
            )
            bt3.metric(
                "Improvement",
                f"{backtest.get('improvement', 0):.1%}",
            )
            bt_df = pd.DataFrame(backtest["cases"])
            cols = [
                c
                for c in [
                    "title", "expected_severity",
                    "predicted_severity", "score", "correct",
                ]
                if c in bt_df.columns
            ]
            if cols:
                st.dataframe(
                    bt_df[cols],
                    use_container_width=True,
                    hide_index=True,
                )
    except Exception:
        st.info("Backtest requires golden dataset cases in tests/.")


# ============================================================
# TAB 9: CONFIGURATION
# ============================================================
with tabs[8]:
    st.subheader("Configuration")

    # Keyword Management
    st.markdown("### Keyword Management")
    with st.form("add_keyword"):
        kc1, kc2, kc3 = st.columns(3)
        new_term = kc1.text_input("New Keyword")
        new_cat = kc2.selectbox(
            "Category",
            [
                "protective_intel",
                "travel_risk",
                "protest_disruption",
                "insider_workplace",
                "general",
            ],
        )
        new_weight = kc3.slider("Threat Weight", 0.1, 5.0, 1.0, 0.1)
        if st.form_submit_button("Add Keyword") and new_term:
            try:
                _post(
                    "/keywords",
                    payload={
                        "term": new_term,
                        "category": new_cat,
                        "weight": new_weight,
                    },
                )
                st.success(f"Added: {new_term}")
                st.rerun()
            except Exception:
                st.error("Keyword already exists or error occurred.")

    try:
        keywords = _get("/keywords")
        if keywords:
            kw_df = pd.DataFrame(keywords)
            cols = [
                c
                for c in ["id", "term", "category", "weight", "active"]
                if c in kw_df.columns
            ]
            st.dataframe(
                kw_df[cols], use_container_width=True, hide_index=True
            )
    except Exception:
        pass

    st.divider()

    # Protected Locations
    st.markdown("### Protected Locations")
    try:
        locations = _get("/locations/protected")
        if locations:
            loc_df = pd.DataFrame(locations)
            cols = [
                c
                for c in ["name", "type", "lat", "lon", "radius_miles"]
                if c in loc_df.columns
            ]
            st.dataframe(
                loc_df[cols], use_container_width=True, hide_index=True
            )
    except Exception:
        pass

    st.markdown("#### Add Protected Location")
    with st.form("add_location"):
        lc1, lc2, lc3 = st.columns(3)
        loc_name = lc1.text_input("Location Name")
        loc_type = lc2.selectbox(
            "Type", ["hq", "office", "residence", "venue", "other"]
        )
        loc_radius = lc3.slider("Radius (miles)", 1.0, 50.0, 5.0, 1.0)
        lc4, lc5 = st.columns(2)
        loc_lat = lc4.number_input("Latitude", value=0.0, format="%.6f")
        loc_lon = lc5.number_input("Longitude", value=0.0, format="%.6f")
        if st.form_submit_button("Add Location") and loc_name:
            try:
                _post(
                    "/locations/protected",
                    payload={
                        "name": loc_name,
                        "type": loc_type,
                        "lat": loc_lat if loc_lat != 0 else None,
                        "lon": loc_lon if loc_lon != 0 else None,
                        "radius_miles": loc_radius,
                    },
                )
                st.success(f"Added: {loc_name}")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")

    st.divider()

    # Source Credibility
    st.markdown("### Source Credibility")
    try:
        sources = _get("/sources")
        if sources:
            for src in sources:
                cred = src.get("credibility_score", 0.5)
                tp = src.get("true_positives", 0)
                fp = src.get("false_positives", 0)
                st.write(
                    f"**{src['name']}** ({src['source_type']}) -- "
                    f"Credibility: {cred:.2f} | TP: {tp} | FP: {fp}"
                )
    except Exception:
        pass

    st.divider()

    # Escalation Tiers
    st.markdown("### Escalation Tiers")
    try:
        tiers_data = _get("/analytics/escalation-tiers")
        for tier in tiers_data.get("tiers", []):
            label = tier["label"]
            css = f"tier-{label.lower()}"
            notify = ", ".join(tier.get("notify", [])) or "None"
            st.markdown(
                f'<span class="tier-badge {css}">{label}</span> '
                f'Score {tier["threshold"]}+ -- '
                f'{tier.get("action", "N/A")} | '
                f'Window: {tier.get("response_window", "N/A")} | '
                f'Notify: {notify}',
                unsafe_allow_html=True,
            )
    except Exception:
        pass

    st.divider()

    # Rescore
    st.markdown("### Re-score Alerts")
    st.write(
        "Recalculate ORS/TAS for all unreviewed alerts using current "
        "keyword weights, source credibility, and proximity factors."
    )
    if st.button("Re-score All Unreviewed Alerts"):
        try:
            result = _post("/alerts/rescore")
            st.success(f"Rescored {result['alerts_rescored']} alerts.")
        except Exception as e:
            st.error(f"Error: {e}")
