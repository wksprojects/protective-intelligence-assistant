import os
from datetime import datetime, date

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

API_URL = (os.getenv("PI_API_URL") or os.getenv("OSINT_API_URL") or "http://localhost:8000").rstrip("/")
API_KEY = (os.getenv("PI_API_KEY") or os.getenv("OSINT_API_KEY") or "").strip()


def _auth_headers():
    if not API_KEY:
        return {}
    return {"X-API-Key": API_KEY}


def _api_get(path, params=None, timeout=20):
    resp = requests.get(
        f"{API_URL}{path}",
        params=params,
        headers=_auth_headers(),
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def _api_post(path, payload=None, timeout=20):
    resp = requests.post(
        f"{API_URL}{path}",
        json=payload,
        headers=_auth_headers(),
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def _api_patch(path, timeout=20):
    resp = requests.patch(
        f"{API_URL}{path}",
        headers=_auth_headers(),
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def _style_plot(fig, height=None):
    fig.update_layout(
        template="plotly_white",
        margin={"l": 24, "r": 20, "t": 40, "b": 24},
        paper_bgcolor="white",
        plot_bgcolor="white",
    )
    if height is not None:
        fig.update_layout(height=height)
    return fig


st.set_page_config(
    page_title="Protective Intelligence Console",
    page_icon="PI",
    layout="wide",
)

st.markdown(
    """
<style>
    :root {
        --bg: #f3f5f8;
        --panel: #ffffff;
        --ink: #0f172a;
        --muted: #475569;
        --line: #dbe2ea;
        --accent: #0f4c81;
    }
    .stApp {
        background:
            radial-gradient(circle at 8% 8%, #e7eef7 0%, rgba(231, 238, 247, 0) 35%),
            radial-gradient(circle at 92% 0%, #edf6f2 0%, rgba(237, 246, 242, 0) 30%),
            var(--bg);
        color: var(--ink);
    }
    .stApp p,
    .stApp span,
    .stApp label,
    .stApp div,
    .stApp h1,
    .stApp h2,
    .stApp h3,
    .stApp h4 {
        color: var(--ink) !important;
    }
    .stApp a {
        color: var(--accent) !important;
    }
    .stTabs [data-baseweb="tab"] {
        color: var(--ink) !important;
    }
    .stDataFrame * {
        color: var(--ink) !important;
    }
    .stTextInput input,
    .stTextArea textarea,
    .stSelectbox [data-baseweb="select"],
    .stSlider {
        color: var(--ink) !important;
    }
    .ops-header {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 18px 22px;
        margin-bottom: 14px;
    }
    .ops-kicker {
        color: var(--accent);
        font-size: 0.76rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        font-weight: 600;
        margin-bottom: 6px;
    }
    .ops-title {
        color: var(--ink);
        font-size: 1.5rem;
        font-weight: 700;
        margin: 0;
    }
    .ops-subtitle {
        color: var(--muted);
        margin-top: 6px;
        margin-bottom: 0;
    }
</style>
""",
    unsafe_allow_html=True,
)
st.markdown(
    """
<section class="ops-header">
  <div class="ops-kicker">Operations Console</div>
  <h1 class="ops-title">Protective Intelligence and Travel Security</h1>
  <p class="ops-subtitle">State Department alerts, public safety indicators, and threat signals for analyst triage.</p>
</section>
""",
    unsafe_allow_html=True,
)

# --- Check API connection ---
try:
    requests.get(f"{API_URL}/", headers=_auth_headers(), timeout=3).raise_for_status()
except requests.RequestException:
    st.error("Cannot connect to API. Make sure the API server is running on port 8000.")
    st.stop()

# --- Tab layout ---
tab_overview, tab_intel, tab_alerts, tab_analytics, tab_config = st.tabs([
    "Overview",
    "Daily Briefing",
    "Alerts",
    "Analytics",
    "Configuration",
])

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


# ============================================================
# TAB 1: OVERVIEW
# ============================================================
with tab_overview:
    try:
        summary = _api_get("/alerts/summary", params={"include_demo": 0})
        st.caption(f"Updated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

        # KPI Row
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        col1.metric("Total Alerts", summary["total_alerts"])
        col2.metric("Unreviewed", summary["unreviewed"])
        col3.metric("Critical", summary["by_severity"].get("critical", 0))
        col4.metric("High", summary["by_severity"].get("high", 0))
        col5.metric("Avg Risk Score", f"{summary.get('avg_risk_score', 0):.1f}")
        col6.metric("Active Spikes", summary.get("active_spikes", 0))

        st.divider()

        # Charts row
        col_left, col_mid, col_right = st.columns(3)

        with col_left:
            st.subheader("Alerts by Severity")
            if summary["by_severity"]:
                severity_df = pd.DataFrame(
                    list(summary["by_severity"].items()), columns=["Severity", "Count"]
                )
                severity_order = ["critical", "high", "medium", "low"]
                severity_df["Severity"] = pd.Categorical(
                    severity_df["Severity"], categories=severity_order, ordered=True
                )
                severity_df = severity_df.sort_values("Severity")
                fig_sev = px.bar(
                    severity_df, x="Severity", y="Count",
                    color="Severity", color_discrete_map=SEVERITY_COLORS,
                )
                fig_sev.update_layout(showlegend=False)
                _style_plot(fig_sev, height=350)
                st.plotly_chart(fig_sev, use_container_width=True)

        with col_mid:
            st.subheader("Alerts by Source")
            if summary["by_source"]:
                source_df = pd.DataFrame(
                    list(summary["by_source"].items()), columns=["Source", "Count"]
                )
                fig_src = px.pie(source_df, values="Count", names="Source", hole=0.4)
                _style_plot(fig_src, height=350)
                st.plotly_chart(fig_src, use_container_width=True)

        with col_right:
            st.subheader("Top Matched Keywords")
            if summary["top_keywords"]:
                kw_df = pd.DataFrame(
                    list(summary["top_keywords"].items()), columns=["Keyword", "Count"]
                )
                kw_df = kw_df.sort_values("Count", ascending=True)
                fig_kw = px.bar(kw_df, x="Count", y="Keyword", orientation="h")
                _style_plot(fig_kw, height=350)
                st.plotly_chart(fig_kw, use_container_width=True)

        # Risk score distribution
        st.subheader("Risk Score Distribution")
        alerts_for_dist = _api_get("/alerts", params={"limit": 500, "include_demo": 0})
        if alerts_for_dist:
            scores = [a["risk_score"] for a in alerts_for_dist if a.get("risk_score")]
            if scores:
                fig_hist = px.histogram(
                    x=scores, nbins=20,
                    labels={"x": "Risk Score", "y": "Count"},
                    color_discrete_sequence=["#0f4c81"],
                )
                fig_hist.update_layout(xaxis_title="Risk Score", yaxis_title="Alert Count")
                _style_plot(fig_hist, height=300)
                st.plotly_chart(fig_hist, use_container_width=True)

    except requests.RequestException as e:
        st.error(f"Cannot load overview data: {e}")


# ============================================================
# TAB 2: INTELLIGENCE REPORT
# ============================================================
with tab_intel:
    st.subheader("Daily Intelligence Briefing")

    report_date = st.date_input("Report Date", value=date.today())

    try:
        report = _api_get(
            "/intelligence/daily",
            params={"date": report_date.strftime("%Y-%m-%d"), "include_demo": 0},
        )

        # Executive Summary
        st.markdown("### Executive Summary")
        st.info(report.get("executive_summary", "No data available for this date."))

        # Stats row
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
            display_cols = [c for c in ["title", "risk_score", "severity", "source_name", "keyword"] if c in risk_df.columns]
            if display_cols:
                st.dataframe(
                    risk_df[display_cols].rename(columns={
                        "title": "Title", "risk_score": "Risk Score",
                        "severity": "Severity", "source_name": "Source",
                        "keyword": "Keyword",
                    }),
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
            fig_themes = px.bar(
                themes_df, x="term", y="spike_ratio",
                color="spike_ratio", color_continuous_scale="Blues",
                labels={"term": "Keyword", "spike_ratio": "Spike Ratio (vs 7d avg)"},
            )
            _style_plot(fig_themes, height=350)
            st.plotly_chart(fig_themes, use_container_width=True)
        else:
            st.info("No keyword spikes detected. Spike detection requires 3+ days of scraping data.")

        # Active Threat Actors
        actors = report.get("active_threat_actors", [])
        st.markdown("### Active Threat Actors")
        if actors:
            for actor in actors:
                known = ", ".join(a["name"] for a in actor.get("known_actors", []))
                line = f"- **{actor['keyword']}**: {actor['mentions']} mention(s)"
                if known:
                    line += f" — linked to: {known}"
                st.markdown(line)
        else:
            st.info("No threat actor activity detected for this period.")

    except requests.RequestException as e:
        st.error(f"Cannot connect to API: {e}")
    except Exception as e:
        st.error(f"Error generating report: {e}")


# ============================================================
# TAB 3: ALERT FEED
# ============================================================
with tab_alerts:
    st.subheader("Alert Queue")

    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        severity_filter = st.selectbox(
            "Filter by Severity", ["All", "critical", "high", "medium", "low"]
        )
    with filter_col2:
        review_filter = st.selectbox(
            "Filter by Status", ["All", "Unreviewed", "Reviewed"]
        )
    with filter_col3:
        min_score = st.slider("Minimum Risk Score", 0.0, 100.0, 0.0, 5.0)

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
        alerts = _api_get("/alerts", params=params)

        if alerts:
            for alert in alerts:
                severity = alert["severity"]
                severity_tag = SEVERITY_LABELS.get(severity, severity.upper())
                reviewed_tag = "REVIEWED" if alert["reviewed"] else "OPEN"
                score = alert.get("risk_score", 0) or 0

                with st.expander(
                    f"[{severity_tag} {score:.0f}] {alert['title'][:100]} ({reviewed_tag})"
                ):
                    mc1, mc2, mc3, mc4 = st.columns(4)
                    mc1.write(f"**Risk Score:** {score:.1f}")
                    mc2.write(f"**Source:** {alert.get('source_name', 'Unknown')}")
                    mc3.write(f"**Keyword:** {alert.get('matched_term', 'N/A')}")
                    mc4.write(f"**Time:** {alert['created_at']}")

                    if alert.get("url"):
                        st.write(f"**URL:** {alert['url']}")
                    if alert.get("content"):
                        st.write(f"**Content:** {alert['content'][:500]}...")

                    # Score breakdown
                    try:
                        score_data = _api_get(f"/alerts/{alert['id']}/score")
                        if "keyword_weight" in score_data:
                            st.markdown("**Score Breakdown:**")
                            sc1, sc2, sc3, sc4 = st.columns(4)
                            sc1.metric("Keyword Weight", f"{score_data['keyword_weight']:.1f}")
                            sc2.metric("Source Credibility", f"{score_data['source_credibility']:.2f}")
                            sc3.metric("Frequency Factor", f"{score_data['frequency_factor']:.1f}x")
                            sc4.metric("Recency Factor", f"{score_data['recency_factor']:.2f}")
                    except Exception:
                        pass

                    if not alert["reviewed"]:
                        if st.button("Mark Reviewed", key=f"review_{alert['id']}"):
                            _api_patch(f"/alerts/{alert['id']}/review")
                            st.rerun()
        else:
            st.info("No alerts found matching your filters.")

    except requests.RequestException as e:
        st.error(f"Cannot load alerts: {e}")


# ============================================================
# TAB 4: ANALYTICS
# ============================================================
with tab_analytics:
    st.subheader("Risk Analytics")

    # Spike Detection
    st.markdown("### Keyword Frequency Spikes")
    try:
        spikes = _api_get("/analytics/spikes", params={"threshold": 1.5})
        if spikes:
            spike_df = pd.DataFrame(spikes)
            fig_spike = px.bar(
                spike_df, x="term", y="spike_ratio",
                color="today_count", color_continuous_scale="Blues",
                labels={"term": "Keyword", "spike_ratio": "Spike Ratio", "today_count": "Today's Count"},
                title="Active Keyword Spikes (vs 7-day average)",
            )
            _style_plot(fig_spike, height=400)
            st.plotly_chart(fig_spike, use_container_width=True)
            st.dataframe(spike_df, use_container_width=True, hide_index=True)
        else:
            st.info("No keyword spikes detected above threshold. Spike detection requires 3+ days of scraping history.")
    except Exception as e:
        st.error(f"Error loading spike data: {e}")

    st.divider()

    # Keyword Trend Explorer
    st.markdown("### Keyword Trend Explorer")
    try:
        keywords = _api_get("/keywords")
        if keywords:
            kw_options = {k["term"]: k["id"] for k in keywords}
            selected_term = st.selectbox("Select Keyword", list(kw_options.keys()))
            if selected_term:
                trend = _api_get(
                    f"/analytics/keyword-trend/{kw_options[selected_term]}",
                    params={"days": 14},
                )
                if trend:
                    trend_df = pd.DataFrame(trend)
                    fig_trend = px.line(
                        trend_df, x="date", y="count",
                        title=f"Daily frequency: {selected_term}",
                        markers=True,
                    )
                    _style_plot(fig_trend, height=350)
                    st.plotly_chart(fig_trend, use_container_width=True)
                else:
                    st.info("No frequency data yet for this keyword. Run the scraper to populate.")
    except Exception as e:
        st.error(f"Error loading trend data: {e}")

    st.divider()

    # Source Credibility Overview
    st.markdown("### Source Credibility Ratings")
    try:
        sources = _api_get("/sources")
        if sources:
            source_df = pd.DataFrame(sources)
            if "credibility_score" in source_df.columns:
                source_df = source_df.sort_values("credibility_score", ascending=True)
                fig_cred = px.bar(
                    source_df, x="credibility_score", y="name", orientation="h",
                    color="credibility_score", color_continuous_scale="Blues",
                    labels={"credibility_score": "Credibility Score", "name": "Source"},
                    title="Intelligence Source Credibility",
                )
                _style_plot(fig_cred, height=350)
                st.plotly_chart(fig_cred, use_container_width=True)
    except Exception as e:
        st.error(f"Error loading source data: {e}")


# ============================================================
# TAB 5: CONFIGURATION
# ============================================================
with tab_config:
    st.subheader("Configuration")

    # --- Keyword Management ---
    st.markdown("### Keyword Management")

    with st.form("add_keyword"):
        kc1, kc2, kc3 = st.columns(3)
        with kc1:
            new_term = st.text_input("New Keyword")
        with kc2:
            new_category = st.selectbox(
                "Category",
                [
                    "protective_intel",
                    "travel_risk",
                    "protest_disruption",
                    "insider_workplace",
                    "general",
                    "threat_actor",
                    "malware",
                    "vulnerability",
                ],
            )
        with kc3:
            new_weight = st.slider("Threat Weight", 0.1, 5.0, 1.0, 0.1)
        submitted = st.form_submit_button("Add Keyword")
        if submitted and new_term:
            try:
                _api_post(
                    "/keywords",
                    payload={"term": new_term, "category": new_category, "weight": new_weight},
                )
                st.success(f"Added keyword: {new_term} (weight: {new_weight})")
                st.rerun()
            except requests.RequestException:
                st.error("Keyword already exists or error occurred.")

    try:
        keywords = _api_get("/keywords")
        if keywords:
            kw_df = pd.DataFrame(keywords)
            display_cols = [c for c in ["id", "term", "category", "weight", "active"] if c in kw_df.columns]
            st.dataframe(kw_df[display_cols], use_container_width=True, hide_index=True)
    except Exception:
        pass

    st.divider()

    # --- Source Credibility ---
    st.markdown("### Source Credibility")
    try:
        sources = _api_get("/sources")
        if sources:
            for src in sources:
                sc1, sc2 = st.columns([3, 1])
                cred = src.get("credibility_score", 0.5)
                sc1.write(f"**{src['name']}** ({src['source_type']}) — Credibility: {cred:.2f}")
                sc2.write("")  # spacer
    except Exception:
        pass

    st.divider()

    # --- Rescore ---
    st.markdown("### Re-score Alerts")
    st.write("Re-calculate risk scores for all unreviewed alerts using current keyword weights and source credibility.")
    if st.button("Re-score All Unreviewed Alerts"):
        try:
            result = _api_post("/alerts/rescore")
            st.success(f"Rescored {result['alerts_rescored']} alerts.")
        except Exception as e:
            st.error(f"Error: {e}")

    st.divider()

    # --- Threat Actors ---
    st.markdown("### Known Threat Actors")
    try:
        actors = _api_get("/threat-actors")
        if actors:
            actor_df = pd.DataFrame(actors)
            display_cols = [c for c in ["name", "aliases", "description"] if c in actor_df.columns]
            st.dataframe(actor_df[display_cols], use_container_width=True, hide_index=True)
    except Exception:
        pass
