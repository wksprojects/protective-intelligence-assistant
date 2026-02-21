import os
from datetime import date, timedelta

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("PI_API_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("PI_API_KEY", "").strip()

st.set_page_config(
    page_title="Protective Intelligence Assistant",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Protective Intelligence / Executive Protection Assistant")

def _auth_headers():
    if not API_KEY:
        return {}
    return {"X-API-Key": API_KEY}


try:
    requests.get(f"{API_URL}/", headers=_auth_headers(), timeout=3).raise_for_status()
except Exception:
    st.error("Cannot connect to API. Start `python run.py api` first.")
    st.stop()

(
    tab_protectees,
    tab_facilities,
    tab_map,
    tab_travel,
    tab_report,
    tab_alerts,
    tab_config,
) = st.tabs(
    [
        "👤 Protectees",
        "🏢 Facilities",
        "🗺️ Map",
        "✈️ Travel Brief",
        "📋 Daily Report",
        "🚨 Alerts (Legacy)",
        "⚙️ Config",
    ]
)


def _safe_get(path, params=None):
    try:
        response = requests.get(
            f"{API_URL}{path}",
            params=params,
            headers=_auth_headers(),
            timeout=20,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def _safe_post(path, payload, timeout=30):
    try:
        response = requests.post(
            f"{API_URL}{path}",
            json=payload,
            headers=_auth_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


with tab_protectees:
    st.subheader("Protectee Monitoring")
    pois = _safe_get("/pois") or []
    if not pois:
        st.info("No protectees found. Seed with `python run.py init`.")
    else:
        poi_map = {f"{poi['name']} ({poi.get('org') or 'N/A'})": poi for poi in pois}
        selected_label = st.selectbox("Select protectee", list(poi_map.keys()))
        selected = poi_map[selected_label]

        c1, c2, c3 = st.columns(3)
        c1.metric("Sensitivity", selected.get("sensitivity", 3))
        c2.metric("Role", selected.get("role") or "N/A")
        c3.metric("Org", selected.get("org") or "N/A")

        force = st.checkbox("Recompute TAS now", value=False)
        assessment = _safe_get(
            f"/pois/{selected['id']}/assessment",
            params={"window_days": 14, "force": 1 if force else 0},
        ) or {}

        tas = float(assessment.get("tas_score") or 0.0)
        evidence = assessment.get("evidence") or {}
        interval = evidence.get("interval") or {}

        st.markdown("### Threat Assessment Score (TAS)")
        if interval:
            st.metric("TAS", f"{tas:.1f}", help=f"p05={interval.get('p05')} p95={interval.get('p95')}")
            st.caption(
                f"Interval: p05={interval.get('p05')} / p50={interval.get('p50')} / p95={interval.get('p95')}"
            )
        else:
            st.metric("TAS", f"{tas:.1f}")

        flags = [
            ("fixation", assessment.get("fixation")),
            ("energy_burst", assessment.get("energy_burst")),
            ("leakage", assessment.get("leakage")),
            ("pathway", assessment.get("pathway")),
            ("targeting_specificity", assessment.get("targeting_specificity")),
        ]
        active_flags = [name for name, active in flags if int(active or 0) == 1]
        st.write("**TRAP-lite flags:**", ", ".join(active_flags) if active_flags else "None")

        hits = _safe_get(f"/pois/{selected['id']}/hits", params={"days": 30}) or []
        st.markdown("### Timeline Hits (30 days)")
        if hits:
            df = pd.DataFrame(hits)
            cols = [
                c
                for c in [
                    "timestamp",
                    "alert_id",
                    "match_type",
                    "match_value",
                    "match_score",
                    "ors_score",
                    "tas_score",
                    "title",
                ]
                if c in df.columns
            ]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
            excerpts = [h.get("context") for h in hits if h.get("context")]
            if excerpts:
                st.markdown("**Evidence excerpts**")
                for snippet in excerpts[:3]:
                    st.code(snippet, language="text")
        else:
            st.info("No POI hits found in the selected window.")

with tab_facilities:
    st.subheader("Facility Watch")
    locations = _safe_get("/locations/protected") or []
    if not locations:
        st.info("No protected locations configured.")
    else:
        location_map = {loc["name"]: loc for loc in locations}
        selected_name = st.selectbox("Protected location", list(location_map.keys()))
        selected = location_map[selected_name]
        days = st.slider("Days", 1, 30, 7)
        min_ors = st.slider("Minimum ORS", 0.0, 100.0, 60.0, 5.0)

        alerts = _safe_get(
            f"/locations/protected/{selected['id']}/alerts",
            params={"days": days, "min_ors": min_ors},
        ) or []

        c1, c2, c3 = st.columns(3)
        c1.metric("Type", selected.get("type") or "N/A")
        c2.metric("Radius (mi)", selected.get("radius_miles") or "N/A")
        c3.metric("Nearby alerts", len(alerts))

        if alerts:
            df = pd.DataFrame(alerts)
            cols = [
                c
                for c in [
                    "timestamp",
                    "id",
                    "title",
                    "ors_score",
                    "tas_score",
                    "distance_miles",
                    "within_radius",
                    "location_text",
                ]
                if c in df.columns
            ]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No nearby alerts match current filters.")

with tab_map:
    st.subheader("Protected Locations + Recent Alert Locations")
    days = st.slider("Map days", 1, 30, 7, key="map_days")
    min_ors = st.slider("Map min ORS", 0.0, 100.0, 60.0, 5.0, key="map_ors")

    points = _safe_get("/analytics/map", params={"days": days, "min_ors": min_ors}) or {}
    protected = points.get("protected_locations", [])
    alerts = points.get("alerts", [])

    fig = go.Figure()
    if protected:
        fig.add_trace(
            go.Scattergeo(
                lat=[row["lat"] for row in protected],
                lon=[row["lon"] for row in protected],
                text=[row["name"] for row in protected],
                mode="markers",
                marker={"size": 11, "color": "green"},
                name="Protected",
            )
        )
    if alerts:
        fig.add_trace(
            go.Scattergeo(
                lat=[row["lat"] for row in alerts],
                lon=[row["lon"] for row in alerts],
                text=[f"#{row['id']} ORS={row.get('ors_score', 0):.1f} {row['title'][:70]}" for row in alerts],
                mode="markers",
                marker={"size": 8, "color": "red"},
                name="Alerts",
            )
        )

    fig.update_layout(height=520, geo=dict(scope="world", showcountries=True, showland=True))
    st.plotly_chart(fig, use_container_width=True)

with tab_travel:
    st.subheader("Travel Brief Generator")
    with st.form("travel_brief_form"):
        destination = st.text_input("Destination", value="San Francisco, CA")
        start_dt = st.date_input("Start date", value=date.today())
        end_dt = st.date_input("End date", value=date.today() + timedelta(days=3))
        submitted = st.form_submit_button("Generate Brief")

    if submitted:
        payload = {
            "destination": destination,
            "start_dt": start_dt.strftime("%Y-%m-%d"),
            "end_dt": end_dt.strftime("%Y-%m-%d"),
        }
        brief = _safe_post("/briefs/travel", payload, timeout=30)
        if brief:
            st.markdown("### Brief Output")
            st.markdown(brief.get("content_md", "No brief generated."))
        else:
            st.error("Brief generation failed. Verify API auth and connectivity.")

    st.markdown("### Recent Briefs")
    briefs = _safe_get("/briefs/travel", params={"limit": 10}) or []
    if briefs:
        st.dataframe(pd.DataFrame(briefs), use_container_width=True, hide_index=True)

with tab_report:
    st.subheader("EP Daily Intelligence Report")
    report_date = st.date_input("Report date", value=date.today(), key="report_date")
    report = _safe_get("/intelligence/daily", params={"date": report_date.strftime("%Y-%m-%d")}) or {}

    st.markdown("### Executive Summary")
    st.info(report.get("executive_summary", "No report content."))

    stats = report.get("stats", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", stats.get("total_alerts", 0))
    c2.metric("Critical", stats.get("critical_count", 0))
    c3.metric("High", stats.get("high_count", 0))
    c4.metric("Medium", stats.get("medium_count", 0))

    st.markdown("### Protectee Status")
    protectee_status = report.get("protectee_status", [])
    if protectee_status:
        st.dataframe(pd.DataFrame(protectee_status), use_container_width=True, hide_index=True)
    else:
        st.info("No protectee escalations in this window.")

    st.markdown("### Facility Watch")
    facility_watch = report.get("facility_watch", [])
    if facility_watch:
        st.dataframe(pd.DataFrame(facility_watch), use_container_width=True, hide_index=True)
    else:
        st.info("No facility proximity alerts in this window.")

    st.markdown("### Upcoming Events / Travel (7d)")
    upcoming = report.get("upcoming_events", [])
    if upcoming:
        st.dataframe(pd.DataFrame(upcoming), use_container_width=True, hide_index=True)
    else:
        st.info("No upcoming events configured.")

    st.markdown("### Escalation Recommendations")
    escalations = report.get("escalation_recommendations", [])
    if escalations:
        for item in escalations:
            st.write(f"- [{item.get('priority', 'MEDIUM')}] {item.get('why', '')}")
    else:
        st.info("No escalations.")

with tab_alerts:
    st.subheader("Legacy Alert Feed")
    min_score = st.slider("Minimum ORS", 0.0, 100.0, 50.0, 5.0, key="legacy_min")
    alerts = _safe_get("/alerts", params={"limit": 100, "min_score": min_score, "sort_by": "risk_score"}) or []
    if not alerts:
        st.info("No alerts match the filter.")
    else:
        for alert in alerts:
            ors = alert.get("ors_score") if alert.get("ors_score") is not None else alert.get("risk_score", 0.0)
            tas = alert.get("tas_score", 0.0)
            with st.expander(f"[{alert.get('severity', 'low').upper()}] ORS={ors:.1f} TAS={tas:.1f} {alert['title'][:100]}"):
                st.write(f"Source: {alert.get('source_name', 'N/A')}")
                st.write(f"Keyword: {alert.get('matched_term', 'N/A')}")
                st.write(f"Published: {alert.get('published_at') or 'Unknown'}")
                if alert.get("url"):
                    st.write(alert["url"])
                if alert.get("content"):
                    st.write(alert["content"][:500])

                score = _safe_get(f"/alerts/{alert['id']}/score", params={"uncertainty": 1, "n": 500}) or {}
                interval = score.get("uncertainty") or {}
                if score:
                    st.write(
                        f"ORS={score.get('ors_score', 0):.1f} TAS={score.get('tas_score', 0):.1f} "
                        f"(p05={interval.get('p05', 'n/a')} p95={interval.get('p95', 'n/a')})"
                    )

with tab_config:
    st.subheader("Configuration Snapshot")
    summary = _safe_get("/alerts/summary") or {}
    st.json(summary)

    st.markdown("### Keywords")
    kws = _safe_get("/keywords") or []
    if kws:
        st.dataframe(pd.DataFrame(kws), use_container_width=True, hide_index=True)

    st.markdown("### Connector Policy")
    st.info(
        "This build ships safe RSS/API collectors. Connectors requiring explicit ToS/legal review "
        "(Telegram/chans/etc.) are stubbed only and not active."
    )
