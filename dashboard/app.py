from __future__ import annotations

import base64
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import streamlit as st

from fuzzynmap.detector import analyze_xml
from fuzzynmap.scanner import scan_target


st.set_page_config(
    page_title="Fuzzynmap | Network Risk",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Keep the uploaded banner image at: Fuzzynmap/assets/cover.png
HERO_IMAGE = ROOT / "assets" / "cover.png"


def image_background_css(image_path: Path) -> str:
    """Return a CSS background image with a dark overlay, or a fallback."""
    if not image_path.is_file():
        return "background: linear-gradient(110deg, #101015, #38204c);"

    encoded = base64.b64encode(image_path.read_bytes()).decode("utf-8")
    return (
        "background-image: "
        "linear-gradient(90deg, rgba(8,9,14,.96) 0%, "
        "rgba(8,9,14,.78) 42%, rgba(8,9,14,.12) 100%), "
        f"url('data:image/png;base64,{encoded}');"
    )


hero_background = image_background_css(HERO_IMAGE)

st.markdown(
    f"""
    <style>
      :root {{
        --cream: #fff2e2;
        --purple: #38204c;
        --muted: #7c7698;
        --lavender: #b2acbd;
      }}

      .stApp {{
        background: #fff2e2;
        color: #38204c;
      }}

      [data-testid="stHeader"] {{
        background: rgba(255, 242, 226, 0.92);
      }}

      h1, h2, h3,
      [data-testid="stMetricValue"],
      [data-testid="stMetricLabel"] {{
        color: #38204c !important;
      }}

      p, label, .stCaption,
      [data-testid="stMarkdownContainer"] {{
        color: #7c7698;
      }}

      /* Website-style banner at the very top */
      .fuzzy-hero {{
        box-sizing: border-box;
        position: relative;
        overflow: hidden;
        min-height: 245px;
        padding: 1.7rem 2rem;
        border: 1px solid rgba(178, 172, 189, 0.45);
        border-radius: 18px;
        background-color: #101015;
        background-size: cover;
        background-position: center 48%;
        background-repeat: no-repeat;
        margin: 0 0 1.8rem 0;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        box-shadow: 0 8px 28px rgba(56, 32, 76, 0.12);
      }}

      .fuzzy-brand {{
        color: #fff2e2;
        font-size: clamp(2rem, 3.5vw, 2.65rem);
        font-weight: 800;
        letter-spacing: -0.04em;
        line-height: 1.05;
        margin: 0;
      }}

      .fuzzy-kicker {{
        color: #d0c5df;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        margin-top: 0.55rem;
      }}

      .fuzzy-headline {{
        color: #fff2e2;
        font-size: clamp(1.35rem, 2.6vw, 2rem);
        font-weight: 700;
        line-height: 1.15;
        margin: 1.8rem 0 0.45rem 0;
      }}

      .fuzzy-copy {{
        color: #e0d9e7;
        font-size: 0.92rem;
        line-height: 1.55;
        max-width: 590px;
        margin: 0;
      }}

      div[data-testid="stTextInput"] input {{
        background: #fffaf4;
        color: #38204c;
        border-color: #b2acbd;
        border-radius: 10px;
      }}

      div.stButton > button,
      div[data-testid="stFormSubmitButton"] button,
      div[data-testid="stDownloadButton"] button {{
        background: #38204c;
        color: #fff2e2;
        border: 1px solid #38204c;
        border-radius: 10px;
        font-weight: 700;
        min-height: 2.8rem;
      }}

      div.stButton > button:hover,
      div[data-testid="stFormSubmitButton"] button:hover,
      div[data-testid="stDownloadButton"] button:hover {{
        background: #7c7698;
        border-color: #7c7698;
        color: #fff2e2;
      }}

      [data-testid="stMetric"] {{
        background: rgba(178, 172, 189, 0.18);
        border: 1px solid #b2acbd;
        padding: 1rem;
        border-radius: 14px;
      }}

      [data-testid="stDataFrame"] {{
        border: 1px solid #b2acbd;
        border-radius: 12px;
      }}

      .verdict {{
        background: #fffaf4;
        border-left: 6px solid #38204c;
        border-radius: 10px;
        padding: 1rem 1.2rem;
        color: #38204c;
        margin: 0.5rem 0 1rem;
      }}

      .small-note {{
        color: #7c7698;
        font-size: 0.86rem;
      }}

      footer {{ visibility: hidden; }}

      @media (max-width: 640px) {{
        .fuzzy-hero {{
          min-height: 220px;
          padding: 1.25rem;
          background-position: 62% center;
        }}
      }}
    </style>

    <header class="fuzzy-hero" style="{hero_background}">
      <div>
        <h1 class="fuzzy-brand">Fuzzynmap</h1>
        <div class="fuzzy-kicker">Network security · Risk intelligence</div>
      </div>
      <div>
        <div class="fuzzy-headline">See your network. Understand your risk.</div>
        <p class="fuzzy-copy">
          Discover exposed services, analyze your network, and understand
          your security risk with fuzzy-logic assessment.
        </p>
      </div>
    </header>
    """,
    unsafe_allow_html=True,
)

st.markdown("### Scan a target")
st.caption(
    "Use an IP address, hostname, or CIDR network that you own or have "
    "explicit permission to assess."
)

with st.form("scan_form", clear_on_submit=False):
    target = st.text_input(
        "Target IP or network",
        placeholder="e.g. 192.168.1.10 or 192.168.1.0/24",
        help=(
            "The scan checks TCP ports 1–1024 and identifies available "
            "service/version information."
        ),
    ).strip()
    submitted = st.form_submit_button("Run network scan", use_container_width=True)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if submitted:
    if not target:
        st.error("Enter an IP address, hostname, or network before starting the scan.")
    else:
        scan_path = ROOT / "data" / "scan_results" / "latest_scan.xml"
        started_at = datetime.now().astimezone()
        start_clock = time.perf_counter()

        with st.spinner(f"Scanning {target}. This can take a little while…"):
            try:
                scan_target(target, scan_path)
                results = analyze_xml(scan_path)
                completed_at = datetime.now().astimezone()
                duration = time.perf_counter() - start_clock
                timestamp = completed_at.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

                if results.empty:
                    st.session_state.latest_scan = {
                        "target": target,
                        "timestamp": timestamp,
                        "duration": duration,
                        "results": results,
                        "message": (
                            "The scan completed, but no port results were "
                            "returned for the selected range."
                        ),
                    }
                else:
                    results.insert(0, "scan_time", timestamp)
                    results.insert(1, "target", target)
                    results["fuzzy_risk_percent"] = results["risk_score"].round(1).map(
                        lambda value: f"{value:.1f}%"
                    )

                    st.session_state.latest_scan = {
                        "target": target,
                        "timestamp": timestamp,
                        "duration": duration,
                        "results": results,
                        "message": "",
                    }

                    st.session_state.scan_history.insert(
                        0,
                        {
                            "Scan time": timestamp,
                            "Target": target,
                            "Ports returned": int(len(results)),
                            "Open ports": int(
                                (results["state"].str.lower() == "open").sum()
                            ),
                            "High risk": int((results["risk_level"] == "High").sum()),
                            "Duration (s)": round(duration, 1),
                        },
                    )

                st.rerun()
            except Exception as exc:
                st.error(f"Scan failed: {exc}")

scan = st.session_state.get("latest_scan")

if scan:
    st.divider()
    st.markdown("### Scan outcome")
    st.caption(
        f"Target: {scan['target']} · Completed: {scan['timestamp']} · "
        f"Duration: {scan['duration']:.1f} seconds"
    )

    results = scan["results"]

    if results.empty:
        st.info(scan.get("message") or "No port results were returned.")
    else:
        open_results = results[results["state"].str.lower() == "open"]
        high_count = int((results["risk_level"] == "High").sum())
        medium_count = int((results["risk_level"] == "Medium").sum())
        low_count = int((results["risk_level"] == "Low").sum())
        total_open = len(open_results)

        metric1, metric2, metric3, metric4 = st.columns(4)
        metric1.metric("Ports identified", len(results))
        metric2.metric("Open ports", total_open)
        metric3.metric("High-risk findings", high_count)
        metric4.metric("Scan duration", f"{scan['duration']:.1f}s")

        if high_count:
            verdict = (
                f"Priority review recommended: {high_count} high-risk port "
                "finding(s) were identified. Review the services and restrict "
                "exposure where appropriate."
            )
        elif medium_count:
            verdict = (
                f"Moderate exposure detected: {medium_count} medium-risk "
                "finding(s) were identified. Review whether each service needs "
                "to be reachable."
            )
        elif total_open:
            verdict = (
                "No high-risk findings were scored in this scan. "
                f"{total_open} open port(s) were identified and should still "
                "be reviewed against your network's intended configuration."
            )
        else:
            verdict = (
                "No open ports were identified in the scanned TCP range. "
                "This does not guarantee that the target has no exposed "
                "services outside the scanned range."
            )

        st.markdown(
            f'<div class="verdict"><strong>Assessment</strong><br>{verdict}</div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "Fuzzy risk percentages are heuristic scores, not probabilities "
            "that a port is exploitable or proof of a vulnerability."
        )

        st.markdown("### Port-by-port results")
        risk_filter = st.multiselect(
            "Filter by risk level",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
        )
        filtered = results[results["risk_level"].isin(risk_filter)].copy()

        display_columns = [
            "scan_time",
            "target",
            "host",
            "address",
            "port",
            "protocol",
            "state",
            "service",
            "product",
            "version",
            "fuzzy_risk_percent",
            "risk_level",
        ]
        display_names = {
            "scan_time": "Scan time",
            "target": "Target",
            "host": "Host",
            "address": "IP address",
            "port": "Port",
            "protocol": "Protocol",
            "state": "State",
            "service": "Service",
            "product": "Product",
            "version": "Version",
            "fuzzy_risk_percent": "Fuzzy risk score",
            "risk_level": "Risk level",
        }

        visible = filtered[
            [column for column in display_columns if column in filtered.columns]
        ].rename(columns=display_names)
        st.dataframe(visible, use_container_width=True, hide_index=True)

        csv_data = (
            filtered.drop(columns=["fuzzy_risk_percent"], errors="ignore")
            .to_csv(index=False)
            .encode("utf-8")
        )
        st.download_button(
            "Download scan results (CSV)",
            data=csv_data,
            file_name="fuzzynmap_scan_results.csv",
            mime="text/csv",
        )

        if not open_results.empty:
            st.markdown("### Fuzzy risk scores")
            chart_data = open_results[["port", "risk_score"]].copy()
            chart_data["Port"] = (
                chart_data["port"].astype(str)
                + " · "
                + open_results["service"].fillna("unknown").astype(str)
            )
            chart_data = chart_data.rename(
                columns={"risk_score": "Risk score (%)"}
            ).set_index("Port")[["Risk score (%)"]]
            st.bar_chart(chart_data, y="Risk score (%)", color="#7c7698")

if st.session_state.scan_history:
    st.divider()
    st.markdown("### Recent scans")
    st.dataframe(
        pd.DataFrame(st.session_state.scan_history),
        use_container_width=True,
        hide_index=True,
    )

st.markdown(
    '<p class="small-note">Scan only networks you own or have explicit permission '
    "to assess. Fuzzynmap provides a heuristic triage aid, not a substitute for "
    "security verification.</p>",
    unsafe_allow_html=True,
)
