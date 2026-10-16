from __future__ import annotations

import ipaddress
import sys
import time
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fuzzynmap.detector import analyze_xml
from fuzzynmap.scanner import scan_target

st.set_page_config(
    page_title="Fuzzynmap · Network Risk",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DASHBOARD_DIR = Path(__file__).resolve().parent
CSS_PATH = DASHBOARD_DIR / "style.css"
if CSS_PATH.exists():
    st.markdown(f"<style>{CSS_PATH.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

if "light_mode" not in st.session_state:
    st.session_state.light_mode = False

# Apply the selected theme before rendering the main page.
if st.session_state.light_mode:
    st.markdown("""
    <style>:root{
      --bg:#f7f8fc;--surface:#ffffff;--surface-raised:#f0f3fa;--ink:#172033;
      --muted:#596780;--line:#dfe5ef;--accent:#4c78ff;--accent-strong:#315ee8;
      --hero-a:#edf2ff;--hero-b:#f4f7ff;--grid:rgba(76,120,255,.08);
      --shadow:0 12px 34px rgba(30,48,85,.08);--success:#17845d;
      --danger:#d44961;--warning:#b87813;--input:#ffffff;--chart-track:#e7ebf4;
    }</style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>:root{
      --bg:#0c1018;--surface:#141b27;--surface-raised:#1b2635;--ink:#edf3ff;
      --muted:#9cabc2;--line:#29364a;--accent:#79a7ff;--accent-strong:#a1c2ff;
      --hero-a:#15243a;--hero-b:#1a1e32;--grid:rgba(121,167,255,.09);
      --shadow:0 14px 36px rgba(0,0,0,.2);--success:#64d6a0;
      --danger:#ff748a;--warning:#f3bd69;--input:#101722;--chart-track:#263247;
    }</style>
    """, unsafe_allow_html=True)


def validate_target(value: str) -> tuple[bool, str]:
    value = (value or "").strip()
    if not value:
        return False, "Enter an IP address, CIDR network, or hostname."
    if value.startswith("-") or any(ch.isspace() for ch in value):
        return False, "Enter one target only. Spaces and Nmap arguments are not accepted."
    try:
        ipaddress.ip_address(value)
        return True, ""
    except ValueError:
        pass
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=True)
            return True, ""
        except ValueError:
            return False, "Invalid network/mask. Use a network address such as 192.168.1.0/24."
    if "://" in value or "/" in value or ":" in value:
        return False, "Enter a hostname or IP/CIDR, not a URL or host:port."
    hostname = value.rstrip(".")
    labels = hostname.split(".")
    if len(hostname) > 253 or not all(
        label and len(label) <= 63 and label[0].isalnum() and label[-1].isalnum()
        and all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    ):
        return False, "That doesn't look like a valid hostname or IP address."
    return True, ""


def section_heading(title: str, subtitle: str = "") -> None:
    st.markdown(f'<div class="section-heading">{escape(title)}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="section-subtitle">{escape(subtitle)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value: str | int, note: str, accent: str) -> None:
    st.markdown(
        f'<div class="metric-card"><div class="metric-accent {accent}"></div>'
        f'<div class="metric-label">{escape(label)}</div><div class="metric-value">{escape(str(value))}</div>'
        f'<div class="metric-note">{escape(note)}</div></div>',
        unsafe_allow_html=True,
    )


# Compact product header. The theme control is part of the page, not the Streamlit sidebar.
brand_col, spacer_col, theme_col = st.columns([2.5, 5.4, 1.6], vertical_alignment="center")
with brand_col:
    st.markdown(
        '<div class="brand"><div class="brand-mark">◈</div><div><div class="brand-name">Fuzzynmap</div>'
        '<div class="brand-caption">NETWORK INTELLIGENCE</div></div></div>',
        unsafe_allow_html=True,
    )
with theme_col:
    st.toggle("Light theme", key="light_mode", help="Switch between dark and light mode.")

# The scan panel is deliberately the first major element users encounter.
st.markdown(
    '<section class="scan-hero"><div class="scan-kicker"><span class="live-dot"></span> AUTHORIZED NETWORK ASSESSMENT</div>'
    '<h1>Know what is exposed.<br><span>Understand why it matters.</span></h1>'
    '</section>',
    unsafe_allow_html=True,
)
section_heading("Launch a scan", "Start with one IP address or scan an authorized CIDR network.")
with st.form("scan_form", clear_on_submit=False):
    input_col, button_col = st.columns([4, 1.25], vertical_alignment="bottom")
    with input_col:
        target = st.text_input(
            "Target IP, hostname, or CIDR",
            placeholder="192.168.1.1  /  192.168.1.0/24  /  localhost",
            help="A single IP scans one host. A CIDR such as 192.168.1.0/24 scans that network.",
        ).strip()
    with button_col:
        submitted = st.form_submit_button("Run scan  →", use_container_width=True)

st.markdown(
    '<div class="microcopy">Only scan devices and networks you own or have explicit permission to assess.</div>',
    unsafe_allow_html=True,
)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if submitted:
    valid, reason = validate_target(target)
    if not valid:
        st.error(reason)
    else:
        output_dir = ROOT / "data" / "scan_results"
        output_path = output_dir / "latest_scan.xml"
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            output_path.unlink(missing_ok=True)
        except OSError as exc:
            st.error(f"Could not clear previous scan output: {exc}")
            st.stop()

        started = time.perf_counter()
        status_slot = st.empty()
        status_slot.markdown(
            f'<div class="scan-status"><span class="spinner-dot"></span><div><b>Scanning {escape(target)}</b>'
            '<small>Nmap is running. Large networks can take longer than a single host.</small></div></div>',
            unsafe_allow_html=True,
        )
        try:
            scan_target(target, output_path)
            if not output_path.is_file() or output_path.stat().st_size == 0:
                raise RuntimeError("Nmap did not create a non-empty XML result.")
            results = analyze_xml(output_path)
            duration = time.perf_counter() - started
            timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
            st.session_state.latest_scan = {
                "target": target, "timestamp": timestamp, "duration": duration, "results": results,
                "message": "Nmap completed but returned no individual port rows. Ports may be filtered or outside the configured range." if results.empty else "",
            }
            st.session_state.scan_history.insert(0, {
                "Time": timestamp, "Target": target, "Port rows": len(results),
                "Open ports": int((results["state"].astype(str).str.lower() == "open").sum()) if not results.empty else 0,
                "Duration": f"{duration:.1f}s",
            })
            st.session_state.scan_history = st.session_state.scan_history[:8]
            status_slot.empty()
            st.rerun()
        except Exception as exc:
            status_slot.empty()
            st.error(f"Scan failed: {exc}")

scan = st.session_state.get("latest_scan")
if scan:
    st.markdown('<div class="result-divider"></div>', unsafe_allow_html=True)
    section_heading("Scan report", "The target and scan date are shown once above the port inventory.")
    st.markdown(
        f'<div class="scan-meta"><span class="meta-label">TARGET</span><strong>{escape(scan["target"])}</strong>'
        f'<span class="meta-separator">/</span><span class="meta-label">SCAN DATE</span>'
        f'<span>{escape(scan["timestamp"])}</span><span class="meta-separator">/</span>'
        f'<span>{scan["duration"]:.1f} sec</span></div>',
        unsafe_allow_html=True,
    )
    results = scan["results"]
    if results.empty:
        st.info(scan.get("message") or "No individual port records were returned.")
    else:
        open_rows = results[results["state"].astype(str).str.lower() == "open"].copy()
        high = int((results["risk_level"] == "High").sum())
        medium = int((results["risk_level"] == "Medium").sum())
        low = int((results["risk_level"] == "Low").sum())
        c1, c2, c3, c4 = st.columns(4)
        with c1: metric_card("PORT RECORDS", len(results), "Returned by Nmap", "blue")
        with c2: metric_card("OPEN PORTS", len(open_rows), "Accepting connections", "green")
        with c3: metric_card("HIGH RISK", high, "Review these first", "red")
        with c4: metric_card("DURATION", f'{scan["duration"]:.1f}s', "Elapsed scan time", "purple")

        if high:
            assessment = f"{high} high-risk record(s) need review. Confirm whether the exposed services are required."
            tone = "red"
        elif medium:
            assessment = f"{medium} medium-risk record(s). Check access controls and whether each service is necessary."
            tone = "amber"
        else:
            assessment = "No high or medium fuzzy-risk records were scored. This does not prove the host is secure."
            tone = "green"
        st.markdown(
            f'<div class="assessment {tone}"><span class="assessment-symbol">i</span><div><b>What this scan suggests</b>'
            f'<p>{escape(assessment)}</p><small>Fuzzy scores are heuristic triage indicators, not probabilities of exploitation or proof of vulnerabilities.</small></div></div>',
            unsafe_allow_html=True,
        )

        chart_col, explain_col = st.columns([1.25, 1], gap="large")
        with chart_col:
            average_risk = float(results["risk_score"].mean())
            average_risk = max(0.0, min(100.0, average_risk))
            if average_risk >= 65:
                gauge_color = "var(--danger)"
                average_level = "High"
            elif average_risk >= 35:
                gauge_color = "var(--warning)"
                average_level = "Medium"
            else:
                gauge_color = "var(--success)"
                average_level = "Low"
            section_heading("Average network risk", "Mean fuzzy-risk score across all returned port records.")
            st.markdown(
                f'<div class="risk-gauge-card"><div class="risk-gauge" '
                f'style="--risk-percent:{average_risk:.1f};--gauge-color:{gauge_color}">'
                f'<div class="risk-gauge-center"><strong>{average_risk:.1f}%</strong>'
                f'<span>AVERAGE RISK</span></div></div>'
                f'<div class="risk-gauge-level {average_level.lower()}">{average_level} average risk</div>'
                '</div>',
                unsafe_allow_html=True,
            )
        with explain_col:
            section_heading("How fuzzy logic helps", "A transparent triage aid—not an AI vulnerability verdict.")
            st.markdown(
                '<div class="panel-card fuzzy-explainer">'
                '<div class="fuzzy-step"><span>01</span><div><b>Inputs</b><p>Port number, open/closed state, and service risk.</p></div></div>'
                '<div class="fuzzy-step"><span>02</span><div><b>Fuzzy rules</b><p>Overlapping low, medium, and high membership functions combine the signals.</p></div></div>'
                '<div class="fuzzy-step"><span>03</span><div><b>Score</b><p>The output is a 0–100 heuristic used to prioritize manual review.</p></div></div>'
                '</div>',
                unsafe_allow_html=True,
            )

        section_heading("Port inventory", "Inspect discovered ports and services. Per-port risk scores are summarized above.")
        inventory_columns = ["port", "protocol", "state", "service", "product", "version", "extrainfo"]
        if "/" in str(scan["target"]):
            inventory_columns.insert(0, "host")
        inventory_columns = [column for column in inventory_columns if column in results.columns]
        inventory = results[inventory_columns].copy()
        available_states = sorted(inventory["state"].dropna().astype(str).unique())
        filter_col, search_col = st.columns([1, 2])
        with filter_col:
            selected_states = st.multiselect("Port states", available_states, default=available_states)
        with search_col:
            search = st.text_input("Search inventory", placeholder="Host, service, state, or port…")
        filtered = inventory[inventory["state"].astype(str).isin(selected_states)].copy()
        if search:
            mask = filtered.astype(str).apply(lambda column: column.str.contains(search, case=False, na=False)).any(axis=1)
            filtered = filtered[mask]
        labels = {"host": "Host / IP", "port": "Port", "protocol": "Protocol", "state": "State", "service": "Service", "product": "Product", "version": "Version", "extrainfo": "Extra info"}
        st.dataframe(filtered.rename(columns=labels), use_container_width=True, hide_index=True)
        st.download_button(
            "↓  Export filtered CSV",
            data=filtered.rename(columns=labels).to_csv(index=False).encode("utf-8"),
            file_name="fuzzynmap-results.csv",
            mime="text/csv",
        )

if st.session_state.scan_history:
    section_heading("Recent scans")
    st.dataframe(pd.DataFrame(st.session_state.scan_history), use_container_width=True, hide_index=True)

st.markdown(
    '<footer class="app-footer"><span>FUZZYNMAP</span> · Use only on systems you are authorized to assess.</footer>',
    unsafe_allow_html=True,
)
