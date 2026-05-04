import streamlit as st
import requests
import time
import pandas as pd

# ── Configuration ─────────────────────────────────────────────────────────────
API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="SiteMap Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background-color: #1E1E1E;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #333;
    }
    .metric-value { font-size: 2rem; font-weight: bold; color: #4CAF50; }
    .metric-label { font-size: 1rem; color: #888; }
    .stDataFrame { width: 100%; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ SiteMap Guard v4.0")
st.subheader("Autonomous Web Vulnerability & Sitemap Scanner")
st.markdown("Enter a target domain below to initiate a deep security scan.")

# ── Input Area ────────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])
with col1:
    target_url = st.text_input("Target URL", placeholder="https://example.com/", label_visibility="collapsed")
with col2:
    scan_btn = st.button("Launch Scan", use_container_width=True, type="primary")

# ── State Management ──────────────────────────────────────────────────────────
if "task_id" not in st.session_state:
    st.session_state.task_id = None
if "scan_status" not in st.session_state:
    st.session_state.scan_status = None
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None

# ── Trigger Scan ──────────────────────────────────────────────────────────────
if scan_btn and target_url:
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    with st.spinner("Initializing Scan Engine..."):
        try:
            res = requests.post(f"{API_URL}/scan", json={"url": target_url}, timeout=10)
            if res.status_code == 200:
                data = res.json()
                st.session_state.task_id = data.get("task_id")
                st.session_state.scan_status = "running"
                st.session_state.scan_results = None
            else:
                st.error(f"Failed to start scan: {res.text}")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to FastAPI backend. Is it running on http://localhost:8000 ?")

# ── Polling & Status ──────────────────────────────────────────────────────────
if st.session_state.task_id and st.session_state.scan_status == "running":
    status_container = st.empty()
    progress_bar = st.progress(0)
    
    while st.session_state.scan_status == "running":
        try:
            res = requests.get(f"{API_URL}/status/{st.session_state.task_id}", timeout=10)
            if res.status_code == 200:
                data = res.json()
                status = data.get("status")
                
                if status == "running":
                    status_container.info(f"⏳ Scan is running on target: {data.get('target', target_url)}... Please wait (this may take a few minutes depending on passive recon).")
                elif status == "completed":
                    st.session_state.scan_status = "completed"
                    st.session_state.scan_results = data.get("results")
                    progress_bar.progress(100)
                    status_container.success("✅ Scan completed successfully!")
                    break
                elif status == "failed":
                    st.session_state.scan_status = "failed"
                    error_msg = data.get("error", "Unknown error")
                    status_container.error(f"❌ Scan failed: {error_msg}")
                    break
        except Exception as e:
            status_container.warning(f"Connection issue while polling: {e}")
            
        time.sleep(3)

# ── Results Dashboard ─────────────────────────────────────────────────────────
if st.session_state.scan_results:
    results = st.session_state.scan_results
    
    # Safely extract data
    live_targets = results.get("live_targets", [])
    real_live = [t for t in live_targets if t.get("status", 0) not in (0,)]
    
    header_findings = results.get("header_findings", [])
    real_header = [f for f in header_findings if f.get("type") != "connection_error"]
    
    nuclei_findings = results.get("nuclei_findings", [])
    threat_findings = results.get("threat_findings", [])
    js_secrets = results.get("js_secrets", [])
    plugin_findings = results.get("plugin_findings", [])
    dns_info = results.get("dns_info", {})
    diff = results.get("diff", {})

    total_vulns = len(real_header) + len(nuclei_findings) + len(threat_findings) + len(js_secrets) + len(plugin_findings)

    # Metrics Row
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Live Hosts (Confirmed)", f"{len(real_live)}", f"Out of {len(live_targets)} discovered")
    m2.metric("Total Vulnerabilities", total_vulns)
    m3.metric("JS Secrets", len(js_secrets))
    m4.metric("Live Subdomains", len(dns_info.get("live_subdomains", [])))
    
    st.markdown("---")

    # Tabs
    t1, t2, t3, t4, t5 = st.tabs(["🌐 Infrastructure", "🔗 Live Endpoints", "🚨 Vulnerabilities", "🔑 Secrets & Plugins", "🔄 Scan History (Diff)"])
    
    # ── Tab 1: Infrastructure ──
    with t1:
        st.subheader("DNS Reconnaissance")
        dns_col1, dns_col2 = st.columns(2)
        with dns_col1:
            st.markdown(f"**A Records:** {', '.join(dns_info.get('a', []))}")
            st.markdown(f"**MX Records:** {', '.join(dns_info.get('mx', []))}")
            st.markdown(f"**NS Records:** {', '.join(dns_info.get('ns', []))}")
        with dns_col2:
            st.markdown(f"**Email Provider:** {dns_info.get('email_provider', 'Unknown')}")
            st.markdown(f"**DMARC:** {dns_info.get('dmarc', 'Not configured')}")
            st.markdown(f"**CDN:** {dns_info.get('cdn', 'None')}")
            
        subs = dns_info.get("live_subdomains", [])
        if subs:
            st.subheader(f"Live Subdomains ({len(subs)})")
            sub_df = pd.DataFrame([{"Subdomain": s["subdomain"], "IPs": ", ".join(s["ips"])} for s in subs])
            st.dataframe(sub_df, use_container_width=True, hide_index=True)

    # ── Tab 2: Live Endpoints ──
    with t2:
        st.subheader("Discovered Pages & API Routes")
        if real_live:
            ep_data = []
            for t in real_live:
                ep_data.append({
                    "Status": t.get("status"),
                    "URL": t.get("url"),
                    "Title": t.get("title", ""),
                    "Tech Stack": ", ".join(t.get("tech", []))
                })
            st.dataframe(pd.DataFrame(ep_data), use_container_width=True, hide_index=True)
        else:
            st.info("No live endpoints discovered.")

    # ── Tab 3: Vulnerabilities ──
    with t3:
        st.subheader("Security Header Findings")
        if real_header:
            # Group by name/severity
            seen_hdr = {}
            for f in real_header:
                key = (f.get("type"), f.get("name"))
                if key not in seen_hdr:
                    seen_hdr[key] = {
                        "Severity": f.get("severity", "info").upper(),
                        "Vulnerability": f.get("name", ""),
                        "Affected URLs": 1,
                        "Sample URL": f.get("url", ""),
                        "Details": f.get("details", "")
                    }
                else:
                    seen_hdr[key]["Affected URLs"] += 1

            st.dataframe(pd.DataFrame(list(seen_hdr.values())), use_container_width=True, hide_index=True)
            
            # Show remediations logic natively here if needed, but the cli.py pulls from remediations module. 
            # For simplicity, we just list the raw details here.
        else:
            st.success("No header misconfigurations found!")

        st.subheader("Nuclei & Threat Feeds")
        if nuclei_findings:
            nuc_df = pd.DataFrame([{
                "Severity": f.get("info", {}).get("severity", "unknown").upper(),
                "Name": f.get("info", {}).get("name", "unknown"),
                "URL": f.get("matched-at", f.get("url", ""))
            } for f in nuclei_findings])
            st.dataframe(nuc_df, use_container_width=True, hide_index=True)
        else:
            st.success("No Nuclei findings!")
            
        if threat_findings:
            threat_df = pd.DataFrame([{
                "Severity": f.get("severity", "high").upper(),
                "Type": f.get("type", "malicious"),
                "URL": f.get("url", "")
            } for f in threat_findings])
            st.dataframe(threat_df, use_container_width=True, hide_index=True)

    # ── Tab 4: Secrets & Plugins ──
    with t4:
        st.subheader("JavaScript Secrets Harvested")
        if js_secrets:
            js_df = pd.DataFrame([{
                "Severity": f.get("severity", "high").upper(),
                "Secret Name": f.get("name", ""),
                "Found In URL": f.get("url", ""),
                "Details": f.get("details", "")
            } for f in js_secrets])
            st.dataframe(js_df, use_container_width=True, hide_index=True)
        else:
            st.success("No embedded secrets found in Javascript bundles.")
            
        st.subheader("Plugin Findings (CORS/Open Redirect)")
        if plugin_findings:
            pl_df = pd.DataFrame([{
                "Severity": f.get("severity", "info").upper(),
                "Finding": f.get("name", ""),
                "URL": f.get("url", ""),
                "Details": f.get("details", "")
            } for f in plugin_findings])
            st.dataframe(pl_df, use_container_width=True, hide_index=True)
        else:
            st.info("No plugin vulnerabilities triggered.")

    # ── Tab 5: Scan History (Diff) ──
    with t5:
        st.subheader("Changes Since Last Scan")
        if not diff or not any(diff.values()):
            st.info("No changes detected since the last scan (or this is the first scan).")
        else:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("### 📈 New Discoveries")
                if diff.get("new_urls"):
                    st.success(f"{len(diff['new_urls'])} New URLs Discovered")
                    with st.expander("View New URLs"):
                        for u in diff['new_urls']: st.code(u)
                if diff.get("new_findings"):
                    st.error(f"{len(diff['new_findings'])} New Vulnerabilities")
                    with st.expander("View New Findings"):
                        for f in diff['new_findings']: st.markdown(f"- **{f[0]}** at {f[1]}")
                        
            with c2:
                st.markdown("### 📉 Remediations / Removals")
                if diff.get("gone_urls"):
                    st.warning(f"{len(diff['gone_urls'])} URLs Offline")
                if diff.get("fixed_findings"):
                    st.success(f"{len(diff['fixed_findings'])} Vulnerabilities Fixed")
                    with st.expander("View Fixed Findings"):
                        for f in diff['fixed_findings']: st.markdown(f"- **{f[0]}** at {f[1]}")
