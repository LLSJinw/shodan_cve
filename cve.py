import streamlit as st
import requests
import re
from urllib.parse import quote

# -----------------------------
# Configuration & UI Setup
# -----------------------------
st.set_page_config(page_title="Datadog Presales Recon", page_icon="🔍", layout="wide")

# Custom CSS for better styling
st.markdown("""
    <style>
    .metric-container { background-color: #f0f2f6; padding: 15px; border-radius: 10px; border: 1px solid #d1d5db; }
    .stMetric { text-align: center; }
    </style>
    """, unsafe_allow_value=True)

st.title("🔍 Datadog Presales Recon Helper")
st.caption("Automated Public-Signal Recon for Cloud Infrastructure & Security Exposure.")

# Secrets - These should be set in Streamlit Cloud Secrets or .streamlit/secrets.toml
DNSDUMPSTER_API_KEY = st.secrets.get("dnsdumpster_api_key", "")
OPENCVE_USER = st.secrets.get("opencve_user", "")
OPENCVE_PASS = st.secrets.get("opencve_pass", "")

# -----------------------------
# Helpers & Recon Engines
# -----------------------------
def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.strip()) is not None

def resolve_domain_to_ips(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return [a["data"] for a in data.get("Answer", []) if is_ip(a["data"])]
    except: pass
    return []

def detect_cloud_signals(asset_data):
    """
    Automated logic to flag Cloud Storage and Infrastructure.
    """
    text = " ".join([
        asset_data.get("hostname", ""),
        asset_data.get("asn_name", ""),
        " ".join(asset_data.get("hostnames", [])),
        " ".join(asset_data.get("tags", []))
    ]).lower()

    found = []
    patterns = {
        "Cloud Storage": ["s3.amazonaws", "blob.core", "storage.googleapis", "digitaloceanspaces", "s3-website"],
        "Compute/VM": ["ec2", "amazonaws", "azurewebsites", "googleusercontent", "gcp", "compute.internal"],
        "CDN/Edge": ["cloudfront", "cloudflare", "akamai", "fastly", "azureedge"]
    }

    for category, keys in patterns.items():
        if any(k in text for k in keys):
            found.append(category)
    return list(set(found))

def get_cve_details(cve_id):
    if not OPENCVE_USER: return {"CVE ID": cve_id, "Title": "Key Missing", "CVSS": "N/A"}
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=(OPENCVE_USER, OPENCVE_PASS), timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            score = d.get("metrics", {}).get("cvssV3_1", {}).get("data", {}).get("score", "N/A")
            return {"CVE ID": cve_id, "Title": d.get("title", "No Title"), "CVSS": score}
    except: pass
    return {"CVE ID": cve_id, "Title": "N/A", "CVSS": "N/A"}

# -----------------------------
# Main UI Logic
# -----------------------------
multi_input = st.text_area(
    "Enter Domains or IPs (one per line):", 
    placeholder="example.com\n1.2.3.4", 
    height=120
)

if st.button("🚀 Start Deep Recon"):
    if not multi_input.strip():
        st.warning("Please enter a target.")
        st.stop()

    targets = [t.strip() for t in multi_input.splitlines() if t.strip()]
    all_assets = {}

    with st.status("🔍 Scanning Infrastructure...", expanded=True) as status:
        for t in targets:
            st.write(f"Analyzing: {t}...")
            if is_ip(t):
                all_assets[t] = {"hostname": "Direct IP"}
            else:
                ips = resolve_domain_to_ips(t)
                for ip in ips:
                    all_assets[ip] = {"hostname": t}

        # Enrich with Shodan (InternetDB is free/no key)
        enriched_data = []
        for ip, meta in all_assets.items():
            try:
                res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5).json()
                asset = {**meta, **res, "ip": ip}
                asset["cloud_signals"] = detect_cloud_signals(asset)
                enriched_data.append(asset)
            except: pass
        
        status.update(label="✅ Recon Complete!", state="complete")

    # -----------------------------
    # 1. Automated Count Engine (The Metrics)
    # -----------------------------
    st.subheader("📊 Automated Infrastructure Insights")
    
    # Calculate counts programmatically
    storage_count = sum(1 for a in enriched_data if "Cloud Storage" in a["cloud_signals"])
    compute_count = sum(1 for a in enriched_data if "Compute/VM" in a["cloud_signals"])
    total_cves = sum(len(a.get("vulns", [])) for a in enriched_data)
    
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Cloud Storage Found", storage_count)
    with m2: st.metric("Compute Nodes", compute_count)
    with m3: st.metric("CVE Risks", total_cves)
    with m4: st.metric("Unique Ports", len(set([p for a in enriched_data for p in a.get("ports", [])])))

    # -----------------------------
    # 2. The "Wow Factor" (Dorking Links)
    # -----------------------------
    st.subheader("🎯 Live Deep-Dive (Manual Dorks)")
    st.info("Use these links during conversations to show 'hidden' exposure.")
    
    primary = targets[0]
    dorks = [
        ("📦 S3/Cloud Buckets", f"site:s3.amazonaws.com \"{primary}\" | site:storage.googleapis.com \"{primary}\""),
        ("🔑 Sensitive Files", f"site:{primary} ext:log | ext:env | ext:conf | ext:sql"),
        ("🛠️ Admin Panels", f"site:{primary} inurl:admin | inurl:login | inurl:staging"),
        ("📄 Public Docs", f"site:{primary} ext:pdf | ext:xlsx | ext:docx")
    ]
    
    d_cols = st.columns(4)
    for i, (label, q) in enumerate(dorks):
        url = f"https://www.google.com/search?q={quote(q)}"
        d_cols[i].markdown(f"**[{label}]({url})**")

    st.divider()

    # -----------------------------
    # 3. Asset & CVE Details
    # -----------------------------
    st.subheader("🔐 Detailed Asset Analysis")
    for asset in enriched_data:
        with st.expander(f"🖥️ {asset['ip']} - {asset['hostname']}"):
            c_left, c_right = st.columns(2)
            with c_left:
                st.write(f"**Open Ports:** `{asset.get('ports', [])}`")
                st.write(f"**Cloud Tags:** {asset['cloud_signals'] or 'On-Prem/Other'}")
            with c_right:
                st.write(f"**Hostnames:** {asset.get('hostnames', [])[:3]}")
                st.write(f"**CPEs:** {asset.get('cpes', [])[:3]}")
            
            if asset.get("vulns"):
                st.error(f"Critical Exposure: {len(asset['vulns'])} CVEs detected.")
                if st.checkbox(f"Show CVE Details for {asset['ip']}", key=asset['ip']):
                    rows = [get_cve_details(c) for c in asset["vulns"][:10]]
                    st.table(rows)

    # -----------------------------
    # 4. Presales Framing
    # -----------------------------
    st.info("**Sales Tip:** If 'Cloud Storage' count is > 0, ask: 'How are you currently tracking the security and cost of your public storage buckets?'")
