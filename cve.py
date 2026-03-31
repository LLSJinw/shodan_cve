import streamlit as st
import requests
import re
from urllib.parse import quote

# -----------------------------
# 1. Configuration & UI Setup
# -----------------------------
st.set_page_config(page_title="Datadog Presales Recon", page_icon="🔍", layout="wide")

# Fixed CSS: Simpler approach to avoid rendering errors
st.markdown("""
    <style>
    div[data-testid="stMetric"] {
        background-color: #f8f9fb;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #e6e9ef;
    }
    </style>
    """, unsafe_allow_value=True)

st.title("🔍 Datadog Presales Recon Helper")
st.caption("Automated Public-Signal Recon for Cloud Infrastructure & Security Exposure.")

# Secrets Handling with Defaults to prevent NoneType Errors
DNSDUMPSTER_API_KEY = st.secrets.get("dnsdumpster_api_key", "")
OPENCVE_USER = st.secrets.get("opencve_user", "")
OPENCVE_PASS = st.secrets.get("opencve_pass", "")

# -----------------------------
# 2. Helpers & Recon Engines
# -----------------------------
def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.strip()) is not None

def resolve_domain_to_ips(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return [a["data"] for a in data.get("Answer", []) if is_ip(a["data"])]
    except:
        pass
    return []

def detect_cloud_signals(asset_data):
    text = " ".join([
        str(asset_data.get("hostname", "")),
        str(asset_data.get("asn_name", "")),
        " ".join(asset_data.get("hostnames", [])),
        " ".join(asset_data.get("tags", []))
    ]).lower()

    found = []
    patterns = {
        "Cloud Storage": ["s3.amazonaws", "blob.core", "storage.googleapis", "digitaloceanspaces"],
        "Compute/VM": ["ec2", "amazonaws", "azurewebsites", "googleusercontent", "gcp"],
        "CDN/Edge": ["cloudfront", "cloudflare", "akamai", "fastly"]
    }
    for category, keys in patterns.items():
        if any(k in text for k in keys):
            found.append(category)
    return list(set(found))

def get_cve_details(cve_id):
    if not OPENCVE_USER or not OPENCVE_PASS:
        return {"CVE ID": cve_id, "Title": "OpenCVE Credentials Missing", "CVSS": "N/A"}
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=(OPENCVE_USER, OPENCVE_PASS), timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            score = d.get("metrics", {}).get("cvssV3_1", {}).get("data", {}).get("score") or \
                    d.get("metrics", {}).get("cvssV3_0", {}).get("data", {}).get("score", "N/A")
            return {"CVE ID": cve_id, "Title": d.get("summary", "No Summary Available"), "CVSS": score}
    except:
        pass
    return {"CVE ID": cve_id, "Title": "Details Fetch Failed", "CVSS": "N/A"}

# -----------------------------
# 3. Main UI Logic
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
                if not ips: # Fallback if DNS fails
                    st.write(f"⚠️ Could not resolve {t}")
                for ip in ips:
                    all_assets[ip] = {"hostname": t}

        enriched_data = []
        for ip, meta in all_assets.items():
            try:
                # Shodan InternetDB - No API Key required
                res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5).json()
                asset = {**meta, **res, "ip": ip}
                asset["cloud_signals"] = detect_cloud_signals(asset)
                enriched_data.append(asset)
            except:
                # If Shodan fails, still keep basic info
                asset = {**meta, "ip": ip, "ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
                asset["cloud_signals"] = detect_cloud_signals(asset)
                enriched_data.append(asset)
        
        status.update(label="✅ Recon Complete!", state="complete")

    # -----------------------------
    # 4. Automated Count Engine (Safety Applied)
    # -----------------------------
    st.subheader("📊 Automated Infrastructure Insights")
    
    # Defaults to 0 to prevent TypeError
    storage_cnt = 0
    compute_cnt = 0
    vuln_cnt = 0
    ports_found = set()

    if enriched_data:
        storage_cnt = sum(1 for a in enriched_data if "Cloud Storage" in a.get("cloud_signals", []))
        compute_cnt = sum(1 for a in enriched_data if "Compute/VM" in a.get("cloud_signals", []))
        vuln_cnt = sum(len(a.get("vulns", [])) for a in enriched_data)
        for a in enriched_data:
            for p in a.get("ports", []):
                ports_found.add(p)

    m1, m2, m3, m4 = st.columns(4)
    # Convert all values to string to ensure st.metric doesn't crash
    m1.metric("Cloud Storage", str(storage_cnt))
    m2.metric("Compute Nodes", str(compute_cnt))
    m3.metric("CVE Risks", str(vuln_cnt))
    m4.metric("Unique Ports", str(len(ports_found)))

    # -----------------------------
    # 5. The "Wow Factor" (Dorking Links)
    # -----------------------------
    st.subheader("🎯 Live Deep-Dive (Manual Dorks)")
    primary_target = targets[0]
    
    dorks = [
        ("📦 Cloud Buckets", f"site:s3.amazonaws.com \"{primary_target}\" | site:storage.googleapis.com \"{primary_target}\""),
        ("🔑 Sensitive Files", f"site:{primary_target} ext:log | ext:env | ext:conf | ext:sql"),
        ("🛠️ Admin Panels", f"site:{primary_target} inurl:admin | inurl:login | inurl:staging"),
        ("📄 Public Docs", f"site:{primary_target} ext:pdf | ext:xlsx | ext:docx")
    ]
    
    d_cols = st.columns(4)
    for i, (label, q) in enumerate(dorks):
        google_url = f"https://www.google.com/search?q={quote(q)}"
        d_cols[i].markdown(f"**[{label}]({google_url})**")

    st.divider()

    # -----------------------------
    # 6. Detailed Asset View
    # -----------------------------
    st.subheader("🔐 Detailed Asset Analysis")
    for asset in enriched_data:
        with st.expander(f"🖥️ {asset['ip']} - {asset['hostname']}"):
            c_left, c_right = st.columns(2)
            with c_left:
                st.write(f"**Open Ports:** `{asset.get('ports', [])}`")
                st.write(f"**Cloud Signals:** {', '.join(asset['cloud_signals']) if asset['cloud_signals'] else 'None Detected'}")
            with c_right:
                st.write(f"**Shodan Hostnames:** {asset.get('hostnames', [])[:3]}")
                st.write(f"**CPEs (Tech Stack):** {asset.get('cpes', [])[:3]}")
            
            if asset.get("vulns"):
                st.error(f"Found {len(asset['vulns'])} CVEs")
                # Add a unique key for each checkbox to prevent Streamlit errors
                if st.checkbox(f"Show CVE Details ({asset['ip']})", key=f"check_{asset['ip']}"):
                    with st.spinner("Fetching CVE info..."):
                        cve_rows = [get_cve_details(c) for c in asset["vulns"][:8]]
                        st.table(cve_rows)
