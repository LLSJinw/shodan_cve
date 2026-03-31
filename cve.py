import streamlit as st
import requests
import re
from urllib.parse import quote

st.set_page_config(page_title="Datadog Presales Recon", page_icon="🔍", layout="wide")
st.title("🔍 Datadog Presales Recon Helper")
st.caption("Public-signal recon to support presales conversations. Use findings as discussion starters.")

# Secrets - Ensure these are in your .streamlit/secrets.toml
DNSDUMPSTER_API_KEY = st.secrets.get("dnsdumpster_api_key", "")
OPENCVE_USER = st.secrets.get("opencve_user", "")
OPENCVE_PASS = st.secrets.get("opencve_pass", "")

# -----------------------------
# Helpers
# -----------------------------
def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.strip()) is not None

def resolve_domain_to_ips(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            return [a["data"] for a in answers if is_ip(a["data"])]
    except Exception:
        pass
    return []

def fetch_dnsdumpster_data(domain):
    if not DNSDUMPSTER_API_KEY: return {}
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": DNSDUMPSTER_API_KEY}
    assets = {}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for section in ["a", "mx", "ns"]:
                for record in data.get(section, []):
                    host = record.get("host", "")
                    for ip_entry in record.get("ips", []):
                        ip = ip_entry.get("ip")
                        if ip:
                            assets[ip] = {
                                "hostname": host or "Not found",
                                "asn_name": ip_entry.get("asn_name", ""),
                                "country": ip_entry.get("country", ""),
                                "ptr": ip_entry.get("ptr", "")
                            }
    except Exception:
        pass
    return assets

def query_shodan_vulns(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {"ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": []}

def get_cve_details(cve_id):
    if not OPENCVE_USER: return {"CVE ID": cve_id, "Title": "API Key Missing", "CVSS": "N/A"}
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=(OPENCVE_USER, OPENCVE_PASS), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            metrics = data.get("metrics", {})
            score = metrics.get("cvssV3_1", {}).get("data", {}).get("score") or \
                    metrics.get("cvssV3_0", {}).get("data", {}).get("score", "N/A")
            return {"CVE ID": cve_id, "Title": data.get("title", "No Title"), "CVSS": score}
    except Exception:
        pass
    return {"CVE ID": cve_id, "Title": "Not Found", "CVSS": "N/A"}

def detect_cloud_signal(asset):
    text = " ".join([
        asset.get("hostname", ""),
        asset.get("asn_name", ""),
        asset.get("ptr", ""),
        " ".join(asset.get("hostnames", []))
    ]).lower()

    cloud_hits = []
    patterns = {
        "AWS (EC2/ELB)": ["amazonaws", "aws", "cloudfront", "elb.amazonaws"],
        "AWS S3 Bucket": ["s3.amazonaws", "s3-website"],
        "Azure (VM/App)": ["azure", "azurewebsites", "trafficmanager"],
        "Azure Storage": ["core.windows.net", "blob.core", "azureedge"],
        "GCP (Compute)": ["googleusercontent", "appspot", "google cloud", "gcp"],
        "GCP Storage": ["storage.googleapis", "commondatastorage"],
        "Cloudflare": ["cloudflare"],
        "DigitalOcean": ["digitaloceanspaces", "digitalocean"]
    }

    for provider, keys in patterns.items():
        if any(k in text for k in keys):
            cloud_hits.append(provider)
    return sorted(set(cloud_hits))

def get_dork_queries(target):
    # If target is an IP, we dork the IP, otherwise the domain
    dorks = [
        {"label": "📦 Cloud Storage", "q": f"site:s3.amazonaws.com \"{target}\" | site:storage.googleapis.com \"{target}\" | site:core.windows.net \"{target}\""},
        {"label": "🔑 Sensitive Files", "q": f"site:{target} ext:log | ext:txt | ext:conf | ext:env | ext:ini"},
        {"label": "🛠️ Exposed Panels", "q": f"site:{target} inurl:admin | inurl:login | inurl:dev | inurl:staging"},
        {"label": "📄 Public Docs", "q": f"site:{target} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx"},
        {"label": "🚀 Subdomains", "q": f"site:*.{target} -www"}
    ]
    return dorks

def infer_observability_use_cases(assets):
    total_assets = len(assets)
    total_cves = sum(len(a.get("vulns", [])) for a in assets)
    unique_ports = sorted(set(p for a in assets for p in a.get("ports", [])))
    cloud_signals = sorted(set(sig for a in assets for sig in a.get("cloud_signals", [])))

    # Logic for summary scoring
    score = 0
    reasons = []
    if total_assets >= 3: score += 1; reasons.append("Multiple assets detected")
    if cloud_signals: score += 1; reasons.append(f"Cloud signals: {', '.join(cloud_signals)}")
    if total_cves >= 1: score += 1; reasons.append("Public CVE exposure detected")
    
    fit = "High" if score >= 3 else "Medium" if score >= 2 else "Low"
    
    return {
        "score": score, "fit": fit, "reasons": reasons,
        "total_assets": total_assets, "total_cves": total_cves,
        "unique_ports": unique_ports, "cloud_signals": cloud_signals
    }

# -----------------------------
# UI
# -----------------------------
multi_input = st.text_area(
    "Paste IPs or Domains (one per line):",
    height=150,
    placeholder="example.com\n1.2.3.4"
)

run = st.button("Run Recon")

if run:
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
        st.stop()

    entries = [line.strip() for line in multi_input.splitlines() if line.strip()]
    all_assets = {}

    st.subheader("🔄 Resolving Assets")
    for entry in entries:
        if is_ip(entry):
            all_assets[entry] = {"hostname": "Direct IP", "asn_name": "", "country": "", "ptr": ""}
        else:
            resolved = resolve_domain_to_ips(entry)
            for ip in resolved:
                all_assets[ip] = {"hostname": entry, "asn_name": "", "country": "", "ptr": ""}
            
            dnsdump_data = fetch_dnsdumpster_data(entry)
            all_assets.update(dnsdump_data)

    if not all_assets:
        st.error("No assets found.")
        st.stop()

    # Enrichment
    enriched_assets = []
    for ip, meta in all_assets.items():
        shodan_data = query_shodan_vulns(ip)
        asset = {**meta, "ip": ip, **shodan_data}
        asset["cloud_signals"] = detect_cloud_signal(asset)
        enriched_assets.append(asset)

    summary = infer_observability_use_cases(enriched_assets)

    # -----------------------------
    # NEW: Dorking Section
    # -----------------------------
    st.subheader("🎯 Google Dorking (Deep Search)")
    st.caption("Click a link to launch a Google search for hidden assets.")
    
    # Use the first domain/IP for dorking
    dork_target = entries[0]
    dorks = get_dork_queries(dork_target)
    
    cols = st.columns(len(dorks))
    for i, dork in enumerate(dorks):
        google_url = f"https://www.google.com/search?q={quote(dork['q'])}"
        cols[i].markdown(f"**[{dork['label']}]({google_url})**")

    st.markdown("---")

    # Executive Summary
    st.subheader("📌 Presales Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Assets", summary["total_assets"])
    c2.metric("Ports", len(summary["unique_ports"]))
    c3.metric("CVEs", summary["total_cves"])
    c4.metric("Fit Score", summary["fit"])

    # Detail View
    st.subheader("🔐 Asset Detail")
    for asset in enriched_assets:
        with st.expander(f"🖥️ {asset['ip']} ({asset['hostname']})"):
            colA, colB = st.columns(2)
            with colA:
                st.write(f"**ASN:** {asset.get('asn_name', 'N/A')}")
                st.write(f"**Ports:** `{asset.get('ports', [])}`")
            with colB:
                st.write(f"**Cloud:** {', '.join(asset['cloud_signals']) if asset['cloud_signals'] else 'None'}")
                st.write(f"**Tags:** {asset.get('tags', [])}")
            
            if asset.get("vulns"):
                st.warning(f"Found CVEs: {', '.join(asset['vulns'])}")
                rows = [get_cve_details(c) for c in asset["vulns"][:5]] # Limit to 5 for speed
                st.table(rows)
