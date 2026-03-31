import streamlit as st
import requests
import re
from collections import Counter

st.set_page_config(page_title="Datadog Presales Recon", page_icon="🔍", layout="wide")
st.title("🔍 Datadog Presales Recon Helper")
st.caption("Public-signal recon to support presales conversations. Use findings as discussion starters, not as definitive internal facts.")

DNSDUMPSTER_API_KEY = st.secrets["dnsdumpster_api_key"]
OPENCVE_USER = st.secrets["opencve_user"]
OPENCVE_PASS = st.secrets["opencve_pass"]


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
            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            cpes = data.get("cpes", [])
            tags = data.get("tags", [])
            return {
                "ports": ports,
                "vulns": vulns,
                "hostnames": hostnames,
                "cpes": cpes,
                "tags": tags
            }
    except Exception:
        pass

    return {
        "ports": [],
        "vulns": [],
        "hostnames": [],
        "cpes": [],
        "tags": []
    }


def get_cve_details(cve_id):
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=(OPENCVE_USER, OPENCVE_PASS), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            title = data.get("title", "")
            score = (
                data.get("metrics", {})
                .get("cvssV3_0", {})
                .get("data", {})
                .get("score", "N/A")
            )
            if score == "N/A":
                score = (
                    data.get("metrics", {})
                    .get("cvssV3_1", {})
                    .get("data", {})
                    .get("score", "N/A")
                )
            return {"CVE ID": cve_id, "Title": title or "Not Found", "CVSS": score}
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
        "AWS": ["amazonaws", "aws", "cloudfront", "elb.amazonaws"],
        "Azure": ["azure", "azurewebsites", "trafficmanager"],
        "GCP": ["googleusercontent", "appspot", "google cloud", "gcp"],
        "Cloudflare": ["cloudflare", "ns.cloudflare.com"],
        "Huawei Cloud": ["hwclouds", "huawei clouds"],
        "Akamai": ["akamai"],
        "Fastly": ["fastly"]
    }

    for provider, keys in patterns.items():
        if any(k in text for k in keys):
            cloud_hits.append(provider)

    return sorted(set(cloud_hits))


def infer_observability_use_cases(assets):
    total_assets = len(assets)
    total_cves = sum(len(a.get("vulns", [])) for a in assets)
    unique_ports = sorted(set(p for a in assets for p in a.get("ports", [])))
    cloud_signals = sorted(set(sig for a in assets for sig in a.get("cloud_signals", [])))

    api_like = 0
    modern_web = 0
    external_web = 0

    for a in assets:
        hostname_text = (a.get("hostname", "") + " " + " ".join(a.get("hostnames", []))).lower()
        ports = a.get("ports", [])
        cpes_text = " ".join(a.get("cpes", [])).lower()

        if any(x in hostname_text for x in ["api", "gateway", "auth", "app", "mobile", "service"]):
            api_like += 1
        if any(p in ports for p in [80, 443, 8080, 8443, 9443]):
            external_web += 1
        if any(x in cpes_text for x in ["nginx", "openssl", "http_server", "jquery"]) or any(
            p in ports for p in [443, 8443, 8080]
        ):
            modern_web += 1

    score = 0
    reasons = []

    if total_assets >= 3:
        score += 1
        reasons.append("Multiple externally observable assets detected")
    if len(unique_ports) >= 4:
        score += 1
        reasons.append("Multiple service ports detected")
    if cloud_signals:
        score += 1
        reasons.append(f"Cloud / CDN signals detected: {', '.join(cloud_signals)}")
    if api_like >= 1:
        score += 1
        reasons.append("API / application-style endpoints likely present")
    if external_web >= 2:
        score += 1
        reasons.append("Several public-facing web services detected")
    if total_cves >= 1:
        score += 1
        reasons.append("Security exposure signal present from public CVE mapping")

    if score <= 1:
        fit = "Low"
    elif score <= 3:
        fit = "Medium"
    else:
        fit = "High"

    modules = []
    talk_tracks = []

    if external_web >= 1:
        modules.append("Synthetic Monitoring / Availability Monitoring")
        talk_tracks.append(
            "We noticed public-facing services. How do you currently monitor uptime and user-facing availability?"
        )
    if total_assets >= 3 or len(unique_ports) >= 4:
        modules.append("Infrastructure Monitoring")
        talk_tracks.append(
            "You appear to have multiple internet-facing assets and services. Do you have centralized visibility across hosts and endpoints?"
        )
    if api_like >= 1 or modern_web >= 1:
        modules.append("APM / Application Observability")
        talk_tracks.append(
            "This looks like a web or API-driven environment. How does your team troubleshoot latency or trace issues across application flows today?"
        )
    if total_assets >= 2:
        modules.append("Log Management")
        talk_tracks.append(
            "With multiple services exposed, teams often struggle to correlate events quickly. Do you already centralize logs from these systems?"
        )
    if total_cves >= 1:
        modules.append("Security Monitoring / Exposure Context")
        talk_tracks.append(
            "We also see public exposure signals. Do your ops and security teams have a shared view between service health and security events?"
        )

    modules = list(dict.fromkeys(modules))
    talk_tracks = list(dict.fromkeys(talk_tracks))

    return {
        "score": score,
        "fit": fit,
        "reasons": reasons,
        "modules": modules,
        "talk_tracks": talk_tracks,
        "total_assets": total_assets,
        "total_cves": total_cves,
        "unique_ports": unique_ports,
        "cloud_signals": cloud_signals,
    }


# -----------------------------
# UI
# -----------------------------
multi_input = st.text_area(
    "Paste IPs or Domains (one per line):",
    height=180,
    placeholder="example.com\napi.example.com\n1.2.3.4"
)

run = st.button("Run Recon")

if run:
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
        st.stop()

    entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
    all_assets = {}

    st.subheader("🔄 Resolving & Enumerating Assets")

    for entry in entries:
        if is_ip(entry):
            st.markdown(f"✅ **{entry}** (direct IP)")
            all_assets[entry] = {
                "hostname": "Direct IP",
                "asn_name": "",
                "country": "",
                "ptr": "",
            }
            continue

        resolved = resolve_domain_to_ips(entry)
        if resolved:
            st.markdown(f"🌐 **{entry}** ➔ DNS A Record: {', '.join(resolved)}")
            for ip in resolved:
                if ip not in all_assets:
                    all_assets[ip] = {
                        "hostname": entry,
                        "asn_name": "",
                        "country": "",
                        "ptr": "",
                    }
        else:
            st.warning(f"❌ Could not resolve A record for: {entry}")

        dnsdump_data = fetch_dnsdumpster_data(entry)
        if dnsdump_data:
            st.markdown(f"🔍 **{entry}** ➔ DNSDumpster IPs: {', '.join(dnsdump_data.keys())}")
            for ip, meta in dnsdump_data.items():
                all_assets[ip] = meta
        else:
            st.info(f"ℹ️ No DNSDumpster results for: {entry}")

    if not all_assets:
        st.warning("No valid assets found.")
        st.stop()

    # enrich from shodan
    enriched_assets = []
    for ip, meta in sorted(all_assets.items()):
        shodan_data = query_shodan_vulns(ip)
        asset = {
            "ip": ip,
            "hostname": meta.get("hostname", "Not found"),
            "asn_name": meta.get("asn_name", ""),
            "country": meta.get("country", ""),
            "ptr": meta.get("ptr", ""),
            "ports": shodan_data.get("ports", []),
            "vulns": shodan_data.get("vulns", []),
            "hostnames": shodan_data.get("hostnames", []),
            "cpes": shodan_data.get("cpes", []),
            "tags": shodan_data.get("tags", []),
        }
        asset["cloud_signals"] = detect_cloud_signal(asset)
        enriched_assets.append(asset)

    summary = infer_observability_use_cases(enriched_assets)

    # -----------------------------
    # Executive Summary
    # -----------------------------
    st.subheader("📌 Presales Summary")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Assets Found", summary["total_assets"])
    c2.metric("Unique Ports", len(summary["unique_ports"]))
    c3.metric("CVE Signals", summary["total_cves"])
    c4.metric("Datadog Fit", summary["fit"])

    st.markdown("### 🧭 External Signals Observed")
    for r in summary["reasons"] or ["No strong signals identified yet."]:
        st.markdown(f"- {r}")

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("### 🚀 Likely Relevant Product Areas")
        for m in summary["modules"] or ["No strong product mapping yet."]:
            st.markdown(f"- {m}")

    with col_right:
        st.markdown("### 🗣️ Suggested Discovery Questions")
        for t in summary["talk_tracks"] or ["Use standard discovery questions."]:
            st.markdown(f"- {t}")

    if summary["cloud_signals"]:
        st.markdown("### ☁️ Cloud / CDN Indicators")
        st.write(", ".join(summary["cloud_signals"]))

    st.markdown("---")

    # -----------------------------
    # Asset Detail
    # -----------------------------
    st.subheader("🔐 Asset Detail")

    for asset in enriched_assets:
        ip = asset["ip"]
        hostname = asset["hostname"]
        ports = asset["ports"]
        vulns = asset["vulns"]

        title = f"🖥️ {ip} ({hostname})"
        with st.expander(title):
            left, right = st.columns(2)

            with left:
                st.markdown(f"**Hostname:** {hostname}")
                st.markdown(f"**PTR:** {asset['ptr'] or 'N/A'}")
                st.markdown(f"**Country:** {asset['country'] or 'N/A'}")
                st.markdown(f"**ASN / Provider:** {asset['asn_name'] or 'N/A'}")

            with right:
                st.markdown(f"**Open TCP Ports:** `{', '.join(str(p) for p in ports) if ports else 'None'}`")
                st.markdown(f"**Shodan Tags:** {', '.join(asset['tags']) if asset['tags'] else 'None'}")
                st.markdown(f"**Cloud Signals:** {', '.join(asset['cloud_signals']) if asset['cloud_signals'] else 'None'}")

            if asset["hostnames"]:
                st.markdown("**Observed Hostnames from Shodan:**")
                for h in asset["hostnames"]:
                    st.markdown(f"- {h}")

            if asset["cpes"]:
                st.markdown("**Observed Technologies / CPEs:**")
                for cpe in asset["cpes"][:10]:
                    st.markdown(f"- {cpe}")

            st.markdown("### 🛡️ CVE Summary")
            if vulns:
                st.markdown(", ".join(vulns))
                rows = [get_cve_details(cve) for cve in vulns]
                st.table(rows)
            else:
                st.success("✅ No known CVEs found.")

    st.markdown("---")
    st.markdown("### 📝 Presales Framing Note")
    st.info(
        "Use these findings as public-signal conversation starters. Avoid presenting them as proof of internal architecture. "
        "A better phrasing is: 'Based on public observations, it looks like you may have multiple services or cloud components. "
        "How are you currently monitoring them today?'"
    )
