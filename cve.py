import streamlit as st
import requests
import socket
import re

st.set_page_config(page_title="Multi-Input CVE Lookup", page_icon="🔍")
st.title("🔍 Multi-Input CVE Lookup (IP + Domain + DNSDumpster)")

DNSDUMPSTER_API_KEY = "f45c10dee6c277ed34f0168bed29a936d92d52c60eb65d011104046f2ae4740b"
OPENCVE_AUTH = ("thirasit.kanti@gmail.com", "SxT74uZ3RULRLP@")

def is_ip(s):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s.strip()) is not None

def resolve_domain_to_ips(domain):
    url = f"https://dns.google/resolve?name={domain}&type=A"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            return [a["data"] for a in answers if is_ip(a["data"])]
    except:
        pass
    return []

def fetch_dnsdumpster_records(domain):
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": DNSDUMPSTER_API_KEY}
    records = []
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for section in ["a", "mx", "ns"]:
                for record in data.get(section, []):
                    for ip_entry in record.get("ips", []):
                        ip = ip_entry.get("ip")
                        if ip:
                            records.append((record.get("host", ""), ip))
    except:
        pass
    return records

def query_shodan_vulns(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            return ports, vulns
    except:
        pass
    return [], []

def get_cve_info(cve_id):
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=OPENCVE_AUTH, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "CVE ID": cve_id,
                "Title": data.get("title", "N/A"),
                "CVSS 2.0 Score": data.get("metrics", {}).get("cvssV2_0", {}).get("data", {}).get("score", "N/A")
            }
    except:
        pass
    return {"CVE ID": cve_id, "Title": "N/A", "CVSS 2.0 Score": "N/A"}

# --- UI Input Box ---
multi_input = st.text_area("Paste IPs or Domains (one per line):", height=200)

if st.button("Run Lookup"):
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
    else:
        entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
        all_records = set()

        st.subheader("🔄 Resolving & Enumerating IPs")
        for entry in entries:
            if is_ip(entry):
                st.markdown(f"✅ **{entry}** (direct IP)")
                all_records.add(("", entry))
            else:
                resolved = resolve_domain_to_ips(entry)
                for ip in resolved:
                    st.markdown(f"🌐 **{entry}** ➔ DNS A Record: {ip}")
                    all_records.add((entry, ip))
                dns_records = fetch_dnsdumpster_records(entry)
                if dns_records:
                    for host, ip in dns_records:
                        st.markdown(f"🔍 DNSDumpster ➔ {host} → {ip}")
                        all_records.add((host, ip))
                else:
                    st.info(f"ℹ️ No DNSDumpster results for: {entry}")

        if not all_records:
            st.warning("No valid IPs to query.")
        else:
            st.subheader("🔐 Shodan CVE & Port Lookup Table")
            for host, ip in sorted(all_records, key=lambda x: x[1]):
                ports, vulns = query_shodan_vulns(ip)
                st.markdown(f"#### 🔹 IP: {ip}")
                if host:
                    st.markdown(f"**Hostname:** {host}")
                st.markdown(f"**Open TCP Ports:** {', '.join(str(p) for p in ports) if ports else 'None'}")

                if vulns:
                    with st.expander(f"🦠 {len(vulns)} CVEs found – click to expand"):
                        cve_table = []
                        for cve_id in vulns:
                            info = get_cve_info(cve_id)
                            cve_table.append(info)
                        st.table(cve_table)
                else:
                    st.markdown("✅ No known CVEs found.")
