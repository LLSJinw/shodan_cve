import streamlit as st
import requests
import socket
import re

st.set_page_config(page_title="Multi-Input CVE Lookup", page_icon="🔍")
st.title("🔍 Multi-Input CVE Lookup (IP + Domain + DNSDumpster)")

DNSDUMPSTER_API_KEY = "f45c10dee6c277ed34f0168bed29a936d92d52c60eb65d011104046f2ae4740b"
OPENCVE_USER = "thirasit.kanti@gmail.com"
OPENCVE_PASS = "SxT74uZ3RULRLP@"


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

def fetch_dnsdumpster_data(domain):
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": DNSDUMPSTER_API_KEY}
    ip_host_map = {}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for section in ["a", "mx", "ns"]:
                for record in data.get(section, []):
                    host = record.get("host", "")
                    for ip_entry in record.get("ips", []):
                        ip = ip_entry.get("ip")
                        if ip:
                            ip_host_map[ip] = host
    except:
        pass
    return ip_host_map

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

def get_cve_details(cve_id):
    url = f"https://app.opencve.io/api/cve/{cve_id}"
    try:
        resp = requests.get(url, auth=(OPENCVE_USER, OPENCVE_PASS), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            title = data.get("title", "")
            score = data.get("metrics", {}).get("cvssV2_0", {}).get("data", {}).get("score", "N/A")
            return {"CVE ID": cve_id, "Title": title, "CVSS 2.0": score}
    except:
        pass
    return {"CVE ID": cve_id, "Title": "Not Found", "CVSS 2.0": "N/A"}

# --- UI Input Box ---
multi_input = st.text_area("Paste IPs or Domains (one per line):", height=200)

if st.button("Run Lookup"):
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
    else:
        entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
        all_ips = {}

        st.subheader("🔄 Resolving & Enumerating IPs")
        for entry in entries:
            if is_ip(entry):
                st.markdown(f"✅ **{entry}** (direct IP)")
                all_ips[entry] = "Not found"
            else:
                resolved = resolve_domain_to_ips(entry)
                if resolved:
                    st.markdown(f"🌐 **{entry}** ➔ DNS A Record: {', '.join(resolved)}")
                    for ip in resolved:
                        all_ips[ip] = entry
                else:
                    st.warning(f"❌ Could not resolve A record for: {entry}")

                dnsdump_data = fetch_dnsdumpster_data(entry)
                if dnsdump_data:
                    for ip, host in dnsdump_data.items():
                        all_ips[ip] = host
                    st.markdown(f"🔍 **{entry}** ➔ DNSDumpster IPs: {', '.join(dnsdump_data.keys())}")
                else:
                    st.info(f"ℹ️ No DNSDumpster results for: {entry}")

        if not all_ips:
            st.warning("No valid IPs to query.")
        else:
            st.subheader("🔐 Shodan CVE & Port Lookup Table")
            main_table = []
            detailed_cves = []

            for ip, hostname in sorted(all_ips.items()):
                ports, vulns = query_shodan_vulns(ip)
                port_str = ", ".join(str(p) for p in ports) if ports else "None"
                cve_list = vulns if vulns else []

                main_table.append({
                    "IP": ip,
                    "Hostname": hostname,
                    "Open TCP Ports": port_str,
                    "CVEs": ", ".join(cve_list) if cve_list else "No known CVEs"
                })

                for cve in cve_list:
                    details = get_cve_details(cve)
                    detailed_cves.append(details)

            st.table(main_table)

            if detailed_cves:
                st.markdown("### 📋 Detailed CVE Information")
                st.table(detailed_cves)
