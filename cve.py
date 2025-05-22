import streamlit as st
import requests
import socket
import re

st.set_page_config(page_title="Multi-Input CVE Lookup", page_icon="🔍")
st.title("🔍 Multi-Input CVE Lookup (IP + Domain + DNSDumpster)")

DNSDUMPSTER_API_KEY = "f45c10dee6c277ed34f0168bed29a936d92d52c60eb65d011104046f2ae4740b"

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

def fetch_dnsdumpster_ips(domain):
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    headers = {"X-API-Key": DNSDUMPSTER_API_KEY}
    ips = set()
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for section in ["a", "mx", "ns"]:
                for record in data.get(section, []):
                    for ip_entry in record.get("ips", []):
                        ip = ip_entry.get("ip")
                        if ip: ips.add(ip)
    except:
        pass
    return list(ips)

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

# --- UI Input Box ---
multi_input = st.text_area("Paste IPs or Domains (one per line):", height=200)

if st.button("Run Lookup"):
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
    else:
        entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
        all_ips = set()

        st.subheader("🔄 Resolving & Enumerating IPs")
        for entry in entries:
            if is_ip(entry):
                st.markdown(f"✅ **{entry}** (direct IP)")
                all_ips.add(entry)
            else:
                resolved = resolve_domain_to_ips(entry)
                if resolved:
                    st.markdown(f"🌐 **{entry}** ➔ DNS A Record: {', '.join(resolved)}")
                    all_ips.update(resolved)
                else:
                    st.warning(f"❌ Could not resolve A record for: {entry}")

                dnsdump_ips = fetch_dnsdumpster_ips(entry)
                if dnsdump_ips:
                    st.markdown(f"🔍 **{entry}** ➔ DNSDumpster IPs: {', '.join(dnsdump_ips)}")
                    all_ips.update(dnsdump_ips)
                else:
                    st.info(f"ℹ️ No DNSDumpster results for: {entry}")

        if not all_ips:
            st.warning("No valid IPs to query.")
        else:
            st.subheader("🔐 Shodan CVE & Port Lookup Table")
            table = []

            for ip in sorted(all_ips):
                ports, vulns = query_shodan_vulns(ip)
                port_str = ", ".join(str(p) for p in ports) if ports else "None"
                cve_links = [f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" for cve in vulns] if vulns else ["No known CVEs"]

                table.append({
                    "IP": ip,
                    "Open TCP Ports": port_str,
                    "CVEs": ", ".join(cve_links)
                })

            st.table(table)
