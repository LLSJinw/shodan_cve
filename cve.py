import streamlit as st
import requests
import socket
import re

st.title("🔍 Multi-Input CVE Lookup (IP + Domain)")

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

def query_shodan_vulns(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except:
        pass
    return []

# --- UI Input Box ---
multi_input = st.text_area("Paste IPs or Domains (one per line):", height=200)

if st.button("Run Lookup"):
    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
    else:
        entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
        all_ips = set()

        st.subheader("🔄 Resolving Domains to IPs (if needed)")
        for entry in entries:
            if is_ip(entry):
                st.markdown(f"✅ **{entry}** (direct IP)")
                all_ips.add(entry)
            else:
                resolved_ips = resolve_domain_to_ips(entry)
                if resolved_ips:
                    st.markdown(f"🌐 **{entry}** ➜ {', '.join(resolved_ips)}")
                    all_ips.update(resolved_ips)
                else:
                    st.warning(f"❌ Could not resolve domain: {entry}")

        if not all_ips:
            st.warning("No valid IPs to query.")
        else:
            st.subheader("🔐 Shodan CVE Lookup Table")
            table = []

            for ip in sorted(all_ips):
                cves = query_shodan_vulns(ip)
                if cves:
                    cve_links = [f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" for cve in cves]
                    table.append({"IP": ip, "CVEs": ", ".join(cve_links)})
                else:
                    table.append({"IP": ip, "CVEs": "No known CVEs"})

            st.table(table)
