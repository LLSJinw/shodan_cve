import streamlit as st
import dns.resolver
import requests

st.title("🌐 Domain to CVE Table via Shodan API")

# Input domain
domain = st.text_input("Enter a domain name (e.g., example.com):")

def resolve_dns_via_api(domain):
    record_types = ['A', 'MX', 'CNAME']
    results = {"A": [], "MX": [], "CNAME": []}

    for rtype in record_types:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                for ans in answers:
                    results[rtype].append(ans["data"])
        except:
            pass

    return results

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

if st.button("Run Lookup"):
    if domain:
        ip_list = dns_data["A"]

        if not ip_list:
            st.warning("No A records found for this domain.")
        else:
            st.subheader("🔐 CVE Table")
            table_data = []

            for ip in ip_list:
                cves = query_shodan_vulns(ip)
                if cves:
                    cve_links = [f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" for cve in cves]
                    table_data.append({"IP": ip, "CVEs": ", ".join(cve_links)})
                else:
                    table_data.append({"IP": ip, "CVEs": "No known CVEs"})

            # Display the table
            st.table(table_data)
    else:
        st.warning("Please enter a domain.")
