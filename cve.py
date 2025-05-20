import streamlit as st
import requests

st.title("🌐 Domain → IP → CVE Lookup (Google DNS + Shodan API)")

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

# --- Streamlit UI ---

domain = st.text_input("Enter a domain (e.g., example.com):")

if st.button("Run Lookup"):
    if not domain:
        st.warning("Please enter a domain.")
    else:
        dns_data = resolve_dns_via_api(domain)

        st.subheader("📡 DNS Records")
        for record_type, values in dns_data.items():
            st.write(f"**{record_type} Records:** {', '.join(values) if values else 'None'}")

        ip_list = dns_data["A"]

        if not ip_list:
            st.warning("No A records found to scan with Shodan.")
        else:
            st.subheader("🔐 CVEs from Shodan InternetDB")

            result_table = []
            for ip in ip_list:
                cves = query_shodan_vulns(ip)
                if cves:
                    cve_links = [f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})" for cve in cves]
                    result_table.append({"IP": ip, "CVEs": ", ".join(cve_links)})
                else:
                    result_table.append({"IP": ip, "CVEs": "No known CVEs"})

            st.table(result_table)
