import streamlit as st
import requests

# Optional: insert your NVD API key here (free)
NVD_API_KEY = "YOUR_NVD_API_KEY"

def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            desc = data["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
            return desc
        else:
            return "Description not found."
    except Exception:
        return "Error retrieving CVE info."

st.title("🔎 Shodan CVE Analyzer")

ip_or_domain = st.text_input("Enter IP Address or Domain:")

if st.button("Check Vulnerabilities"):
    if ip_or_domain:
        url = f"https://internetdb.shodan.io/{ip_or_domain}"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                data = resp.json()

                st.subheader("📡 Host Info")
                st.write(f"IP: {data.get('ip')}")
                st.write(f"Ports: {data.get('ports')}")
                st.write(f"CPEs: {data.get('cpes')}")

                vulns = data.get("vulns", [])
                if vulns:
                    st.subheader("🛡️ Vulnerabilities (CVEs)")
                    for cve in vulns:
                        desc = get_cve_details(cve)
                        st.markdown(f"**[{cve}](https://nvd.nist.gov/vuln/detail/{cve})**: {desc}")
                else:
                    st.success("No CVEs found.")
            else:
                st.error(f"Shodan API returned status code {resp.status_code}")
        except Exception as e:
            st.error(f"Error: {e}")
    else:
        st.warning("Please enter a valid IP or domain.")
