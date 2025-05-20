import streamlit as st
import requests
import socket

# Optional: your NVD API key (can be left blank for now)
NVD_API_KEY = "YOUR_NVD_API_KEY"

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

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

st.title("🔍 Shodan CVE Lookup (IP or Domain)")

user_input = st.text_input("Enter IP Address or Domain Name:")

if st.button("Analyze"):
    if not user_input:
        st.warning("Please enter a valid IP or domain.")
    else:
        # Determine if it's an IP or a domain
        ip = user_input
        try:
            # Try parsing as IP
            socket.inet_aton(user_input)
        except socket.error:
            # If not IP, try resolving as domain
            resolved_ip = resolve_domain(user_input)
            if resolved_ip:
                ip = resolved_ip
                st.info(f"Resolved domain {user_input} ➜ {ip}")
            else:
                st.error("Failed to resolve domain.")
                st.stop()

        # Query Shodan InternetDB
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                data = resp.json()

                st.subheader("🔧 IP Information")
                st.write(f"IP: {data.get('ip')}")
                st.write(f"Ports: {data.get('ports')}")
                st.write(f"CPEs: {data.get('cpes')}")

                vulns = data.get("vulns", [])
                if vulns:
                    st.subheader("🛡️ CVE Vulnerabilities")
                    for cve in vulns:
                        desc = get_cve_details(cve)
                        st.markdown(f"**[{cve}](https://nvd.nist.gov/vuln/detail/{cve})**: {desc}")
                else:
                    st.success("No CVEs found.")
            else:
                st.error(f"Shodan API error: {resp.status_code}")
        except Exception as e:
            st.error(f"Error querying Shodan: {e}")
