import streamlit as st
import requests
import socket

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None

def get_cve_details(cve_id):
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("summary", "No description available.")
        elif resp.status_code == 404:
            return "CVE not found in CIRCL database."
        else:
            return f"CIRCL API error: {resp.status_code}"
    except Exception as e:
        return f"Error retrieving CVE info: {e}"

st.title("🔍 Shodan CVE Lookup (IP or Domain)")

user_input = st.text_input("Enter IP Address or Domain Name:")

if st.button("Analyze"):
    if not user_input:
        st.warning("Please enter a valid IP or domain.")
    else:
        ip = user_input
        try:
            socket.inet_aton(user_input)
        except socket.error:
            resolved_ip = resolve_domain(user_input)
            if resolved_ip:
                ip = resolved_ip
                st.info(f"Resolved domain {user_input} ➜ {ip}")
            else:
                st.error("Failed to resolve domain.")
                st.stop()

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
                        st.markdown(f"**[{cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve})**: {desc}")
                else:
                    st.success("No CVEs found.")
            else:
                st.error(f"Shodan API error: {resp.status_code}")
        except Exception as e:
            st.error(f"Error querying Shodan: {e}")
