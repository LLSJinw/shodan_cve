import streamlit as st
import requests
import re
import pandas as pd
from io import BytesIO

st.set_page_config(page_title="Multi-Input CVE Lookup", page_icon="🔍")
st.title("🔍 Multi-Input CVE Lookup (IP + Domain + DNSDumpster)")

DNSDUMPSTER_API_KEY = st.secrets["dnsdumpster_api_key"]
OPENCVE_USER = st.secrets["opencve_user"]
OPENCVE_PASS = st.secrets["opencve_pass"]


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
    except Exception:
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
                            ip_host_map[ip] = {
                                "hostname": host,
                                "record_type": section.upper(),
                                "asn": ip_entry.get("asn", ""),
                                "asn_name": ip_entry.get("asn_name", ""),
                                "country": ip_entry.get("country", ""),
                                "ptr": ip_entry.get("ptr", "")
                            }
    except Exception:
        pass

    return ip_host_map


def query_shodan_vulns(ip):
    url = f"https://internetdb.shodan.io/{ip}"

    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "cpes": data.get("cpes", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", [])
            }
    except Exception:
        pass

    return {
        "ports": [],
        "vulns": [],
        "cpes": [],
        "hostnames": [],
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

            return {
                "CVE ID": cve_id,
                "Title": title,
                "CVSS": score
            }

    except Exception:
        pass

    return {
        "CVE ID": cve_id,
        "Title": "Not Found",
        "CVSS": "N/A"
    }


def build_excel(summary_df, cve_df):
    output = BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        summary_df.to_excel(writer, index=False, sheet_name="Summary")
        cve_df.to_excel(writer, index=False, sheet_name="CVE_Details")

    output.seek(0)
    return output


# Keep results after button click
if "summary_rows" not in st.session_state:
    st.session_state.summary_rows = []

if "cve_detail_rows" not in st.session_state:
    st.session_state.cve_detail_rows = []


multi_input = st.text_area("Paste IPs or Domains (one per line):", height=200)

if st.button("Run Lookup"):
    st.session_state.summary_rows = []
    st.session_state.cve_detail_rows = []

    if not multi_input.strip():
        st.warning("Please input at least one IP or domain.")
    else:
        entries = [line.strip() for line in multi_input.strip().splitlines() if line.strip()]
        all_ips = {}

        st.subheader("🔄 Resolving & Enumerating IPs")

        for entry in entries:
            if is_ip(entry):
                st.markdown(f"✅ **{entry}** (direct IP)")
                all_ips[entry] = {
                    "hostname": "Direct IP",
                    "source": "Input",
                    "record_type": "",
                    "asn": "",
                    "asn_name": "",
                    "country": "",
                    "ptr": ""
                }
            else:
                resolved = resolve_domain_to_ips(entry)

                if resolved:
                    st.markdown(f"🌐 **{entry}** ➔ DNS A Record: {', '.join(resolved)}")
                    for ip in resolved:
                        all_ips[ip] = {
                            "hostname": entry,
                            "source": "Google DNS",
                            "record_type": "A",
                            "asn": "",
                            "asn_name": "",
                            "country": "",
                            "ptr": ""
                        }
                else:
                    st.warning(f"❌ Could not resolve A record for: {entry}")

                dnsdump_data = fetch_dnsdumpster_data(entry)

                if dnsdump_data:
                    for ip, meta in dnsdump_data.items():
                        all_ips[ip] = {
                            "hostname": meta.get("hostname", ""),
                            "source": "DNSDumpster",
                            "record_type": meta.get("record_type", ""),
                            "asn": meta.get("asn", ""),
                            "asn_name": meta.get("asn_name", ""),
                            "country": meta.get("country", ""),
                            "ptr": meta.get("ptr", "")
                        }

                    st.markdown(
                        f"🔍 **{entry}** ➔ DNSDumpster IPs: {', '.join(dnsdump_data.keys())}"
                    )
                else:
                    st.info(f"ℹ️ No DNSDumpster results for: {entry}")

        if not all_ips:
            st.warning("No valid IPs to query.")
        else:
            st.subheader("🔐 Shodan CVE & Port Lookup Table")

            for ip, meta in sorted(all_ips.items()):
                hostname = meta.get("hostname", "Not found")
                shodan_data = query_shodan_vulns(ip)

                ports = shodan_data.get("ports", [])
                vulns = shodan_data.get("vulns", [])
                cpes = shodan_data.get("cpes", [])
                shodan_hostnames = shodan_data.get("hostnames", [])
                tags = shodan_data.get("tags", [])

                port_str = ", ".join(str(p) for p in ports) if ports else "None"
                cve_str = ", ".join(vulns) if vulns else "No known CVEs"
                cpe_str = ", ".join(cpes) if cpes else ""
                shodan_hostnames_str = ", ".join(shodan_hostnames) if shodan_hostnames else ""
                tags_str = ", ".join(tags) if tags else ""

                st.session_state.summary_rows.append({
                    "IP": ip,
                    "Hostname": hostname,
                    "Source": meta.get("source", ""),
                    "Record Type": meta.get("record_type", ""),
                    "Open TCP Ports": port_str,
                    "CVE Count": len(vulns),
                    "CVEs": cve_str,
                    "CPEs": cpe_str,
                    "Shodan Hostnames": shodan_hostnames_str,
                    "Tags": tags_str,
                    "ASN": meta.get("asn", ""),
                    "ASN Name": meta.get("asn_name", ""),
                    "Country": meta.get("country", ""),
                    "PTR": meta.get("ptr", "")
                })

                with st.expander(f"🖥️ {ip} ({hostname})"):
                    st.markdown(f"**🔌 Open TCP Ports:** `{port_str}`")

                    if cpes:
                        st.markdown(f"**🧩 CPEs:** {cpe_str}")

                    if tags:
                        st.markdown(f"**🏷️ Tags:** {tags_str}")

                    if vulns:
                        st.markdown(f"**🛡️ CVEs:** {cve_str}")

                        detailed_rows = []

                        for cve in vulns:
                            details = get_cve_details(cve)

                            row = {
                                "IP": ip,
                                "Hostname": hostname,
                                "CVE ID": details["CVE ID"],
                                "Title": details["Title"],
                                "CVSS": details["CVSS"]
                            }

                            detailed_rows.append(row)
                            st.session_state.cve_detail_rows.append(row)

                        st.markdown("**📋 CVE Details**")
                        st.table(detailed_rows)
                    else:
                        st.success("✅ No known CVEs found.")


# Export section
if st.session_state.summary_rows:
    st.markdown("---")
    st.subheader("📤 Export Results")

    summary_df = pd.DataFrame(st.session_state.summary_rows)

    if st.session_state.cve_detail_rows:
        cve_df = pd.DataFrame(st.session_state.cve_detail_rows)
    else:
        cve_df = pd.DataFrame(columns=["IP", "Hostname", "CVE ID", "Title", "CVSS"])

    st.markdown("### 📊 Summary Preview")
    st.dataframe(summary_df, use_container_width=True)

    if not cve_df.empty:
        st.markdown("### 🛡️ CVE Details Preview")
        st.dataframe(cve_df, use_container_width=True)

    csv_summary = summary_df.to_csv(index=False).encode("utf-8-sig")
    csv_cves = cve_df.to_csv(index=False).encode("utf-8-sig")
    excel_file = build_excel(summary_df, cve_df)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button(
            label="⬇️ Download Summary CSV",
            data=csv_summary,
            file_name="shodan_summary.csv",
            mime="text/csv"
        )

    with col2:
        st.download_button(
            label="⬇️ Download CVE Details CSV",
            data=csv_cves,
            file_name="shodan_cve_details.csv",
            mime="text/csv"
        )

    with col3:
        st.download_button(
            label="⬇️ Download Excel XLSX",
            data=excel_file,
            file_name="shodan_lookup_results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
