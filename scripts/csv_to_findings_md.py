#!/usr/bin/env python3
"""
csv_to_findings_md.py — Parse all Nessus CSV files in a directory (or a single
CSV) and produce ONE findings.md. Multiple CSVs are merged — findings are
deduplicated by name and host lists are combined. Never creates per-CSV files.

Structure of output:
  1. Header / metadata
  2. Port & Service Summary (all detected host:port pairs — filled by nmap)
  3. Table of Contents
  4. Individual finding sections
  5. Excluded Findings (if any)

Usage:
    python3 csv_to_findings_md.py /path/to/scans/          # all .csv in dir
    python3 csv_to_findings_md.py /path/to/scans/ -o report.md
    python3 csv_to_findings_md.py single.csv -o report.md
"""

import csv
import sys
import os
import glob
import argparse
from collections import defaultdict
from datetime import date

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "": 5}

# Pure scanner-noise rows — skip entirely (still used to extract port data)
SKIP_NAMES = {
    "Nessus SYN scanner",
    "Nessus Scan Information",
    "Traceroute Information",
    "OS Identification",
    "OS Fingerprints Detected",
    "Device Type",
    "Common Platform Enumeration (CPE)",
    "Host Fully Qualified Domain Name (FQDN) Resolution",
    "Open Port Re-check",
}

# Findings excluded per asset-owner acknowledgement (from CLAUDE.md)
EXCLUDED_KEYWORDS = [
    "HSTS",
    "TLS Certificate",
    "SSL Certificate",
    "TLS 1.0",
    "TLS 1.1",
    "SSLv3",
    "POODLE",
    "BEAST",
    "DHE",
    "RC4",
    "3DES",
    "NULL Cipher",
    "EXPORT",
    "Discouraged Cipher",
    "Weak Cipher",
    "Cipher Suite",
    "Apache Tomcat",
    "Certificate Expir",
    "Self-Signed",
    "Untrusted CA",
]

WEB_PORTS = {"80", "443", "8080", "8443", "8000", "8888"}

VERIFY_CMDS = {
    "HSTS Missing": (
        "# Verify: check if Strict-Transport-Security header is present\n"
        "curl -sk -o /dev/null -D - --max-time 8 https://<host> | grep -i strict-transport-security\n"
        "# Empty output = HSTS missing = CONFIRMED"
    ),
    "SSL/TLS Recommended Cipher": (
        "# Verify: check if DHE (non-ECDHE) ciphers are accepted\n"
        "openssl s_client -connect <host>:<port> -tls1_2 -cipher 'DHE:!ECDHE:!aNULL:!eNULL' 2>&1 </dev/null | grep 'New,'\n"
        "# 'New, TLSv1.2, Cipher is DHE-...' = CONFIRMED\n\n"
        "# Full cipher enumeration\n"
        "nmap --script ssl-enum-ciphers -p <port> <host>"
    ),
    "Post-Quantum": (
        "# Verify: check key exchange type (should show classical ECDH only)\n"
        "openssl s_client -connect <host>:<port> -msg 2>&1 </dev/null | grep 'Peer Temp Key'\n"
        "# 'prime256v1' or 'X25519' (no MLKEM/Kyber) = CONFIRMED classical-only"
    ),
    "Shor": (
        "# Same root cause as post-quantum finding above\n"
        "openssl s_client -connect <host>:<port> -msg 2>&1 </dev/null | grep 'Peer Temp Key'\n"
        "# No MLKEM/Kyber hybrid = CONFIRMED"
    ),
    "SSL Session Resume": (
        "# Verify: check if TLS session ID resumption is supported\n"
        "openssl s_client -connect <host>:<port> -sess_out /tmp/sess.pem 2>&1 </dev/null | grep 'Session-ID:'\n"
        "openssl s_client -connect <host>:<port> -sess_in /tmp/sess.pem 2>&1 </dev/null | grep 'Reused,'\n"
        "# 'Reused, TLSv1.2' = CONFIRMED"
    ),
    "SSL / TLS Versions": (
        "# Verify: check which TLS versions are accepted\n"
        "for v in tls1 tls1_1 tls1_2 tls1_3; do\n"
        "  result=$(openssl s_client -connect <host>:<port> -$v 2>&1 </dev/null | grep '^New,')\n"
        '  echo "$v: ${result:-rejected}"\n'
        "done"
    ),
    "TCP/IP Timestamps": (
        "# Verify: TCP timestamps is an OS-level feature. Confirm via nmap OS scan\n"
        "nmap -O --osscan-limit <host>\n"
        "# Or check kernel setting on the host itself:\n"
        "# sysctl net.ipv4.tcp_timestamps"
    ),
    "UPnP": (
        "# Verify: send unicast SSDP M-SEARCH to port 1900/udp\n"
        "nmap -sU -p 1900 --script upnp-info <host>"
    ),
    "HyperText Transfer Protocol": (
        "# Verify: check HTTP response headers (read-only)\n"
        "curl -sk -o /dev/null -D - --max-time 8 https://<host> | head -20"
    ),
    "Service Detection": (
        "# Verify: identify service running on port\n"
        "nmap -sV -p <port> <host>"
    ),
}


def get_verify_cmd(name):
    for keyword, cmd in VERIFY_CMDS.items():
        if keyword.lower() in name.lower():
            return cmd
    return (
        "# Generic: port scan and banner grab\n"
        "nmap -sV -p <port> <host>"
    )


def is_excluded(name):
    name_lower = name.lower()
    return any(kw.lower() in name_lower for kw in EXCLUDED_KEYWORDS)


def is_web_finding(name, hosts):
    web_keywords = ["http", "hsts", "https", "web", "server"]
    name_is_web = any(k in name.lower() for k in web_keywords)
    port_is_web = any(h.split(":")[1].split("/")[0] in WEB_PORTS for h in hosts if ":" in h)
    return name_is_web or port_is_web


def collect_host_ports(paths):
    """Return dict: {host: {proto: sorted list of ports}} from all CSVs, skipping port 0."""
    by_host = defaultdict(lambda: defaultdict(set))
    for path in paths:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                host = row["Host"].strip()
                port = row["Port"].strip()
                proto = row["Protocol"].strip()
                if not host or port == "0":
                    continue
                by_host[host][proto].add(port)
    # Convert sets to sorted lists
    result = {}
    for host in sorted(by_host):
        result[host] = {}
        for proto in ("tcp", "udp"):
            ports = sorted(by_host[host].get(proto, set()), key=lambda p: int(p) if p.isdigit() else 0)
            if ports:
                result[host][proto] = ports
    return result


def load_csvs(paths):
    findings = defaultdict(lambda: {
        "desc": "", "risk": "", "cve": "", "cvss": "", "hosts": [], "sources": set()
    })
    for path in paths:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row["Name"].strip()
                if name in SKIP_NAMES:
                    continue
                host = row["Host"].strip()
                port = row["Port"].strip()
                proto = row["Protocol"].strip()
                entry = f"{host}:{port}/{proto}"
                if not findings[name]["desc"]:
                    findings[name]["desc"] = row["Description"].strip()
                    findings[name]["risk"] = row["Risk Factor"].strip() or row["Risk"].strip()
                    findings[name]["cve"] = row["CVE"].strip()
                    findings[name]["cvss"] = row["CVSS v2.0 Base Score"].strip()
                findings[name]["sources"].add(os.path.basename(path))
                if entry not in findings[name]["hosts"]:
                    findings[name]["hosts"].append(entry)
    return findings


def build_port_summary_section(host_ports):
    """Build the ## Port & Service Summary section with a placeholder table."""
    lines = []
    lines.append("## Port & Service Summary")
    lines.append("")
    lines.append("> **Action required:** Run the nmap commands below, then fill in State, Service, and Version columns.")
    lines.append("> Port states: `open` = service live | `closed` = host reachable, nothing listening | `filtered` = firewall/ACL blocking | `open|filtered` = UDP ambiguity")
    lines.append("")

    # nmap commands block
    lines.append("**Commands to run:**")
    lines.append("```bash")
    for host, protos in host_ports.items():
        tcp_ports = protos.get("tcp", [])
        udp_ports = protos.get("udp", [])
        if tcp_ports:
            lines.append(f"nmap -sT -sV -Pn -p {','.join(tcp_ports)} -T4 {host}")
        if udp_ports:
            lines.append(f"nmap -sU -Pn -p {','.join(udp_ports)} -T4 {host}")
    lines.append("```")
    lines.append("")

    # Pre-populated table (State/Service/Version left blank for fill-in)
    lines.append("| Host | Port | Protocol | State | Service | Version |")
    lines.append("|------|------|----------|-------|---------|---------|")
    for host, protos in host_ports.items():
        for proto in ("tcp", "udp"):
            for port in protos.get(proto, []):
                lines.append(f"| {host} | {port} | {proto} | — | — | — |")
    lines.append("")
    lines.append("> Hosts where **all** ports are `filtered` or `closed`: mark as **Host unreachable from scanner** and skip finding verification for that host.")
    lines.append("")
    lines.append("---")
    lines.append("")
    return lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Directory containing .csv files, or single .csv file")
    parser.add_argument("-o", "--output", default="findings.md",
                        help="Output file name (default: findings.md). Always a single file.")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        csv_files = sorted(glob.glob(os.path.join(args.path, "*.csv")))
        output_path = os.path.join(args.path, args.output)
    else:
        csv_files = [args.path]
        output_path = os.path.join(os.path.dirname(args.path) or ".", args.output)

    if not csv_files:
        print(f"No CSV files found in {args.path}", file=sys.stderr)
        sys.exit(1)

    findings = load_csvs(csv_files)
    host_ports = collect_host_ports(csv_files)

    all_findings = sorted(
        findings.items(),
        key=lambda x: (RISK_ORDER.get(x[1]["risk"], 99), -len(x[1]["hosts"]))
    )

    active_findings = [(n, d) for n, d in all_findings if not is_excluded(n)]
    excluded_findings = [(n, d) for n, d in all_findings if is_excluded(n)]

    lines = []

    # --- Header ---
    lines.append("# Nessus Findings Report")
    lines.append(f"**Generated:** {date.today()}  ")
    lines.append(f"**Sources ({len(csv_files)}):** {', '.join(os.path.basename(p) for p in csv_files)}  ")
    lines.append(f"**Unique hosts:** {len(host_ports)}  ")
    lines.append(f"**Active findings:** {len(active_findings)}  ")
    if excluded_findings:
        lines.append(f"**Excluded findings:** {len(excluded_findings)} (acknowledged by asset owner — not verified)  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- Port & Service Summary ---
    lines.extend(build_port_summary_section(host_ports))

    # --- Table of Contents ---
    lines.append("## Table of Contents")
    lines.append("")
    for i, (name, data) in enumerate(active_findings, 1):
        risk = data["risk"] or "Info"
        anchor = (name.lower()
                  .replace(" ", "-")
                  .replace("/", "")
                  .replace("'", "")
                  .replace("(", "")
                  .replace(")", "")
                  .replace(",", "")
                  .replace(".", ""))
        lines.append(f"{i}. [{name}](#{anchor}) — {risk} — {len(data['hosts'])} host(s)")
    if excluded_findings:
        lines.append(f"{len(active_findings) + 1}. [Excluded Findings](#excluded-findings)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- Individual findings ---
    for i, (name, data) in enumerate(active_findings, 1):
        risk = data["risk"] or "Info"
        cvss = data["cvss"] or "N/A"
        cve = data["cve"] or "N/A"
        hosts = sorted(data["hosts"])
        sources = sorted(data["sources"])
        web = is_web_finding(name, hosts)

        lines.append(f"## {i}. {name}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| Risk | {risk} |")
        lines.append(f"| CVSS | {cvss} |")
        lines.append(f"| CVE | {cve} |")
        lines.append(f"| Hosts affected | {len(hosts)} |")
        lines.append(f"| Source file(s) | {', '.join(sources)} |")
        lines.append("")

        lines.append("**Description:**")
        lines.append(f"> {data['desc'].replace(chr(10), ' ').strip()}")
        lines.append("")

        lines.append("**Affected hosts:**")
        lines.append("```")
        for h in hosts:
            lines.append(h)
        lines.append("```")
        lines.append("")

        if web:
            lines.append("> **Web finding — verification is read-only (headers/status only). No payloads, no data modification.**")
            lines.append("")

        lines.append("**Verification (bash):**")
        lines.append("```bash")
        lines.append(get_verify_cmd(name))
        lines.append("```")
        lines.append("")
        lines.append(f"**Status:** <!-- CONFIRMED | PARTIALLY CONFIRMED | NOT CONFIRMED | Could not verify -->")
        lines.append("")
        lines.append("---")
        lines.append("")

    # --- Excluded Findings ---
    if excluded_findings:
        lines.append("## Excluded Findings")
        lines.append("")
        lines.append("| Finding | Note |")
        lines.append("|---------|------|")
        for name, _ in excluded_findings:
            lines.append(f"| {name} | Excluded from this assessment as acknowledged by the developer/asset owner. |")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Written: {output_path}")
    print(f"  {len(csv_files)} CSV(s) merged  |  {len(host_ports)} host(s)  |  {len(active_findings)} active finding(s)  |  {len(excluded_findings)} excluded")


if __name__ == "__main__":
    main()
