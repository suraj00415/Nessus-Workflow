#!/usr/bin/env python3
"""
csv_to_findings_md.py — Parse all Nessus CSV files in a directory and produce
a single findings.md file ready for a security researcher.

For each unique finding it outputs:
  - Finding name, risk, CVE/CVSS
  - Full description (from Nessus)
  - All affected hosts:port/proto
  - A ready-to-run bash verification command block

Web findings (HTTP/HTTPS on port 80/443) only get a passive check command
(curl headers) — no payloads, no modification.

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

# Findings that are pure informational/scanner noise — skip in output
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

WEB_PORTS = {"80", "443", "8080", "8443", "8000", "8888"}

# Bash verification commands per finding name (keyword match)
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
        "  echo \"$v: ${result:-rejected}\"\n"
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
        "nmap -sU -p 1900 --script upnp-info <host>\n"
        "# Or direct probe:\n"
        "python3 -c \"\nimport socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(5)\nmsg=b'M-SEARCH * HTTP/1.1\\r\\nHOST:<host>:1900\\r\\nMAN:\\\"ssdp:discover\\\"\\r\\nMX:3\\r\\nST:ssdp:all\\r\\n\\r\\n'\ns.sendto(msg,('<host>',1900))\ntry: print(s.recvfrom(4096))\nexcept: print('No response - may be filtered')\n\""
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


def is_web_finding(name, hosts):
    web_keywords = ["http", "hsts", "https", "web", "server"]
    name_is_web = any(k in name.lower() for k in web_keywords)
    port_is_web = any(h.split(":")[1].split("/")[0] in WEB_PORTS for h in hosts if ":" in h)
    return name_is_web or port_is_web


def load_csvs(paths):
    findings = defaultdict(lambda: {"desc": "", "risk": "", "cve": "", "cvss": "", "hosts": [], "source": ""})
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
                    findings[name]["source"] = os.path.basename(path)
                if entry not in findings[name]["hosts"]:
                    findings[name]["hosts"].append(entry)
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Directory containing .csv files, or single .csv file")
    parser.add_argument("-o", "--output", default="findings.md", help="Output .md file (default: findings.md)")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        csv_files = glob.glob(os.path.join(args.path, "*.csv"))
    else:
        csv_files = [args.path]

    if not csv_files:
        print(f"No CSV files found in {args.path}")
        sys.exit(1)

    findings = load_csvs(csv_files)

    sorted_findings = sorted(
        findings.items(),
        key=lambda x: (RISK_ORDER.get(x[1]["risk"], 99), -len(x[1]["hosts"]))
    )

    lines = []
    lines.append(f"# Nessus Findings Report")
    lines.append(f"**Generated:** {date.today()}  ")
    lines.append(f"**Sources:** {', '.join(os.path.basename(p) for p in csv_files)}  ")
    lines.append(f"**Total unique findings:** {len(sorted_findings)}  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    for i, (name, data) in enumerate(sorted_findings, 1):
        risk = data["risk"] or "Info"
        anchor = name.lower().replace(" ", "-").replace("/", "").replace("'", "").replace("(", "").replace(")", "").replace(",", "")
        lines.append(f"{i}. [{name}](#{anchor}) — {risk} — {len(data['hosts'])} host(s)")
    lines.append("")
    lines.append("---")
    lines.append("")

    for i, (name, data) in enumerate(sorted_findings, 1):
        risk = data["risk"] or "Info"
        cvss = data["cvss"] or "N/A"
        cve = data["cve"] or "N/A"
        hosts = sorted(data["hosts"])
        web = is_web_finding(name, hosts)

        lines.append(f"## {i}. {name}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Risk | {risk} |")
        lines.append(f"| CVSS | {cvss} |")
        lines.append(f"| CVE | {cve} |")
        lines.append(f"| Hosts affected | {len(hosts)} |")
        lines.append(f"| Source | {data['source']} |")
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
            lines.append("> **Web finding — verification is read-only (headers/status check only). Do NOT send payloads or modify any data.**")
            lines.append("")

        lines.append("**Verification (bash):**")
        cmd = get_verify_cmd(name)
        lines.append("```bash")
        lines.append(cmd)
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    output_path = args.output
    if os.path.isdir(args.path):
        output_path = os.path.join(args.path, args.output)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Written: {output_path}  ({len(sorted_findings)} findings)")


if __name__ == "__main__":
    main()
