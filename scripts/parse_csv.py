#!/usr/bin/env python3
"""
parse_csv.py — Parse a Nessus CSV and print a grouped finding summary.

Usage:
    python3 parse_csv.py scan.csv
    python3 parse_csv.py scan.csv --names-only
    python3 parse_csv.py scan.csv --filter-name "SSL"
    python3 parse_csv.py scan.csv --hosts-ports
"""

import csv
import sys
import argparse
from collections import defaultdict

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "": 5}

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


def load(path):
    findings = defaultdict(lambda: {
        "desc": "", "risk": "", "cve": "", "cvss": "", "hosts": [], "plugin_outputs": {}
    })
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row["Name"].strip()
            host = row["Host"].strip()
            port = row["Port"].strip()
            proto = row["Protocol"].strip()
            entry = f"{host}:{port}/{proto}"
            if not findings[name]["desc"]:
                findings[name]["desc"] = row["Description"].strip()
                findings[name]["risk"] = row["Risk Factor"].strip() or row["Risk"].strip()
                findings[name]["cve"] = row["CVE"].strip()
                findings[name]["cvss"] = row["CVSS v2.0 Base Score"].strip()
            if entry not in findings[name]["hosts"]:
                findings[name]["hosts"].append(entry)
            raw = row.get("Plugin Output", "").strip()
            if raw and entry not in findings[name]["plugin_outputs"]:
                findings[name]["plugin_outputs"][entry] = raw
    return findings


def load_hosts_ports(path):
    """Return sorted list of (host, port, proto) tuples, skipping port 0 and noise findings."""
    seen = set()
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row["Name"].strip()
            if name in SKIP_NAMES:
                continue
            host = row["Host"].strip()
            port = row["Port"].strip()
            proto = row["Protocol"].strip()
            if port == "0" or not host:
                continue
            key = (host, port, proto)
            if key not in seen:
                seen.add(key)
                rows.append(key)
    return sorted(rows, key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else 0, x[2]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Nessus CSV file path")
    parser.add_argument("--names-only", action="store_true", help="List unique finding names sorted by host count")
    parser.add_argument("--filter-name", default="", help="Only show findings whose name contains this string")
    parser.add_argument("--hosts-ports", action="store_true",
                        help="List all unique host/port/proto combos (use for nmap accessibility checks)")
    args = parser.parse_args()

    if args.hosts_ports:
        rows = load_hosts_ports(args.csv)
        # Group by host for easy nmap command construction
        by_host = defaultdict(lambda: {"tcp": [], "udp": []})
        for host, port, proto in rows:
            by_host[host][proto].append(port)

        print(f"{'HOST':<40} {'PROTO':<6} {'PORTS'}")
        print("-" * 80)
        for host in sorted(by_host):
            for proto in ("tcp", "udp"):
                ports = by_host[host][proto]
                if ports:
                    print(f"{host:<40} {proto:<6} {','.join(ports)}")
        print()
        print("# nmap commands:")
        for host in sorted(by_host):
            tcp = by_host[host]["tcp"]
            udp = by_host[host]["udp"]
            if tcp:
                print(f"nmap -sT -Pn -p {','.join(tcp)} -T4 {host}")
            if udp:
                print(f"nmap -sU -Pn -p {','.join(udp)} -T4 {host}")
        return

    findings = load(args.csv)
    sorted_findings = sorted(findings.items(), key=lambda x: (RISK_ORDER.get(x[1]["risk"], 99), -len(x[1]["hosts"])))

    if args.filter_name:
        sorted_findings = [(n, d) for n, d in sorted_findings if args.filter_name.lower() in n.lower()]

    if args.names_only:
        for name, data in sorted_findings:
            print(f"{len(data['hosts']):4d}  [{data['risk'] or 'Info':8s}]  {name}")
        return

    for name, data in sorted_findings:
        risk = data["risk"] or "Info"
        print(f"\n{'='*70}")
        print(f"  {name}")
        print(f"  Risk: {risk}  |  CVSS: {data['cvss'] or 'N/A'}  |  CVE: {data['cve'] or 'N/A'}")
        print(f"  Hosts ({len(data['hosts'])}):")
        for h in sorted(data["hosts"])[:15]:
            print(f"    {h}")
        if len(data["hosts"]) > 15:
            print(f"    ... and {len(data['hosts']) - 15} more")
        print(f"  Description: {data['desc'][:300].replace(chr(10), ' ')}")
        if data["plugin_outputs"]:
            first_entry, first_output = next(iter(data["plugin_outputs"].items()))
            print(f"  Plugin output ({first_entry}): {first_output[:200].replace(chr(10), ' | ')}")


if __name__ == "__main__":
    main()
