#!/usr/bin/env python3
"""
parse_csv.py — Parse a Nessus CSV and print a grouped finding summary.

Usage:
    python3 parse_csv.py scan.csv
    python3 parse_csv.py scan.csv --names-only
    python3 parse_csv.py scan.csv --filter-name "SSL"
"""

import csv
import sys
import argparse
from collections import defaultdict

RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "": 5}


def load(path):
    findings = defaultdict(lambda: {"desc": "", "risk": "", "cve": "", "cvss": "", "hosts": []})
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
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Nessus CSV file path")
    parser.add_argument("--names-only", action="store_true", help="List unique finding names sorted by host count")
    parser.add_argument("--filter-name", default="", help="Only show findings whose name contains this string")
    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
