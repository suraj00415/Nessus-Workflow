#!/usr/bin/env python3
"""
hosts_by_finding.py — Extract all hosts/ports affected by a specific finding name.
Useful for feeding into verification bash commands.

Usage:
    python3 hosts_by_finding.py scan.csv "HSTS Missing"
    python3 hosts_by_finding.py scan.csv "SSL" --ips-only
    python3 hosts_by_finding.py scan.csv "HSTS" --ips-only > /tmp/hsts_hosts.txt
"""

import csv
import sys
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="Nessus CSV file")
    parser.add_argument("name", help="Finding name substring to match")
    parser.add_argument("--ips-only", action="store_true", help="Print unique IPs only (no port/proto)")
    args = parser.parse_args()

    seen = set()
    ips_seen = set()

    with open(args.csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if args.name.lower() not in row["Name"].strip().lower():
                continue
            host = row["Host"].strip()
            port = row["Port"].strip()
            proto = row["Protocol"].strip()
            entry = f"{host}:{port}/{proto}"
            if args.ips_only:
                if host not in ips_seen:
                    ips_seen.add(host)
                    print(host)
            else:
                if entry not in seen:
                    seen.add(entry)
                    print(entry)


if __name__ == "__main__":
    main()
