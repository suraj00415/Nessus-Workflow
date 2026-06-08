#!/usr/bin/env python3
"""
hosts_by_finding.py — Extract all hosts/ports affected by a specific finding name.
Accepts a single CSV or a directory of CSVs (all are merged).

Usage:
    python3 hosts_by_finding.py scan.csv "HSTS Missing"
    python3 hosts_by_finding.py scan.csv "SSL" --ips-only
    python3 hosts_by_finding.py /path/to/dir "HSTS" --ips-only > /tmp/hsts_hosts.txt
"""

import csv
import sys
import os
import glob
import argparse


def iter_csv_files(path):
    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.csv"))
        if not files:
            print(f"No CSV files found in {path}", file=sys.stderr)
            sys.exit(1)
        return files
    return [path]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Nessus CSV file or directory of CSV files")
    parser.add_argument("name", help="Finding name substring to match")
    parser.add_argument("--ips-only", action="store_true", help="Print unique IPs/hostnames only (no port/proto)")
    args = parser.parse_args()

    csv_files = iter_csv_files(args.path)

    seen = set()
    ips_seen = set()

    for csv_path in csv_files:
        with open(csv_path, newline="", encoding="utf-8") as f:
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
