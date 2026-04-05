import os
import sys
import csv
import json
import argparse
import ipaddress
import getpass
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any
import pyfiglet
import logging

ascii_banner = pyfiglet.figlet_format("SEEK")
print(ascii_banner)
print("by \033[1;32mDEMEJI\033[0m")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ─── IP Loading ───────────────────────────────────────────────────────────────

def load_ips(path: str) -> List[str]:
    with open(path, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    seen = set()
    ordered = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def expand_cidr(cidr: str) -> List[str]:
    """Expand a CIDR range into individual IP strings."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR range '{cidr}': {e}")


def resolve_ips(args) -> List[str]:
    """
    Resolve the IP list from whichever input flag was provided.
    Priority: --ip > --cidr > --input file > interactive prompt.
    """
    if hasattr(args, "ip") and args.ip:
        return [args.ip.strip()]

    if hasattr(args, "cidr") and args.cidr:
        ips = expand_cidr(args.cidr)
        print(f"CIDR {args.cidr} expanded to {len(ips)} hosts.")
        return ips

    input_path = getattr(args, "input", None)
    if not input_path:
        while True:
            input_path = input("Enter path to input file (one IP per line): ").strip()
            input_path = os.path.expanduser(input_path)
            if os.path.isfile(input_path):
                break
            print("File not found. Please enter a valid path.")

    return load_ips(os.path.expanduser(input_path))


# ─── Output ───────────────────────────────────────────────────────────────────

def parse_result(ip: str, hit: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a blocklist hit into a flat result row."""
    return {
        "ip":      ip,
        "verdict": hit.get("verdict", "unknown"),
        "source":  hit.get("source") or "",
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def write_csv(output_path: str, rows: List[Dict[str, Any]]):
    fieldnames = ["ip", "verdict", "source", "scanned_at"]
    with open(output_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def write_json(output_path: str, rows: List[Dict[str, Any]]):
    with open(output_path, "w") as f:
        json.dump(rows, f, indent=2)


def resolve_output_path(provided: str = None) -> str:
    if provided:
        return os.path.expanduser(provided)
    while True:
        path = input("Enter path for output file (CSV or JSON): ").strip()
        path = os.path.expanduser(path)
        if os.path.isdir(path):
            print("That is a directory. Please provide a filename e.g. results.csv")
            continue
        if os.path.exists(path):
            confirm = input(f"{path} exists. Overwrite? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                continue
        parent = os.path.dirname(path) or "."
        if not os.path.exists(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except Exception as e:
                print(f"Cannot create directory {parent}: {e}")
                continue
        return path


# ─── Main scan runner ─────────────────────────────────────────────────────────

def run_scan(args):
    # Import here to avoid circular imports when used as a package
    from seek.blocklist import BlocklistStore

    store = BlocklistStore()
    store.load()

    ips = resolve_ips(args)
    if not ips:
        print("No IPs to scan.")
        sys.exit(0)

    print(f"Loaded {len(ips)} unique IP(s). Scanning against local blocklists...\n")

    results = []
    for idx, ip in enumerate(ips, 1):
        print(f"[{idx}/{len(ips)}] Checking {ip} ...")
        try:
            hit     = store.check_ip(ip)
            parsed  = parse_result(ip, hit)
            results.append(parsed)
        except Exception as e:
            logging.error(f"Error checking {ip}: {e}")
            results.append({
                "ip":         ip,
                "verdict":    "error",
                "source":     "",
                "scanned_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            })

    # ── Write output ──────────────────────────────────────────────────────────
    output_path = resolve_output_path(getattr(args, "output", None))
    use_json    = getattr(args, "json", False)

    if use_json or output_path.endswith(".json"):
        write_json(output_path, results)
    else:
        write_csv(output_path, results)

    # ── Summary ───────────────────────────────────────────────────────────────
    malicious = [r for r in results if r["verdict"] == "malicious"]
    clean     = [r for r in results if r["verdict"] == "clean"]
    errors    = [r for r in results if r["verdict"] == "error"]

    print("\n==== Summary ====")
    print(f"Total scanned : {len(results)}")
    print(f"Malicious     : {len(malicious)}")
    print(f"Clean         : {len(clean)}")
    print(f"Errors        : {len(errors)}")
    print(f"Results saved : {output_path}")

    if malicious:
        print("\nFlagged IPs:")
        for r in malicious:
            print(f"  {r['ip']}  [{r['source']}]")


# ─── Standalone entry (for direct invocation during dev) ─────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seek — local IP threat scanner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ip",    help="Scan a single IP")
    group.add_argument("--cidr",  help="Scan a CIDR range e.g. 10.0.0.0/24")
    group.add_argument("-i", "--input",  help="Path to file with one IP per line")
    parser.add_argument("-o", "--output", help="Output file path (CSV or JSON)")
    parser.add_argument("--json", action="store_true", help="Force JSON output")
    run_scan(parser.parse_args())