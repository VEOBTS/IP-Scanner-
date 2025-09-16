import os
import sys
import time
import csv
import json
import argparse
import requests
import getpass
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any


# Default delays chosen to respect the free/public API (4 requests/minute -> one request every 15 seconds)
DEFAULT_SECONDS_BETWEEN_REQUESTS = 15
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 2  # exponential backoff multiplier

VT_IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/{}"


def load_ips(path: str) -> List[str]:
    with open(path, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    # dedupe while preserving order
    seen = set()
    ordered = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def get_vt_ip_report(ip: str, api_key: str, retries: int = DEFAULT_MAX_RETRIES) -> Dict[str, Any]:
    url = VT_IP_ENDPOINT.format(ip)
    headers = {"x-apikey": api_key}
    attempt = 0
    delay = 1.0
    while attempt <= retries:
        attempt += 1
        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except requests.RequestException as e:
            # network-level error, retry
            if attempt > retries:
                raise RuntimeError(f"Network error fetching {ip}: {e}")
            wait = delay * DEFAULT_RETRY_BACKOFF
            print(f"[{ip}] Network error. Retrying in {wait}s (attempt {attempt}/{retries}).")
            time.sleep(wait)
            delay *= DEFAULT_RETRY_BACKOFF
            continue

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 429:
            # rate limited - obey Retry-After header if present, else exponential backoff
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = int(retry_after) + 1
                except ValueError:
                    wait = delay * DEFAULT_RETRY_BACKOFF
            else:
                wait = delay * DEFAULT_RETRY_BACKOFF
                delay *= DEFAULT_RETRY_BACKOFF
            print(f"[{ip}] 429 rate limited. Waiting {wait}s before retry (attempt {attempt}/{retries}).")
            time.sleep(wait)
            continue
        if 500 <= resp.status_code < 600:
            # server error, retry
            wait = delay * DEFAULT_RETRY_BACKOFF
            print(f"[{ip}] Server error {resp.status_code}. Retrying in {wait}s (attempt {attempt}/{retries}).")
            time.sleep(wait)
            delay *= DEFAULT_RETRY_BACKOFF
            continue
        # other client error (4xx except 429) - no point retrying
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        raise RuntimeError(f"Failed to fetch report for {ip}: HTTP {resp.status_code} - {body}")
    raise RuntimeError(f"Exceeded retries when fetching report for {ip}. Last status code: {resp.status_code}")


def parse_ip_report(ip: str, report_json: Dict[str, Any]) -> Dict[str, Any]:
    # Extract useful fields. The v3 API returns analysis under data.attributes.last_analysis_stats
    data = report_json.get("data") or {}
    attributes = data.get("attributes") or {}
    last_stats = attributes.get("last_analysis_stats") or {}
    # last_analysis_stats commonly contains keys: harmless, malicious, suspicious, undetected, timeout
    malicious_count = last_stats.get("malicious", 0)
    suspicious_count = last_stats.get("suspicious", 0)
    harmless_count = last_stats.get("harmless", 0)
    undetected_count = last_stats.get("undetected", 0)
    total_positive = malicious_count + suspicious_count
    verdict = "malicious" if total_positive > 0 else "clean"
    first_seen = attributes.get("first_seen") or ""
    last_analysis_date = attributes.get("last_analysis_date") or ""

    return {
        "ip": ip,
        "verdict": verdict,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "harmless_count": harmless_count,
        "undetected_count": undetected_count,
        "total_positive": total_positive,
        "first_seen": first_seen,
        "last_analysis_date": last_analysis_date,
        "raw": json.dumps(report_json)
    }


def write_csv(output_path: str, rows: List[Dict[str, Any]]):
    fieldnames = [
        "ip", "verdict", "malicious_count", "suspicious_count", "harmless_count",
        "undetected_count", "total_positive", "first_seen", "last_analysis_date"
    ]
    with open(output_path, "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


def prompt_for_paths_and_key(provided_input: str = None, provided_output: str = None, provided_key: str = None):
    """
    Prompts the user for input file, API key, and output file if any are missing.
    Returns tuple: (input_path, output_path, api_key)
    """
    # Input file
    if provided_input:
        input_path = os.path.expanduser(provided_input)
    else:
        while True:
            input_path = input("Enter path to input file (one IP per line): ").strip()
            input_path = os.path.expanduser(input_path)
            if os.path.isfile(input_path):
                break
            print("File not found. Please enter a valid path.")

    # API key (masked)
    if provided_key:
        api_key = provided_key
    else:
        # try env var first
        env_key = os.getenv("VT_API_KEY")
        if env_key:
            use_env = input("VT_API_KEY environment variable found. Use it? [Y/n]: ").strip().lower()
            if use_env in ("", "y", "yes"):
                api_key = env_key
            else:
                api_key = getpass.getpass("Enter VirusTotal API key (input hidden): ").strip()
        else:
            api_key = getpass.getpass("Enter VirusTotal API key (input hidden): ").strip()

    # Output file
    if provided_output:
        output_path = os.path.expanduser(provided_output)
    else:
        while True:
            output_path = input("Enter path for output CSV file (will be overwritten if exists): ").strip()
            output_path = os.path.expanduser(output_path)
            if os.path.isdir(output_path):
                print("That's a directory. Please provide a filename (e.g. results.csv).")
                continue
            # if file exists ask to confirm overwrite
            if os.path.exists(output_path):
                confirm = input(f"File {output_path} exists. Overwrite? [y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    print("Please specify a different output filename.")
                    continue
            # parent dir must exist or be creatable
            parent = os.path.dirname(output_path) or "."
            if not os.path.exists(parent):
                try:
                    os.makedirs(parent, exist_ok=True)
                except Exception as e:
                    print(f"Cannot create directory {parent}: {e}")
                    continue
            break

    return input_path, output_path, api_key


def main():
    parser = argparse.ArgumentParser(description="Scan IPs against VirusTotal (v3) and output CSV results.")
    parser.add_argument("input_file", nargs="?", help="Path to input file with one IP per line (optional)")
    parser.add_argument("output_file", nargs="?", help="Path to output CSV file (optional)")
    parser.add_argument("--api-key", help="VirusTotal API key (or set VT_API_KEY env var)")
    parser.add_argument("--delay", type=float, default=DEFAULT_SECONDS_BETWEEN_REQUESTS,
                        help="Seconds to wait between API requests (default %(default)s)")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES, help="Max retries on transient errors")
    args = parser.parse_args()

    # If any of required values missing, prompt interactively
    input_path, output_path, api_key = prompt_for_paths_and_key(
        provided_input=args.input_file,
        provided_output=args.output_file,
        provided_key=args.api_key
    )

    if not api_key:
        print("Error: VirusTotal API key required.")
        sys.exit(2)

    ips = load_ips(input_path)
    if not ips:
        print("No IPs found in the input file.")
        sys.exit(0)

    print(f"Loaded {len(ips)} unique IPs to check. Delay between requests: {args.delay}s")
    results = []
    scanned = 0
    for idx, ip in enumerate(ips, 1):
        print(f"[{idx}/{len(ips)}] Checking {ip} ...")
        try:
            report = get_vt_ip_report(ip, api_key, retries=args.max_retries)
            parsed = parse_ip_report(ip, report)
            results.append(parsed)
            scanned += 1
        except Exception as e:
            print(f"Error checking {ip}: {e}")
            # record an error entry
            results.append({
                "ip": ip,
                "verdict": "error",
                "malicious_count": "",
                "suspicious_count": "",
                "harmless_count": "",
                "undetected_count": "",
                "total_positive": "",
                "first_seen": "",
                "last_analysis_date": ""
            })
        # Be polite with the free API. Sleep between calls.
        if idx != len(ips):
            time.sleep(args.delay)

    write_csv(output_path, results)
    # simple summary printed to console
    malicious_ips = [r for r in results if r.get("verdict") == "malicious"]
    clean_ips = [r for r in results if r.get("verdict") == "clean"]
    error_ips = [r for r in results if r.get("verdict") == "error"]
    print("==== Summary ====")
    print(f"Total scanned: {scanned}")
    print(f"Malicious: {len(malicious_ips)}")
    print(f"Clean: {len(clean_ips)}")
    print(f"Errors: {len(error_ips)}")
    print(f"Results written to: {output_path}")

if __name__ == "__main__":
    main()