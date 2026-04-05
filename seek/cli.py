import argparse
import pyfiglet
from seek.scanner import run_scan
from seek.updater import run_update
from seek.watcher import run_watch

def main():
    print(pyfiglet.figlet_format("SEEK"))
    print("by \033[1;32mDEMEJI\033[0m")

    parser = argparse.ArgumentParser(
        prog="seek",
        description="Local IP threat intelligence — no API required"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- seek scan ---
    scan_p = sub.add_parser("scan", help="Scan IPs against local blocklists")
    scan_p.add_argument("-i", "--input", help="Path to file with one IP per line")
    scan_p.add_argument("-o", "--output", help="Path to output CSV file")
    scan_p.add_argument("--ip", help="Scan a single IP directly")
    scan_p.add_argument("--cidr", help="Scan a CIDR range e.g. 10.0.0.0/24")
    scan_p.add_argument("--json", action="store_true", help="Output as JSON instead of CSV")

    # --- seek update ---
    upd_p = sub.add_parser("update", help="Download fresh blocklists from the internet")
    upd_p.add_argument("--source", choices=["firehol","spamhaus","emerging","all"],
                        default="all", help="Which blocklist to update (default: all)")

    # --- seek watch ---
    watch_p = sub.add_parser("watch", help="Monitor live outbound connections")
    watch_p.add_argument("--interval", type=int, default=3,
                         help="Seconds between connection polls (default: 3)")
    watch_p.add_argument("--log", help="Optional path to write flagged connections")

    args = parser.parse_args()
    if args.command == "scan":   run_scan(args)
    elif args.command == "update": run_update(args)
    elif args.command == "watch":  run_watch(args)

if __name__ == "__main__":
    main()
