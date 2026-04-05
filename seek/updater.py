import requests, os
from pathlib import Path

SAVE_DIR = Path.home() / ".seek" / "blocklists"

URLS = {
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
    "emerging": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
}

def run_update(args):
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    sources = URLS if args.source == "all" else {args.source: URLS[args.source]}

    for name, url in sources.items():
        print(f"Updating {name}...")
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            dest = SAVE_DIR / f"{name}.txt"
            dest.write_text(resp.text)
            lines = len([l for l in resp.text.splitlines() if l and not l.startswith('#')])
            print(f"  {name}: {lines} entries saved.")
        except Exception as e:
            print(f"  {name}: Update failed — {e}. Bundled list will be used.")
