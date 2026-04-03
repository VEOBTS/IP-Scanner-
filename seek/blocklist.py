import os, ipaddress
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
USER_DIR = Path.home() / ".seek" / "blocklists"

SOURCES = {
    "firehol": "firehol_level1.netset",
    "spamhaus": "spamhaus_drop.txt",
    "emerging": "emerging_threats.txt",
}

class BlocklistStore:
    def __init__(self):
        self.networks = []   # list of ipaddress.ip_network objects
        self.ips = set()     # flat set of individual IPs
        self.source_map = {} # ip/network -> which blocklist flagged it

    def load(self):
        for source, filename in SOURCES.items():
            # prefer user-updated version, fall back to bundled seed
            path = USER_DIR / filename
            if not path.exists():
                path = DATA_DIR / filename
            self._load_file(path, source)

    def _load_file(self, path, source):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    self.networks.append((net, source))
                except ValueError:
                    pass  # skip malformed lines

    def check_ip(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return {"ip": ip_str, "verdict": "invalid", "source": None}

        for (net, source) in self.networks:
            if addr in net:
                return {"ip": ip_str, "verdict": "malicious", "source": source}
        return {"ip": ip_str, "verdict": "clean", "source": None}
