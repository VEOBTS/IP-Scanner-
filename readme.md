# SEEK
**Standalone IP threat intelligence CLI — no API key required.**

Seek scans IP addresses against locally stored blocklists (Firehol, Spamhaus, Emerging Threats). Everything runs offline. Blocklists update on demand. Ships as a single `pip install`.

## Installation

```bash
pip install seek
seek update        # pull fresh blocklists before first scan
```


## Commands

### `seek scan` — Scan IPs against local blocklists

| Flag | Description |
|------|-------------|
| `--ip <address>` | Scan a single IP directly |
| `--cidr <range>` | Scan a full CIDR range e.g. `10.0.0.0/24` |
| `-i, --input <file>` | Path to a file with one IP per line |
| `-o, --output <file>` | Path to output CSV file |
| `--json` | Output results as JSON instead of CSV |

**Examples:**
```bash
seek scan --ip 185.220.101.1
seek scan --cidr 192.168.1.0/24 -o results.csv
seek scan -i ips.txt -o results.csv
seek scan -i ips.txt --json
```

### `seek update` — Refresh local blocklists

Downloads the latest blocklists from Firehol, Spamhaus, and Emerging Threats and saves them to `~/.seek/blocklists/`. The bundled seed lists are never overwritten — they are always the fallback if an update fails.

| Flag | Description |
|------|-------------|
| `--source <name>` | Which list to update: `firehol`, `spamhaus`, `emerging`, or `all` (default: `all`) |

**Examples:**
```bash
seek update
seek update --source spamhaus
seek update --source firehol
```

### `seek watch` — Monitor live outbound connections

Polls all active outbound network connections on your machine every N seconds and flags any remote IP found in the local blocklists. No admin or root required on Windows.

| Flag | Description |
|------|-------------|
| `--interval <seconds>` | Poll frequency in seconds (default: `3`) |
| `--log <file>` | Optional path to write flagged IPs to a log file |

**Examples:**
```bash
seek watch
seek watch --interval 5
seek watch --interval 10 --log flagged.txt
```

## Output Format

### CSV columns (`seek scan`)
| Column | Description |
|--------|-------------|
| `ip` | The scanned IP address |
| `verdict` | `clean`, `malicious`, or `invalid` |
| `source` | Which blocklist flagged it (`firehol`, `spamhaus`, `emerging`) |

### Live watch output (`seek watch`)
Flagged connections print to terminal in real time in red. Clean connections are silent. If `--log` is set, flagged IPs are appended to the log file as `ip,source` per line.

## Blocklist Sources

| Source | Coverage |
|--------|----------|
| Firehol Level 1 | Known attackers, scanners, botnets |
| Spamhaus DROP | Hijacked IP space, spam infrastructure |
| Emerging Threats | Active threat actors, C2 servers |

Bundled seed lists ship with the package. Run `seek update` to get the latest versions.

## Data Storage

| Path | Contents |
|------|----------|
| `~/.seek/blocklists/` | User-updated blocklists (preferred at scan time) |
| Package `data/` folder | Bundled seed lists (fallback if no update has been run) |

---

## Author
**DEMEJI** — MIT License
