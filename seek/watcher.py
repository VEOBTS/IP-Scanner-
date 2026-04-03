import psutil, time, socket
from seek.blocklist import BlocklistStore
from rich.console import Console
from rich.table import Table as RichTable

console = Console()

def run_watch(args):
    store = BlocklistStore()
    store.load()
    seen = set()
    log_file = open(args.log, 'a') if args.log else None

    console.print("[bold green]SEEK WATCH[/] — monitoring live connections. Ctrl+C to stop.\n")

    try:
        while True:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.raddr and c.raddr.ip:
                    ip = c.raddr.ip
                    if ip in seen: continue
                    seen.add(ip)
                    result = store.check_ip(ip)
                    if result['verdict'] == 'malicious':
                        console.print(f"[bold red]FLAGGED[/] {ip} — source: {result['source']}")
                        if log_file:
                            log_file.write(f"{ip},{result['source']}\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[grey]Watch stopped.[/]")
    finally:
        if log_file: log_file.close()
