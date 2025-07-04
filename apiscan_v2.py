```python
import argparse
import requests
import sys
import time
import json
import socket
from datetime import datetime
from urllib.parse import urlparse
from requests.exceptions import SSLError

# === Configuration ===
TIMEOUT = 3  # seconds for HTTP requests
JSON_FILE = "scan_report.json"

# === Default endpoints to scan initially ===
DEFAULT_ENDPOINTS = [
    ("GET", "/api/v1/user"),
    ("POST", "/api/v1/login"),
    ("GET", "/api/v1/public"),
]

# === Helpers & Formatting ===
COLS = {
    'target': 30,
    'method': 6,
    'endpoint': 25,
    'ip': 15,
    'status': 6,
    'time': 6,
}


def print_header():
    header = (
        f"{'TARGET':<{COLS['target']}} "
        f"{'METHOD':<{COLS['method']}} "
        f"{'ENDPOINT':<{COLS['endpoint']}} "
        f"{'IP':<{COLS['ip']}} "
        f"{'STAT':<{COLS['status']}} "
        f"{'MS':<{COLS['time']}}"
    )
    separator = '-' * len(header)
    print(f"\n{header}\n{separator}")


def print_footer(total, ok_count, alert_count, error_count):
    width = sum(COLS.values()) + len(COLS) - 1
    print(f"\n{'-'*width}\nSCAN COMPLETE: {total} endpoints | OK: {ok_count} | ALERT: {alert_count} | ERR: {error_count}\n")


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return 'N/A'


def format_row(data):
    return (
        f"{data['target']:<{COLS['target']}} "
        f"{data['method']:<{COLS['method']}} "
        f"{data['endpoint']:<{COLS['endpoint']}} "
        f"{data['ip']:<{COLS['ip']}} "
        f"{data['status']:<{COLS['status']}} "
        f"{data['time_ms']:<{COLS['time']}}"
    )


def scan_endpoint(api, method, path):
    url = api + path
    parsed = urlparse(api)
    host = parsed.hostname
    ip = resolve_ip(host)

    try:
        t0 = time.time()
        resp = requests.request(method, url, timeout=TIMEOUT)
        ms = int((time.time()-t0)*1000)
        stat = resp.status_code
    except SSLError:
        stat, ms = 'SSLERR', '-'
    except Exception:
        stat, ms = 'ERROR', '-'

    row = {
        'target': api,
        'method': method,
        'endpoint': path,
        'ip': ip,
        'status': stat,
        'time_ms': ms
    }
    print(format_row(row))

        # Response snippet only on HTTP 200
    if isinstance(stat, int) and stat == 200 and 'resp' in locals() and resp is not None:
        print('  Response snippet:')
        try:
            snippet = json.dumps(resp.json(), indent=2)
        except:
            snippet = resp.text
        for line in snippet.splitlines()[:10]:
            print('    ' + line)
        if len(snippet.splitlines()) > 10:
            print('    ...')

    return stat


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='API Null Auth Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='Single API base URL', metavar='URL')
    group.add_argument('-f', '--file', help='File of API base URLs, one per line', metavar='FILE')
    args = parser.parse_args()

    targets = []
    if args.file:
        with open(args.file) as f:
            for ln in f:
                targets.append(ln.strip().rstrip('/'))
    else:
        targets.append(args.target.rstrip('/'))

    print_header()
    total = ok = alert = err = 0

    for api in targets:
        for method, path in DEFAULT_ENDPOINTS:
            st = scan_endpoint(api, method, path)
            total += 1
            if isinstance(st, int) and st < 400:
                alert += 1
            elif isinstance(st, int) and st >= 400:
                ok += 1
            else:
                err += 1
        print_footer(total, ok, alert, err)

    # Write JSON summary (no results)
    with open(JSON_FILE, 'w') as jf:
        json.dump({'scan_time': datetime.now().isoformat()}, jf)
    sys.exit(1 if alert else (2 if err else 0))
```
