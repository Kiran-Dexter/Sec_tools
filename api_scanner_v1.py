import argparse
import requests
import sys
import time
import json
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
from requests.exceptions import SSLError

# === Configuration ===
TIMEOUT = 3  # seconds for HTTP requests
JSON_FILE = "scan_report.json"

# === Default endpoints to scan initially for base URLs ===
DEFAULT_ENDPOINTS = [
    ("GET", "/api/v1/user"),
    ("POST", "/api/v1/login"),
    ("GET", "/api/v1/public"),
]

# === Common paths for brute-force spidering ===
COMMON_PATHS = [
    "/", "/health", "/status", "/api", "/login", "/users",
    "/swagger.json", "/openapi.json", "/docs"
]

# === HTTP methods to test during spidering ===
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# === Column widths for neat output ===
COLS = {
    'target': 30,
    'method': 6,
    'endpoint': 25,
    'ip': 15,
    'status': 6,
    'time': 6,
    'cert': 10,
    'cipher': 20,
    'tls': 8,
}

# === Helpers ===
def print_header():
    header = (
        f"{'TARGET':<{COLS['target']}} "
        f"{'METHOD':<{COLS['method']}} "
        f"{'ENDPOINT':<{COLS['endpoint']}} "
        f"{'IP':<{COLS['ip']}} "
        f"{'STAT':<{COLS['status']}} "
        f"{'MS':<{COLS['time']}} "
        f"{'CERT_EXP':<{COLS['cert']}} "
        f"{'CIPHER':<{COLS['cipher']}} "
        f"{'TLS':<{COLS['tls']}}"
    )
    separator = '-' * len(header)
    print(f"\n{header}\n{separator}")


def print_footer(total, ok_count, alert_count, error_count):
    print('\n' + '-' * sum(COLS.values()) + f"\nSCAN COMPLETE: {total} endpoints | OK: {ok_count} | ALERT: {alert_count} | ERR: {error_count}\n")


def get_tls_info(hostname, port=443, timeout=3):
    ctx = ssl.create_default_context()
    info = {"cert_expiry": None, "cipher": None, "tls_version": None}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp = cert.get('notAfter')
                if exp:
                    info['cert_expiry'] = datetime.strptime(exp, '%b %d %H:%M:%S %Y %Z')
                ci = ssock.cipher()
                info['cipher'] = f"{ci[0]} ({ci[2]}b)"
                info['tls_version'] = ci[1]
    except:
        pass
    return info


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
        f"{data['time_ms']:<{COLS['time']}} "
        f"{data['cert_expiry']:<{COLS['cert']}} "
        f"{data['cipher']:<{COLS['cipher']}} "
        f"{data['tls_version']:<{COLS['tls']}}"
    )


def scan_endpoint(api, method, path, known_public):
    url = api + path
    parsed = urlparse(api)
    scheme, host = parsed.scheme, parsed.hostname
    port = parsed.port or (443 if scheme=='https' else 80)
    ip = resolve_ip(host)
    tls = get_tls_info(host, port) if scheme=='https' else {'cert_expiry':'N/A','cipher':'N/A','tls_version':'N/A'}

    resp = None
    try:
        t0 = time.time()
        resp = requests.request(method, url, timeout=TIMEOUT, verify=True)
        ms = int((time.time()-t0)*1000)
        stat, reason = resp.status_code, resp.reason
        tag = 'ALERT' if stat < 400 else 'OK'
    except SSLError:
        stat, reason, ms, tag = 'SSLERR', '', '-', 'ERR'
    except Exception:
        stat, reason, ms, tag = 'ERROR', '', '-', 'ERR'

    row = {
        'target': api,
        'method': method,
        'endpoint': path,
        'ip': ip,
        'status': stat,
        'time_ms': ms,
        'cert_expiry': tls['cert_expiry'].strftime('%Y-%m-%d') if tls.get('cert_expiry') else 'N/A',
        'cipher': tls.get('cipher','N/A'),
        'tls_version': tls.get('tls_version','N/A')
    }
    print(format_row(row))

    # Print formatted response snippet (terminal only)
    if resp is not None:
        print('  Response snippet:')
        try:
            data = resp.json()
            snippet = json.dumps(data, indent=2)
        except Exception:
            snippet = resp.text
        for line in snippet.splitlines()[:10]:  # show first 10 lines
            print('    ' + line)
        if len(snippet.splitlines()) > 10:
            print('    ...')

    return stat


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Neat API Null Auth & TLS Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t','--target',help='Single API URL (base or full path)',metavar='URL')
    group.add_argument('-f','--file',help='File of API URLs, one per line',metavar='FILE')
    parser.add_argument('-p','--public',help='Comma-separated public paths to skip',default='',metavar='PATHS')
    args = parser.parse_args()

    public = [p.strip() for p in args.public.split(',') if p]
    endpoints = []

    # Determine targets and scan lists
    targets = []
    if args.file:
        with open(args.file) as f:
            for ln in f:
                u = ln.strip().rstrip('/')
                targets.append((u, False))
    else:
        pt = urlparse(args.target)
        full = bool((pt.path and pt.path!='/') or pt.query)
        base = args.target.rstrip('/')
        targets.append((base, full))

    print_header()
    total=ok=alert=err=0
    for api, is_full in targets:
        scan_list = [("GET",pt.path+('?'+pt.query if pt.query else ''))] if is_full else DEFAULT_ENDPOINTS
        default_200 = False
        for m,p in scan_list:
            st = scan_endpoint(api,m,p,public)
            total+=1
            if st==200: default_200=True
            if st<400: alert+=1
            elif st>=400 and isinstance(st,int): ok+=1
            else: err+=1
        if not is_full and not default_200:
            for p in COMMON_PATHS:
                if p in public: continue
                for m in METHODS:
                    st = scan_endpoint(api,m,p,public)
                    total+=1
                    if st<400: alert+=1
                    elif st>=400 and isinstance(st,int): ok+=1
                    else: err+=1
    print_footer(total, ok, alert, err)
    # Write JSON
    with open(JSON_FILE,'w') as jf:
        json.dump({'scan_time':datetime.now().isoformat(),'results':[]},jf)
    sys.exit(1 if alert else (2 if err else 0))
