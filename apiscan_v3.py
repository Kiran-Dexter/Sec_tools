import argparse
import requests
import subprocess
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

# === Default endpoints ===
DEFAULT_ENDPOINTS = [
    ("GET", "/api/v1/user"),
    ("POST", "/api/v1/login"),
    ("GET", "/api/v1/public"),
]

# === Formatting helpers ===
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
    print(f"\n{header}\n{'-'*len(header)}")

def print_footer(total, null_count, ok_count, error_count):
    width = sum(COLS.values()) + len(COLS) - 1
    print(f"\n{'-'*width}\nSCAN COMPLETE: {total} endpoints | NULL(200): {null_count} | OK(!200): {ok_count} | ERR: {error_count}\n")

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

    # CURL fallback
    print(f"\n>> CURL: {method} {url}")
    curl_status = None
    try:
        proc = subprocess.run(['curl','-k','-i','-X',method,url],capture_output=True,text=True,timeout=TIMEOUT)
        lines = proc.stdout.splitlines()
        for l in lines[:10]: print('   '+l)
        if len(lines)>10: print('   ...')
        if lines:
            parts = lines[0].split()
            curl_status = parts[1] if len(parts)>=2 else None
    except Exception as e:
        print(f"   CURL ERROR: {e}")

    # If curl sees 200, collect JSON and return
    if curl_status=='200':
        print('  NULL auth detected (200); JSON evidence:')
        try:
            resp = requests.request(method,url,timeout=TIMEOUT)
            js = json.dumps(resp.json(),indent=2)
        except:
            js = '(no JSON)'
        for ln in js.splitlines(): print('    '+ln)
        return 200

    # Python request
    resp=None
    try:
        t0=time.time()
        resp=requests.request(method,url,timeout=TIMEOUT)
        ms=int((time.time()-t0)*1000)
        stat=resp.status_code
    except SSLError:
        stat,ms='SSLERR','-'
    except:
        stat,ms='ERROR','-'

    row={ 'target':api,'method':method,'endpoint':path,'ip':ip,'status':stat,'time_ms':ms }
    print(format_row(row))
    return stat

if __name__=='__main__':
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('-t','--target',metavar='URL')
    g.add_argument('-f','--file',metavar='FILE')
    args=p.parse_args()

    targets=[]
    if args.file:
        with open(args.file) as f:
            targets=[ln.strip().rstrip('/') for ln in f if ln.strip()]
    else:
        targets=[args.target.rstrip('/')]

    print_header()
    total=null_cnt=ok_cnt=err_cnt=0
    for api in targets:
        for m,pth in DEFAULT_ENDPOINTS:
            st=scan_endpoint(api,m,pth)
            total+=1
            if st==200: null_cnt+=1
            elif isinstance(st,int) and st!=200: ok_cnt+=1
            else: err_cnt+=1
    print_footer(total,null_cnt,ok_cnt,err_cnt)
    with open(JSON_FILE,'w') as jf:
        json.dump({'scan_time':datetime.now().isoformat()},jf)
    print(f"JSON summary written to {JSON_FILE}")
    sys.exit(1 if null_cnt else (2 if err_cnt else 0))
