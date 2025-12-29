# =============================================================================
# webrecon_modules.py
# =============================================================================

#!/usr/bin/env python3

import socket
import ssl
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from webrecon_utils import SECURITY_HEADERS, DANGEROUS_METHODS, RISKY_METHODS, TIMEOUT, USER_AGENT

HOST_TIMEOUT = 3

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,
    pool_maxsize=50,
    max_retries=0
)
session.mount('https://', adapter)
session.mount('http://', adapter)

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 2
dns_resolver.lifetime = 2

# Subdomain enumeration

def valid_subdomain(name, domain):
    sub = name.replace(domain, "").strip(".")
    if not sub or sub == "www":
        return True
    if len(sub) > 63:
        return False
    if sum(c.isdigit() for c in sub) / len(sub) > 0.5:
        return False
    if sub.count("-") > 4:
        return False
    if len(sub) >= 32 and all(c in "0123456789abcdef-" for c in sub):
        return False
    if len(sub) > 20 and sum(c in "aeiou" for c in sub) < 2:
        return False
    if "*" in sub or "%" in sub:
        return False
    if sub.startswith("-") or sub.endswith("-"):
        return False
    return True

def subdomains_certspotter(domain):
    results = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        r = session.get(url, timeout=TIMEOUT)
        if r.status_code != 200:
            return results
        for entry in r.json():
            for name in entry.get("dns_names", []):
                name = name.lower()
                if name.endswith(domain) and valid_subdomain(name, domain):
                    results.add(name)
    except Exception:
        pass
    return results

def subdomains_rapiddns(domain):
    results = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = session.get(url, timeout=TIMEOUT)
        if r.status_code != 200:
            return results
        for line in r.text.splitlines():
            if "<td>" in line and domain in line:
                name = line.split("<td>")[1].split("</td>")[0].strip().lower()
                if name.endswith(domain) and valid_subdomain(name, domain):
                    results.add(name)
    except Exception:
        pass
    return results

def enumerate_subdomains(domain):
    subs = []
    cs = subdomains_certspotter(domain)
    rd = subdomains_rapiddns(domain)
    subs.extend(sorted(cs))
    subs.extend(sorted(rd))
    subs.append(domain)
    subs.append(f"www.{domain}")
    
    # Remove duplicates while preserving order
    seen = set()
    ordered = []
    for s in subs:
        if s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered

# DNS validation

def validate_single_dns(host):
    try:
        dns_resolver.resolve(host, "A")
        return host
    except Exception:
        return None

def validate_dns(hosts):
    print(f"  Validating {len(hosts)} hosts in parallel...")
    valid = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(validate_single_dns, host): host for host in hosts}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"    Progress: {completed}/{len(hosts)}")
            
            result = future.result()
            if result:
                valid.append(result)
    
    return valid

# HTTP status filtering

def probe_http_status(host):
    try:
        r = session.get(
            f"https://{host}/",
            timeout=HOST_TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        return (host, r.status_code)
    except Exception:
        return (host, None)

def filter_hosts_for_posture(subdomains, max_workers=30, limit=None, include_redirects=True):
    print(f"  Filtering {len(subdomains)} hosts by HTTP status (parallel)...")
    
    working_hosts = []
    redirect_hosts = {}
    blocked_hosts = {}
    client_error_hosts = {}
    server_error_hosts = {}
    unreachable = []
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_http_status, host): host for host in subdomains}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 20 == 0:
                elapsed = time.time() - start_time
                print(f"    Progress: {completed}/{len(subdomains)} ({elapsed:.1f}s)")
            
            host, status = future.result()
            
            if status == 200:
                working_hosts.append(host)
            elif status and 300 <= status < 400:
                redirect_hosts[host] = status
            elif status in {401, 403}:
                blocked_hosts[host] = status
            elif status and 400 <= status < 500:
                client_error_hosts[host] = status
            elif status and 500 <= status < 600:
                server_error_hosts[host] = status
            else:
                unreachable.append(host)
    
    elapsed = time.time() - start_time
    print(f"  Filtering completed in {elapsed:.1f}s")
    print(f"    - 200 OK: {len(working_hosts)}")
    print(f"    - 3xx Redirects: {len(redirect_hosts)}")
    print(f"    - 401/403 Auth Required: {len(blocked_hosts)}")
    print(f"    - 4xx Client Errors: {len(client_error_hosts)}")
    print(f"    - 5xx Server Errors: {len(server_error_hosts)}")
    print(f"    - Unreachable: {len(unreachable)}")
    
    all_accessible = working_hosts.copy()
    if include_redirects:
        all_accessible.extend(redirect_hosts.keys())
        print(f"    - Total accessible (200 + 3xx): {len(all_accessible)}")
    
    if limit and len(all_accessible) > limit:
        print(f"    - Limiting to first {limit} hosts")
        return all_accessible[:limit], {
            "blocked": blocked_hosts,
            "redirects": redirect_hosts,
            "client_errors": client_error_hosts,
            "server_errors": server_error_hosts
        }
    
    return all_accessible, {
        "blocked": blocked_hosts,
        "redirects": redirect_hosts,
        "client_errors": client_error_hosts,
        "server_errors": server_error_hosts
    }

# Host security posture

def security_headers(headers):
    return {h: h in headers for h in SECURITY_HEADERS}

def tls_details(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(3)
            s.connect((host, 443))
            cert = s.getpeercert()
        return {"issuer": cert.get("issuer"), "expires": cert.get("notAfter")}
    except Exception as e:
        return {"error": str(e)}

def http_methods(host):
    try:
        r = session.options(f"https://{host}/", timeout=3, verify=False)
        allow = r.headers.get("Allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        return {
            "allowed": methods,
            "dangerous": [m for m in methods if m in DANGEROUS_METHODS],
            "risky": [m for m in methods if m in RISKY_METHODS]
        }
    except Exception as e:
        return {"error": str(e)}

def host_posture(host):
    result = {"host": host}
    try:
        r = session.get(f"https://{host}/", timeout=3, verify=False)
        result["status"] = r.status_code
        result["headers"] = security_headers(r.headers)
    except Exception as e:
        result["http_error"] = str(e)
    
    result["tls"] = tls_details(host)
    result["methods"] = http_methods(host)
    return result

def analyze_hosts(hosts, max_workers=16):
    print(f"  Analyzing {len(hosts)} hosts in parallel (workers: {max_workers})...")
    results = []
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(host_posture, host): host for host in hosts}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            host = futures[future]
            
            try:
                result = future.result()
                results.append(result)
                
                status_str = "OK"
                if result.get("status") == 200:
                    sec_headers = result.get("headers", {})
                    present = sum(1 for v in sec_headers.values() if v)
                    status_str = f"[{result['status']}] Sec: {present}/{len(sec_headers)}"
                elif "http_error" in result:
                    status_str = "Error"
                else:
                    status_str = f"[{result.get('status', '?')}]"
                
                print(f"    [{completed}/{len(hosts)}] {status_str} {host}")
            except Exception as e:
                results.append({"host": host, "error": str(e)})
                print(f"    [{completed}/{len(hosts)}] Error {host} - {str(e)[:40]}")
    
    elapsed = time.time() - start_time
    avg_time = elapsed / len(hosts) if hosts else 0
    print(f"  Analysis completed in {elapsed:.1f}s (avg: {avg_time:.1f}s/host)")
    
    return results

# Robots & sitemap

def robots_sitemap(domain):
    out = {}
    try:
        r = session.get(f"https://{domain}/robots.txt", timeout=TIMEOUT)
        out["robots"] = {
            "exists": r.status_code == 200,
            "content": r.text if r.status_code == 200 else None
        }
    except Exception as e:
        out["robots"] = {"error": str(e)}
    
    try:
        r = session.get(f"https://{domain}/sitemap.xml", timeout=TIMEOUT)
        out["sitemap"] = {"exists": r.status_code == 200}
    except Exception as e:
        out["sitemap"] = {"error": str(e)}
    
    return out
