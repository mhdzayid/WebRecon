#=============================================================================
# webrecon_utils.py
# =============================================================================

#!/usr/bin/env python3

import os
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

USER_AGENT = "webrecon/1.0"
TIMEOUT = 10

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DANGEROUS_METHODS = {"TRACE", "CONNECT"}
RISKY_METHODS = {"PUT", "DELETE", "PATCH"}

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}"
    r"(\.(?!-)[A-Za-z0-9-]{1,63})+$"
)

def normalize_domain(value: str):
    if not value:
        return None
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    if value.startswith("www."):
        value = value[4:]
    try:
        socket.inet_aton(value)
        return None
    except Exception:
        pass
    if not DOMAIN_REGEX.match(value):
        return None
    return value

def main_menu():
    print("\n1) Analyze domain")
    print("2) Exit")
    while True:
        choice = input("Select option: ").strip()
        if choice in {"1", "2"}:
            return choice

def domain_menu():
    print("\n1) Subdomain enumeration")
    print("2) WHOIS lookup")
    print("3) Host security posture")
    print("4) Robots & sitemap")
    print("5) Run all")
    while True:
        choice = input("Select module: ").strip()
        if choice in {"1", "2", "3", "4", "5"}:
            return choice

def format_tls_issuer(issuer_data):
    if not issuer_data:
        return "N/A"
    parts = []
    for item in issuer_data:
        for pair in item:
            if len(pair) == 2:
                key, value = pair
                if key == "commonName":
                    parts.append(value)
                elif key == "organizationName":
                    parts.append(value)
    return ", ".join(parts) if parts else "Unknown"

def create_report_files(report):
    # Create folder
    domain = report.get("domain", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{domain}_{timestamp}"
    
    os.makedirs(folder_name, exist_ok=True)
    
    # File 1: All discovered subdomains
    if "subdomains" in report:
        write_subdomains_file(folder_name, report)
    
    # File 2: Working hosts (200 OK)
    if "working_hosts" in report:
        write_working_hosts_file(folder_name, report)
    
    # File 3: Blocked hosts (401/403)
    if "blocked_data" in report:
        write_blocked_hosts_file(folder_name, report)
    
    # File 4: Security posture analysis
    if "host_posture" in report:
        write_posture_file(folder_name, report)
    
    # File 5: Robots.txt content
    if "robots_sitemap" in report:
        write_robots_file(folder_name, report)
    
    return folder_name

def write_subdomains_file(folder, report):
    filepath = os.path.join(folder, "01_subdomains.txt")
    subs = report["subdomains"]
    
    with open(filepath, "w") as f:
        for sub in sorted(subs['validated']):
            f.write(f"{sub}\n")

def write_working_hosts_file(folder, report):
    filepath = os.path.join(folder, "02_working_hosts_200.txt")
    
    with open(filepath, "w") as f:
        for host in sorted(report['working_hosts']):
            f.write(f"{host}\n")

def write_blocked_hosts_file(folder, report):
    filepath = os.path.join(folder, "03_blocked_hosts_auth.txt")
    blocked_data = report['blocked_data']
    
    with open(filepath, "w") as f:
        blocked = blocked_data.get('blocked', {})
        
        for host in sorted(blocked.keys()):
            f.write(f"{host}\n")

def write_posture_file(folder, report):
    filepath = os.path.join(folder, "04_security_posture.txt")
    
    with open(filepath, "w") as f:
        f.write("="*80 + "\n")
        f.write("SECURITY POSTURE ANALYSIS\n")
        f.write("="*80 + "\n\n")
        f.write(f"Domain: {report['domain']}\n")
        f.write(f"Timestamp: {report['timestamp']}\n")
        f.write(f"Hosts analyzed: {len(report['host_posture'])}\n\n")
        
        for host_data in report['host_posture']:
            f.write("="*80 + "\n")
            f.write(f"Host: {host_data['host']}\n")
            f.write("="*80 + "\n\n")
            
            # HTTP status
            if "http_error" in host_data:
                f.write(f"Status: Error - {host_data['http_error']}\n\n")
            else:
                f.write(f"Status: {host_data.get('status', 'Unknown')}\n\n")
            
            # Security headers
            if "headers" in host_data:
                headers = host_data["headers"]
                present = sum(1 for v in headers.values() if v)
                f.write(f"Security Headers: {present}/{len(headers)} present\n")
                for header, is_present in headers.items():
                    status = "[PRESENT]" if is_present else "[MISSING]"
                    f.write(f"  {status} {header}\n")
                f.write("\n")
            
            # TLS
            if "tls" in host_data:
                tls = host_data["tls"]
                if "error" in tls:
                    f.write(f"TLS: Error - {tls['error']}\n\n")
                else:
                    issuer = format_tls_issuer(tls.get("issuer"))
                    expires = tls.get("expires", "Unknown")
                    f.write(f"TLS Certificate:\n")
                    f.write(f"  Issuer: {issuer}\n")
                    f.write(f"  Expires: {expires}\n\n")
            
            # HTTP methods
            if "methods" in host_data:
                methods = host_data["methods"]
                if "error" in methods:
                    f.write(f"HTTP Methods: Error - {methods['error']}\n\n")
                else:
                    allowed = methods.get("allowed", [])
                    dangerous = methods.get("dangerous", [])
                    risky = methods.get("risky", [])
                    
                    f.write(f"HTTP Methods: {', '.join(allowed) if allowed else 'None detected'}\n")
                    
                    if dangerous:
                        f.write(f"  [CRITICAL] Dangerous methods: {', '.join(dangerous)}\n")
                    if risky:
                        f.write(f"  [WARNING] Risky methods: {', '.join(risky)}\n")
                    if not dangerous and not risky:
                        f.write(f"  [OK] No dangerous methods detected\n")
                    f.write("\n")

def write_robots_file(folder, report):
    filepath = os.path.join(folder, "05_robots_txt.txt")
    rs = report['robots_sitemap']
    
    with open(filepath, "w") as f:
        if "robots" in rs:
            robots = rs["robots"]
            if robots.get("exists") and robots.get("content"):
                f.write(robots["content"])
