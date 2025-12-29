#!/usr/bin/env python3
# webrecon.py

import os
from datetime import datetime
import urllib3
from webrecon_utils import normalize_domain, main_menu, domain_menu, create_report_files
from webrecon_modules import (
    enumerate_subdomains,
    validate_dns,
    filter_hosts_for_posture,
    analyze_hosts,
    robots_sitemap,
)

urllib3.disable_warnings()

def main():
    if main_menu() == "2":
        return
    
    domain = None
    while not domain:
        domain = normalize_domain(input("Domain: "))
        if not domain:
            print("Invalid domain")
    
    selection = domain_menu()
    report = {
        "domain": domain,
        "timestamp": datetime.now().isoformat()
    }
    
    print(f"\nStarting analysis for: {domain}\n")
    
    # Subdomain enumeration
    if selection in {"1", "5"}:
        print("[STEP 1] Subdomain Enumeration")
        subs = enumerate_subdomains(domain)
        valid_subs = validate_dns(subs)
        report["subdomains"] = {
            "discovered": subs,
            "validated": valid_subs
        }
        print(f"Discovered: {len(subs)}, Validated DNS: {len(valid_subs)}\n")
    
    # Filter hosts by HTTP status
    if selection in {"3", "5"}:
        print("[STEP 2] Filter Hosts by HTTP status")
        valid_hosts = report.get("subdomains", {}).get("validated", [])
        working, blocked_data = filter_hosts_for_posture(valid_hosts)
        report["working_hosts"] = working
        report["blocked_data"] = blocked_data
        print(f"Working hosts (200 OK): {len(working)}")
        print(f"Blocked hosts (401/403): {len(blocked_data.get('blocked', {}))}\n")
        
        # Security posture analysis
        print("[STEP 3] Security Posture Analysis")
        posture_results = analyze_hosts(working)
        report["host_posture"] = posture_results
        print(f"Analyzed {len(working)} hosts\n")
    
    # Robots & Sitemap
    if selection in {"4", "5"}:
        print("[STEP 4] Robots & Sitemap")
        report["robots_sitemap"] = robots_sitemap(domain)
    
    # Create organized output files
    print("\n" + "="*80)
    folder = create_report_files(report)
    print(f"\nAll reports saved to folder: {folder}/")
    print("="*80)

if __name__ == "__main__":
    main()
