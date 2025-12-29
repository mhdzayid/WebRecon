# WebRecon - Early-Stage Web Reconnaissance Tool
---

## Overview

**WebRecon** is a Python-based reconnaissance tool designed for **early-stage web security reconnaissance**.  
It automates **passive and low-noise discovery** of web assets and performs **non-intrusive security posture checks** to help analysts quickly understand an application's external attack surface.

The tool intentionally avoids exploitation, brute-forcing, or deep fuzzing and instead focuses on **signal over noise**—surfacing assets that are most relevant for manual security review.

This project was built to demonstrate practical understanding of:
- web reconnaissance workflows
- asset discovery
- security posture assessment
- scalable and ethical scanning design

---

## 🎯 Design Philosophy

WebRecon is built around the following principles:

- **Early-stage only**: Designed for reconnaissance, not vulnerability exploitation  
- **Low noise**: Avoids endpoint brute-force, parameter fuzzing, or intrusive scanning  
- **Evidence-based**: Reports observable behavior only (headers, TLS metadata, HTTP methods)  
- **Human-first output**: Optimized for analysts to review results quickly  

This makes the tool suitable for:
- authorized penetration testing
- bug bounty reconnaissance (where allowed)
- security assessments
- educational and interview demonstrations

---

## Core Features

- **Subdomain Enumeration**
  - Aggregates subdomains from multiple passive sources (CertSpotter, RapidDNS)
  - Applies heuristic filtering to reduce noise from auto-generated subdomains

- **DNS Validation**
  - Parallel DNS resolution to identify active hosts
  - Eliminates inactive or stale subdomains

- **HTTP Status Classification**
  - Categorizes hosts by response behavior:
    - `200 OK`
    - `3xx Redirects`
    - `401 / 403` (authentication required)
    - `4xx / 5xx` errors
    - unreachable hosts

- **Security Posture Analysis**
  - Presence-based checks for:
    - common security headers
    - TLS certificate issuer & expiration
    - allowed HTTP methods
  - Flags potentially dangerous or risky HTTP methods

- **Robots.txt & Sitemap Analysis**
  - Extracts crawl directives and sitemap presence
  - Useful for understanding intended access boundaries

---

## Project Structure
```
webrecon/
├── webrecon.py              # Main orchestration & CLI entry point
├── webrecon_modules.py      # Reconnaissance and analysis logic
├── webrecon_utils.py        # Utilities (validation, menus, report generation)
├── requirements.txt         # Dependencies
└── README.md                # Documentation
```

---

## 🚀 Installation & Usage

### Requirements
- Python **3.8+**

### Clone the Repository
```bash
git clone https://github.com/mhdzayid/WebRecon
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run the Tool
```bash
python webrecon.py
```

### Execution Flow

1. **Select Analysis Mode**
   - Subdomain enumeration
   - Host security posture analysis
   - Robots.txt & sitemap analysis
   - Or run all modules

2. **Enter Target Domain**
   - Accepts `example.com`, `https://example.com`, `www.example.com`
   - Automatically normalizes input

3. **Automated Reconnaissance**
   - Parallelized discovery and analysis with progress indicators

4. **Report Generation**
   - Creates a timestamped output folder with structured results

---

## 📤 Output Structure

Example output directory:
```
example.com_20250129_143025/
├── 01_subdomains.txt              # DNS-validated subdomains
├── 02_working_hosts_200.txt       # Accessible hosts
├── 03_blocked_hosts_auth.txt      # Hosts requiring authentication
├── 04_security_posture.txt        # Header, TLS, HTTP method analysis
└── 05_robots_txt.txt              # robots.txt content (if present)
```

### Sample: Security Posture Output
```
Host: api.example.com
Status: 200

Security Headers: 4/6 present
  [PRESENT] Strict-Transport-Security
  [PRESENT] X-Frame-Options
  [MISSING] Content-Security-Policy

TLS Certificate:
  Issuer: DigiCert Inc
  Expires: Jul 15 2026 GMT

HTTP Methods: GET, POST, OPTIONS
  [OK] No dangerous methods detected
```

---

## 🌐 Data Sources

### Passive Subdomain Enumeration

**CertSpotter**
- Certificate Transparency logs
- No authentication required for basic usage (at time of writing)

**RapidDNS**
- Passive DNS aggregation
- HTML-based data source

Multiple sources are used to improve coverage and resilience.

---

## Scope & Limitations

**Does not perform:**
- endpoint or directory brute-forcing
- parameter fuzzing
- authentication bypass
- vulnerability exploitation

Analysis is surface-level and intended to guide manual review, not replace professional scanners.

Results depend on availability and completeness of passive data sources.

---

## Ethical Use & Legal Notice

** Authorized use only**

This tool must only be used on:
- systems you own
- environments where you have explicit permission
- approved bug bounty programs
- educational or lab environments

The tool is intentionally non-intrusive, but misuse may still violate local laws or organizational policies.

---

**⭐ If you find this tool useful, please give it a star on GitHub!**
