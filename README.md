<div align="center">

<pre>
██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██╗  ██╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝
███████║ ╚████╔╝ ██║  ██║██████╔╝███████║ ╚███╔╝ 
██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║ ██╔██╗ 
██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██╔╝ ██╗
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
</pre>

**Enterprise Bug Bounty Automation Platform**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-5.3%2B-37814A?style=for-the-badge&logo=celery&logoColor=white)
![License](https://img.shields.io/badge/License-Proprietary-critical?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-Deepesh%20Mahawar-blueviolet?style=for-the-badge)

**Designed & engineered by Deepesh Mahawar — Cybersecurity Engineer / SOC Analyst**

> 🛑 **PROPRIETARY & CONFIDENTIAL — ALL RIGHTS RESERVED**
> This project, including all source code, documentation, architecture, and design, is the **sole intellectual property of Deepesh Mahawar**. It is published here **solely to establish authorship, ownership, and provenance** of original work. **No license, permission, or right of any kind is granted** to any person or entity to use, copy, clone, fork, modify, distribute, sublicense, resell, or create derivative works from this repository, in whole or in part. Any such use without the author's explicit prior **written** consent is strictly prohibited. **Any violation, unauthorized use, or redistribution will be treated as infringement and misappropriation of intellectual property and will be pursued and acted upon to the fullest extent available under applicable law.**
>
> ⚠️ **SECURITY-TESTING NOTICE** — HydraX is an offensive security tool intended **exclusively for authorized engagements** where explicit written permission has been granted by the target system's owner. Unauthorized testing against systems you do not own or lack written consent to assess is **illegal** and may result in criminal prosecution. The author assumes no liability for any misuse by third parties.

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Scanner Modules](#-scanner-modules)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running HydraX](#-running-hydrax)
- [API Reference](#-api-reference)
- [Scan Profiles](#-scan-profiles)
- [Report Formats](#-report-formats)
- [Docker Deployment](#-docker-deployment)
- [Security Model](#-security-model)
- [Legal & Ethics](#-legal--ethics)
- [Author & Ownership](#-author--ownership)
- [License](#-license)

---

## 🎯 Overview

**HydraX** is a full-stack, enterprise-grade bug bounty automation platform built for security researchers, penetration testers, and SOC analysts. It combines a native desktop GUI (CustomTkinter) with a production-hardened FastAPI backend, enabling parallel multi-scanner execution across target web applications with multi-tenant organization support, role-based access control, and structured reporting.

HydraX is purpose-built to accelerate the recon-to-report cycle in authorized bug bounty engagements — letting researchers focus on chain exploitation rather than manual enumeration.

> 🚧 **Project status:** HydraX is an **actively developed, ongoing project**. The codebase is published to establish authorship and track progress; features are evolving and the platform is **not** positioned as a finished or publicly distributable product.

---

## ✨ Features

| Category | Capabilities |
|---|---|
| **Active Scanning** | XSS (reflected/stored/DOM), SQLi (error/boolean/time/union), SSRF, CSRF, RCE, IDOR, broken access control, subdomain takeover, security misconfiguration, info disclosure |
| **Passive Recon** | DNS enumeration, subdomain discovery, HTTP header analysis, technology fingerprinting, certificate transparency |
| **JS-Aware Crawling** | Playwright/Chromium-powered surface discovery for SPAs and JavaScript-heavy applications |
| **API Security** | REST API fuzzing, authentication bypass, JWT attacks, GraphQL introspection |
| **Cloud Security** | S3 bucket exposure, cloud metadata endpoint testing, misconfigured cloud resources |
| **Reporting** | HTML (interactive), JSON (machine-readable), SARIF (GitHub/CI-compatible) |
| **Multi-Tenancy** | Organization-scoped data isolation, RBAC, JWT auth with fail-closed design |
| **Alerting** | SMTP-based alerting with configurable cooldowns, SSE event streaming |
| **Scheduling** | Celery + Redis async scan queue, concurrent scan throttling |
| **Remediation** | AI-assisted remediation engine with OWASP-mapped knowledge base |

---

## 🏗️ Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                       HydraX Platform                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────┐      ┌───────────────────────────┐  │
│  │ Desktop Client (GUI)│      │     API Server (FastAPI)  │  │
│  │                     │      │                           │  │
│  │ CustomTkinter UI    │      │ POST /api/scans/          │  │
│  │ main_window.py      │      │ GET  /api/findings/       │  │
│  │ views/ (dashboard,  │      │ GET  /api/reports/        │  │
│  │ scanner, results,   │      │ SSE  /api/events/         │  │
│  │ reports, settings)  │      │ POST /api/brain/resolve   │  │
│  └──────────┬──────────┘      └─────────────┬─────────────┘  │
│             │                               │                │
├─────────────┴───────────────────────────────┴────────────────┤
│                       Shared Core Layer                      │
│                                                              │
│  ┌────────┐  ┌──────────┐  ┌────────┐  ┌─────────────────┐   │
│  │ core/  │  │scanners/ │  │ utils/ │  │ config/         |   │
│  │ engine │  │ 11 mods  │  │crawler │  │ profiles        |   │
│  │context │  │ parallel │  │reporter│  │remediation KB   │   │
│  │storage │  │execution │  │payloads│  │scope enforcement│   │
│  └────────┘  └──────────┘  └────────┘  └─────────────────┘   │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                      │
│                                                              │
│          PostgreSQL (multi-tenant) · Redis · Celery          │
│                                                              │
│             Docker Compose · Nginx (optional)                │
└──────────────────────────────────────────────────────────────┘
```

### 🔄 Data Flow

```text
1. Target URL submitted (GUI or API)
             │
             ▼
2. URL Discovery (Playwright + BeautifulSoup)
   → Crawls links, forms, parameters, endpoints
             │
             ▼
3. ScanEngine.scan() → ScanContext created
   → Selected scanners dispatched in parallel threads
             │
             ▼
4. Scanner modules execute against attack surface
   → Findings aggregated into ScanReport
             │
             ▼
5. ScanReport persisted → HTML/JSON/SARIF generated
   → SSE events pushed to connected clients
   → Alerts fired if critical findings detected
```

## 🔬 Scanner Modules

| Module | File | Techniques |
|---|---|---|
| **XSS Scanner** | scanners/xss_scanner.py | Reflected, Stored, DOM-based; polyglot payloads; context-aware encoding bypass |
| **SQL Injection** | scanners/sql_injection.py | Error-based, Boolean blind, Time-based blind, UNION-based; WAF evasion |
| **Broken Access Control** | scanners/broken_access.py | IDOR, privilege escalation, forced browsing, UUID prediction |
| **Advanced Scanners** | scanners/advanced_scanners.py | SSRF, CSRF, RCE, API abuse, cloud metadata, XXE, SSTI, Open Redirect |
| **Info Disclosure** | scanners/info_disclosure.py | Sensitive file exposure, error messages, stack traces, debug endpoints |
| **Security Misconfiguration** | scanners/security_misconfig.py | Missing headers, insecure cookies, CORS misconfiguration, TLS issues |
| **Subdomain Takeover** | scanners/subdomain_takeover.py | Dangling DNS, orphaned cloud resources, CNAME hijacking |
| **Passive Recon** | scanners/passive_recon.py | DNS records, certificate transparency, technology fingerprinting |
| **DDoS Tester** | scanners/ddos_tester.py | Rate limit testing, resource exhaustion checks (authorized environments only) |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Desktop GUI** | Python 3.8+, CustomTkinter ≥5.2.2, Pillow |
| **API Backend** | FastAPI ≥0.110, Uvicorn, Pydantic v2 |
| **Database** | PostgreSQL ≥15 (psycopg2), no SQLite fallback — multi-tenant by design |
| **Task Queue** | Celery ≥5.3 + Redis ≥5.0 |
| **HTTP / Crawling** | aiohttp, requests, Playwright/Chromium (JS rendering) |
| **Parsing** | BeautifulSoup4, lxml, tldextract, dnspython |
| **Auth / Crypto** | PyJWT, cryptography, pyotp (TOTP 2FA) |
| **Reporting** | ReportLab (PDF), Markdown, SARIF |
| **Containerization** | Docker, Docker Compose |
| **Testing** | pytest, pytest-asyncio, httpx (hermetic — no real DB/network) |

---

## 📋 Prerequisites

### System Requirements

- **OS**: Kali Linux (recommended), Ubuntu 22.04+, Debian 12+
- **Python**: 3.8 or higher
- **Docker**: 24.0+ (for containerized deployment)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: 2 GB free space

### External Tools (used by scanners)

`ash
sudo apt-get install -y nmap nikto whatweb dirb wfuzz
`

---

## 🚀 Installation

### Option 1 — Local Setup (Desktop + API)

`ash
# 1. Clone the repository
git clone https://github.com/deepmaha2006/bugbounty-automation.git
cd bugbounty-automation

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install Playwright browser (for JS crawling)
playwright install chromium

# 5. Verify everything is wired correctly
python run_checks.py
`

### Option 2 — Docker (Recommended for API mode)

`ash
git clone https://github.com/deepmaha2006/bugbounty-automation.git
cd bugbounty-automation

cp .env.example .env
# Edit .env with your values

docker compose up -d
docker compose logs -f hydrax
`

---

## ⚙️ Configuration

`ash
cp .env.example .env
`

### Critical Settings

`env
# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=hydrax
POSTGRES_USER=postgres
POSTGRES_PASSWORD=CHANGE_ME

# JWT (REQUIRED — app refuses to start without this)
HYDRAX_JWT_SECRET=                   # generate: openssl rand -hex 32

# Bootstrap Admin
HYDRAX_ADMIN_USERNAME=admin
HYDRAX_ADMIN_PASSWORD=CHANGE_ME

# Redis / Celery
HYDRAX_REDIS_URL=redis://localhost:6379/0

# Alerting (SMTP)
HYDRAX_SMTP_HOST=smtp.yourdomain.com
HYDRAX_SMTP_PORT=587
HYDRAX_SMTP_USERNAME=alerts@yourdomain.com
HYDRAX_SMTP_PASSWORD=
HYDRAX_SMTP_FROM=alerts@hydrax.local
`

> ⚠️ Never commit .env. Never set HYDRAX_JWT_DEV_MODE=1 in production.

---

## 🖥️ Running HydraX

### Desktop GUI

`ash
python3 main.py
`

### API Server

`ash
# Development
export HYDRAX_JWT_SECRET=
uvicorn webapp.main:app --host 0.0.0.0 --port 8000 --reload

# Production
./start.sh
`

### Celery Worker

`ash
celery -A webapp.celery_app worker --loglevel=info --concurrency=4
`

### Test Suite

`ash
python run_checks.py   # syntax + import check
python -m pytest -q    # hermetic tests (no real DB/network)
`

---

## 📡 API Reference

Interactive docs available at http://localhost:8000/docs (Swagger UI) and /redoc.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/login | Authenticate, receive JWT |
| POST | /api/auth/register | Register new user/org |
| GET | /api/scans/ | List all scans (org-scoped) |
| POST | /api/scans/ | Initiate a new scan |
| GET | /api/scans/{id} | Scan status & findings |
| DELETE | /api/scans/{id} | Cancel/delete a scan |
| GET | /api/findings/ | Query findings (filter by severity/type) |
| GET | /api/reports/ | List generated reports |
| GET | /api/reports/{id}/download | Download report |
| GET | /api/dashboard/ | Aggregate stats & metrics |
| GET | /api/events/ | SSE stream for real-time updates |
| POST | /api/brain/resolve | AI-powered remediation advice |
| GET | /api/assets/ | Manage target assets |
| POST | /api/verification/ | Scope verification (DNS TXT / engagement letter) |

---

## 📂 Scan Profiles

YAML presets in config/profiles/:

| Profile | File | Use Case |
|---|---|---|
| Full Web Scan | web-full.yaml | Comprehensive OWASP Top 10 coverage |
| API Security | pi-security.yaml | REST/GraphQL API fuzzing & auth testing |
| Mobile API | mobile-api.yaml | Mobile app backend testing |
| Cloud | cloud.yaml | Cloud infrastructure & metadata endpoint testing |

---

## 📊 Report Formats

| Format | Use Case |
|---|---|
| **HTML** | Bug bounty reports, client delivery — interactive severity breakdown |
| **JSON** | API integrations, custom pipelines |
| **SARIF** | GitHub Code Scanning, CI/CD integration |

Reports saved to 
eports/.

---

## 🐳 Docker Deployment

`ash
docker compose up -d

# Services:
#   hydrax-api     → FastAPI on :8000
#   hydrax-worker  → Celery task worker
#   postgres       → PostgreSQL on :5432
#   redis          → Redis on :6379

docker compose ps
docker compose down -v
`

For Nginx reverse proxy setup, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## 🔒 Security Model

- **Fail-Closed Auth** — No JWT secret → app refuses to start. No insecure defaults.
- **Multi-Tenant Isolation** — All queries org-scoped at the DB layer.
- **RBAC** — Role enforcement on every API route.
- **Scope Enforcement** — DNS TXT / engagement letter verification before scans.
- **Rate Limiting** — Adaptive per-host throttling prevents accidental DoS.
- **CORS Lockdown** — Never llow_origins=* with llow_credentials=True.
- **Trusted Proxy** — X-Forwarded-For only trusted from explicitly configured IPs.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## ⚖️ Legal & Ethics

**You MUST have explicit written permission before testing any system.**

✅ Systems you personally own  
✅ Bug bounty programs (within defined scope)  
✅ Signed penetration testing engagements  
❌ Systems you do not own  
❌ Any unauthorized testing — regardless of intent  

Misuse may violate the **CFAA**, **Computer Misuse Act**, **GDPR**, and equivalent laws in your jurisdiction. **The author accepts no responsibility for illegal or unethical use.**

---

## 👤 Author & Ownership

**HydraX is designed, built, and solely owned by Deepesh Mahawar.**

- **Author / Owner:** Deepesh Mahawar
- **Role:** Cybersecurity Engineer · SOC Analyst
- **GitHub:** [@deepmaha2006](https://github.com/deepmaha2006)

This repository represents original, independently authored work. It is maintained by the author alone, and all design decisions, implementation, and intellectual property are attributable exclusively to Deepesh Mahawar.

---

## 📜 License

**Proprietary — All Rights Reserved. © Deepesh Mahawar.**

This software is **not** open source and is **not** released under any permissive or copyleft license. It is published publicly **only** to establish and timestamp authorship and ownership.

**You may NOT**, without the author's explicit prior written permission:

- ❌ Use the software or any part of it for any purpose
- ❌ Copy, clone, fork, or reproduce the repository or its code
- ❌ Modify, adapt, or build derivative works from it
- ❌ Distribute, publish, sublicense, resell, or share it
- ❌ Incorporate any portion of it into other projects

Unauthorized use, reproduction, or distribution constitutes infringement and misappropriation of intellectual property. **The author reserves the right to pursue and act upon any violation to the fullest extent permitted under applicable law.** For licensing or permission inquiries, contact the author directly.

---

## 📁 Project Structure

```text
bugbounty-automation/
├── main.py                    # Desktop app entry point
├── run_checks.py              # Syntax/import verification
├── run_test_scan.py           # Programmatic scan runner
├── requirements.txt           # Python dependencies
├── setup.sh / start.sh        # Setup and launch scripts
├── Dockerfile                 # Container image
├── docker-compose.yml         # Full stack orchestration
├── .env.example               # Environment variable template
├── config/                    # Settings, profiles, scope, remediation KB
├── core/                      # Scan engine, context, models, storage
├── scanners/                  # 9 scanner modules
├── utils/                     # HTTP client, crawler, reporter, payloads
├── ui/                        # Desktop GUI (CustomTkinter views)
├── webapp/                    # FastAPI backend + Celery + PostgreSQL
│   ├── main.py                # FastAPI application factory
│   ├── db.py                  # PostgreSQL persistence layer
│   ├── security.py            # JWT, password hashing
│   ├── routers/               # 16 API router modules
│   └── services/              # Scan orchestration, remediation engine
├── connector/                 # Remote connector agent
├── deploy/                    # Nginx config, deployment scripts
├── docs/                      # Architecture, security, threat model, roadmap
└── tests/                     # Hermetic test suite
```
---

<div align="center">

**HydraX** · © Deepesh Mahawar — All Rights Reserved · Built & maintained solely by the author.

*Unauthorized use is prohibited and will be acted upon.*

</div>
