# WASP — Website Security Posture Auditor

An automated, defensive cybersecurity auditor designed to evaluate the security configuration of web applications, assess compliance against the **OWASP Top 10 (2021)**, and generate actionable, copy-paste remediations alongside an **A+ to F** letter grade.

---

## 🛡️ Core Highlights

- **Editorial, High-Contrast Design System**: Built with Tailwind CSS, Space Grotesk, Inter, and JetBrains Mono. No gradients (except a signature top stripe), no glassmorphism, no emojis, and no pill badges.
- **Backend Defense-in-Depth**:
  - **SSRF Protection & IP Blacklisting**: Automatically resolves hostnames and blocks requests targeting private RFC1918 subnets, loopback addresses, and cloud instance metadata endpoints (`169.254.169.254`).
  - **Sliding-Window Rate Limiting**: In-memory rate limiter restricting scan bursts to protect backend availability.
  - **Strict HTTP Security Headers**: The API itself serves hardened response headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`).
  - **Memory-Bounded Streaming**: Sensitive path checks read only the initial 2KB chunks to prevent memory exhaustion from large archives.
- **Strict Ethical Consent Guard**: Programmatically refuses audits with `403 Forbidden` unless the user explicitly certifies ownership or written permission.
- **OWASP Top 10 (2021) Mapping**: Automatically maps every finding to its corresponding OWASP category.
- **A+ to F Grading Engine**: Computes a weighted 0–100 score and highlights the **Top 3 Priority Fixes** to implement first.
- **Local SQLite Persistence**: All scan snapshots are stored locally via async SQLAlchemy (`auditor.db`).

---

## 🔍 Scanner Modules

| Module | Scope & Methodology | Key Checks |
| :--- | :--- | :--- |
| **HTTP Security Headers** | RFC & Best-Practice Compliance | `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Evaluates missing, weak, or misconfigured directives. |
| **SSL / TLS Configuration** | Native Python `ssl` & `socket` Handshake | Certificate expiry date, days remaining, issuing Certificate Authority, negotiated protocol version (`TLSv1.2`, `TLSv1.3`), and detection of legacy protocols (`TLS 1.0` / `1.1`). |
| **Cookie Security Flags** | HTTP Cookie Hygiene | Evaluates `Set-Cookie` directives for missing `Secure`, `HttpOnly`, and `SameSite` (`Lax`/`Strict`) flags, or weak combinations like `SameSite=None` without `Secure`. |
| **Exposed Sensitive Files** | Safe Streamed Probing with Polite Delay | Non-intrusive rate-limited checks for `/.git/HEAD`, `/.env`, `/backup.zip`, `/admin`, `/phpinfo.php`, and `/robots.txt`. |
| **CORS Misconfiguration** | Origin Reflection & Credential Testing | Tests preflight and GET behaviors with synthetic origin payloads to detect arbitrary origin reflection with `Access-Control-Allow-Credentials: true` or invalid wildcard combinations. |
| **Network Port Scanner** | Socket-based TCP Scanner (No Nmap dependency) | Multi-threaded TCP connect scanner targeting top 20 ports (FTP, SSH, Telnet, SMTP, MySQL, Postgres, MSSQL, Redis, MongoDB, RDP, VNC) with service banner grabbing. |

---

## 🏗️ Architecture

```
                                  +-----------------------------+
                                  |   React UI (Vite + Tailwind)|
                                  |   Port 5173 / Localhost     |
                                  +--------------+--------------+
                                                 |
                                     JSON REST API Requests
                                 (URL + Consent Authorization)
                                                 v
+-----------------------------------------------------------------------------------------------+
| FastAPI Application (Port 8000)                                                              |
|                                                                                               |
|  +-----------------------------------------------------------------------------------------+  |
|  | Security Guards:                                                                        |  |
|  |  ├── Sliding Window Rate Limiter (15 requests/min per IP)                               |  |
|  |  ├── Consent Guard (403 Forbidden if consent is False)                                  |  |
|  |  └── SSRF Validator (Blocks 10.0.0.0/8, 192.168.0.0/16, 169.254.169.254, etc.)           |  |
|  +-----------------------------------------------------------------------------------------+  |
|                                                |                                              |
|                                                v                                              |
|  +-----------------------------------------------------------------------------------------+  |
|  | Scanner Engine Orchestrator                                                             |  |
|  |  ├── SecurityHeadersRule                                                                |  |
|  |  ├── TLSCheckRule (ssl / socket)                                                        |  |
|  |  ├── CookieSecurityRule                                                                 |  |
|  |  ├── ExposedFilesRule (streamed 2KB buffer, rate-limited)                               |  |
|  |  ├── CORSRule                                                                           |  |
|  |  └── PortScannerRule (multi-threaded TCP socket connect scanner)                        |  |
|  +-----------------------------------------------------------------------------------------+  |
|                                                |                                              |
|                                                v                                              |
|  +-----------------------------------------------------------------------------------------+  |
|  | Scoring & OWASP Mapping Engine                                                          |  |
|  |  ├── Severity Penalties (Critical: -25, High: -15, Med: -8, Low: -3)                    |  |
|  |  ├── Grade Assignment (A+ to F) & Top 3 Priority Remediations                           |  |
|  +-----------------------------------------------------------------------------------------+  |
|                                                |                                              |
|                                                v                                              |
|  +-----------------------------------------------------------------------------------------+  |
|  | SQLite Storage (`auditor.db` via SQLAlchemy async engine)                               |  |
|  +-----------------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------------+
```

---

## 📁 Repository Structure

```
WASP/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── dependencies.py       # FastAPI dependency providers
│   │   │   ├── rate_limiter.py       # Sliding-window rate limiter (15 req/min)
│   │   │   └── routes.py             # REST endpoints (POST /scan, GET /reports, GET /reports/{id})
│   │   ├── models/
│   │   │   ├── db_models.py          # SQLAlchemy ORM model for SQLite
│   │   │   └── schemas.py            # Pydantic models with ConfigDict
│   │   ├── scanner/
│   │   │   ├── constants.py          # Enums for Severity, FindingStatus, OWASP categories
│   │   │   ├── engine.py             # Core orchestrator with mandatory consent guard
│   │   │   ├── exceptions.py         # Custom exceptions (UnauthorizedScanError, etc.)
│   │   │   ├── scoring.py            # 0-100 score calculator, A-F grading, top 3 fixes
│   │   │   ├── security.py           # SSRF validator, URL sanitizer & IP blacklist
│   │   │   └── rules/                # Modular audit rules
│   │   │       ├── base.py           # Abstract BaseRule & structured Finding model
│   │   │       ├── headers.py        # HTTP security header evaluator
│   │   │       ├── tls.py            # SSL/TLS handshake & cert analyzer
│   │   │       ├── cookies.py        # Cookie flag analysis
│   │   │       ├── exposed_files.py  # Non-intrusive streamed sensitive path discovery
│   │   │       ├── cors.py           # CORS reflection & credential validator
│   │   │       └── port_scanner.py   # Socket-based TCP port scanner
│   │   ├── config.py                 # App settings, CORS, and security controls
│   │   ├── database.py               # Async SQLite database setup
│   │   └── main.py                   # FastAPI app, security middleware & error handlers
│   ├── tests/                        # Pytest suite with 22 unit tests
│   ├── requirements.txt              # Backend dependencies
│   └── .env.example                  # Example environment config
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.jsx            # Hexagon SVG logo, navigation & anchor links
│   │   │   ├── HeroSection.jsx       # Input form, authorization checkbox, sample card
│   │   │   ├── ChecksSection.jsx     # What it checks (01-06 grid)
│   │   │   ├── HowItWorksSection.jsx # 3-step process & sample finding card
│   │   │   ├── EthicsAndFooter.jsx   # Rules of engagement & black developer footer
│   │   │   ├── ResultsPage.jsx       # Detailed audit results & copyable fixes
│   │   │   ├── HistoryPage.jsx       # Stored SQLite reports browser
│   │   │   └── ScanningLoader.jsx    # Live check progress list
│   │   ├── services/
│   │   │   └── api.js                # Frontend API client
│   │   ├── App.jsx                   # Central state management & view routing
│   │   ├── index.css                 # Clean editorial Tailwind design system
│   │   └── main.jsx                  # React DOM root
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── .gitignore                        # Git exclusion rules
├── .env.example
└── README.md
```

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create virtual environment (if not already created)
python -m venv venv

# Activate virtual environment
# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Run full test suite (22 tests)
pytest tests -v

# Start FastAPI server
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`

### 3. Frontend Setup
```bash
# In a second terminal, navigate to frontend
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open your browser at `http://localhost:5173`

---

## 🧪 Safe Sample Targets for Testing

- `https://example.com` (Standard IANA test domain; tests missing headers like CSP/HSTS)
- `http://testphp.vulnweb.com` (Acunetix public testing lab; tests unencrypted HTTP and configuration issues)
- `http://localhost:3000` (Local sandbox targets like OWASP Juice Shop)

---

## ⚖️ Legal & Ethical Use Disclaimer

> [!CAUTION]
> **Authorized Testing Only**
> 
> WASP was built strictly for educational, defensive posture analysis, and authorized security assessments. 
> 
> Performing network port scanning or sensitive file probing against servers or networks without explicit, verifiable written permission from the owner violates computer crime laws, including the **Computer Fraud and Abuse Act (CFAA - 18 U.S.C. § 1030)** in the United States and equivalent legislation worldwide.
> 
> The scanner enforces a programmatic consent check and rejects unauthorized audit requests with `403 Forbidden`.

---

## 👨‍💻 Author & Connect

- **Author**: Hariharan T
- **LinkedIn**: [linkedin.com/in/hariharan044](https://www.linkedin.com/in/hariharan044/)
- **GitHub**: [github.com/Hariharan8080](https://github.com/Hariharan8080)
