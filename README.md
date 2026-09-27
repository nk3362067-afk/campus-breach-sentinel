# 🛡️ Campus Breach Sentinel

[![Live Demo](https://img.shields.io/badge/Live-Demo_Online-brightgreen?style=for-the-badge&logo=render)](https://campus-breach-sentinel.onrender.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**Campus Breach Sentinel** is an institutional cybersecurity intelligence and audit engine designed to identify exposed credentials, assess organizational leak perimeters, and promote cryptographic privacy safeguards.

🌐 **Live Deployment**: [campus-breach-sentinel.onrender.com](https://campus-breach-sentinel.onrender.com)

---

## 📌 Key Architectural Pillars

* **Zero-Knowledge Password Auditing:** Evaluates plain-text credentials by computing SHA-256 digests on the fly. Plain-text strings are never preserved or recorded in query logs.
* **Campus Domain Perimeter Scanner:** Aggregates and correlates leaks by institutional domain pattern (e.g., `@college.edu`) to discover compromised student and faculty identities.
* **Client-Side CSV Reporting:** Compiles leak incidents into downloadable, structured audit reports (`.csv`) for incident response teams.
* **Interactive Threat Analytics:** Built-in dashboard with real-time entropy estimation, platform breach counters, and structured remediation guidelines.

---

## 🛠️ System Architecture

```text
[ Browser Dashboard (Tailwind CSS) ]
               │
               ▼
[ FastAPI Server (Uvicorn Async Engine) ]
   ├── /api/metrics           ──> Live platform query totals
   ├── /api/check-email       ──> Filter identity exposure
   ├── /api/check-password    ──> SHA-256 cryptographic match
   └── /api/check-domain      ──> Domain wildcard extraction
               │
               ▼
   [ SQLite3 Relational Database Engine ]
      ├── breaches (email, source, leaked_info, risk)
      └── leaked_passwords (hash, times_seen)
