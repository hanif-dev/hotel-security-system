# 🏨 Hotel Management System with Security Intelligence

> A full-stack hotel management system with built-in SOC-grade security monitoring,
> threat detection, and SIEM-compatible audit logging.

## 🔐 Security Features

### Threat Detection
- **Brute Force Detection** — auto-detects >5 failed logins/10min (MITRE T1110.001)
- **SQL Injection Prevention** — real-time pattern scanning on all inputs
- **XSS Protection** — regex-based detection in middleware layer
- **Account Enumeration Detection** — flags bulk auth endpoint requests (MITRE T1087)
- **Rapid Booking Anomaly** — detects automated/fraud booking patterns
- **IP Auto-blocking** — auto-blocks malicious IPs with configurable duration

### Audit Logging
- Comprehensive event logging (25+ event types) across all user actions
- Structured JSON logging compatible with Splunk, Elastic, QRadar
- MITRE ATT&CK technique mapping for each threat event
- CEF (Common Event Format) export for ArcSight/QRadar ingestion
- Correlation IDs for request tracing across distributed components

### Security Dashboard
- Real-time alert monitoring with 30-second auto-refresh
- Event timeline visualization (24h)
- Severity distribution analysis (7d)
- Top suspicious IP ranking
- Alert triage interface with MITRE mapping

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Django 4.2 + Django REST Framework |
| Frontend | Next.js 14 + TypeScript + Tailwind CSS |
| Database | PostgreSQL 15 |
| Auth | JWT (SimpleJWT) |
| Charts | Recharts |

## 🚀 Quick Start (GitHub Codespaces)

1. Fork this repository
2. Click **Code > Codespaces > Create codespace**
3. Wait for environment setup (~2 min)
4. In terminal: `cd backend && python manage.py migrate && python manage.py createsuperuser`
5. Start backend: `python manage.py runserver 0.0.0.0:8000`
6. In new terminal: `cd frontend && npm run dev`
7. Access: Frontend on port 3000, API on port 8000

## 📊 Security Architecture