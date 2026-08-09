# DeepGuard 
**AI-Powered Deep Packet Inspection SIEM**

---

## 1. Overview
DeepGuard is an enterprise-grade Security Information and Event Management (SIEM) system with deep packet inspection capabilities. It captures network traffic in real-time, analyzes it across multiple protocols (TCP, UDP, HTTP, DNS, TLS, SSH, ICMP), and leverages both signature-based rules (IDS) and Machine Learning models to detect anomalies and cyber threats such as DDoS, SQL Injection, and Command & Control (C2) beaconing. All detected threats are mapped to the MITRE ATT&CK framework and presented in a sleek, zero-trust SOC command center dashboard.

## 2. Architecture

```
                         ┌─────────────────┐
                         │     Network      │
                         │   (Interface)    │
                         └────────┬────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │    Packet Capture       │
                     │   (Scapy / PCAP)        │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │    DPI Engine           │
                     │  (Protocol Parser +     │
                     │   Session Tracker)      │
                     └────────────┬────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
     ┌─────────────────┐ ┌──────────────┐ ┌────────────────────┐
     │   IDS Engine     │ │  ML Models   │ │  Threat Intel      │
     │  (Sigma/YARA)    │ │  (XGBoost +  │ │  (Feeds + IOC)     │
     │                  │ │  RandomForest│ │                    │
     └────────┬────────┘ └──────┬───────┘ └─────────┬──────────┘
              │                  │                   │
              └──────────────────┼───────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Alert Classifier        │
                    │  + MITRE ATT&CK Mapping  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Zero-Trust Risk Engine   │
                    │  (Per-IP scoring)         │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │                          │
                    ▼                          ▼
       ┌──────────────────────┐  ┌──────────────────────┐
       │  Automated Response   │  │  Incident Manager    │
       │  Engine (Upgrade 6)   │  │  (Correlation)       │
       │  • Block IP           │  │                      │
       │  • Isolate Host       │  └───────────┬──────────┘
       │  • Disable Account    │              │
       │  • Create Incident    │              │
       └──────────────────────┘              │
                                              ▼
                              ┌───────────────────────────┐
                              │     SOC Dashboard          │
                              │  (React + Vite)            │
                              │  • Live Attack Map         │
                              │  • MITRE ATT&CK Navigator  │
                              │  • Threat Feed              │
                              │  • PCAP Intelligence        │
                              └───────────────────────────┘
```

### Data Flow
```
Packets → Sniffer → DPI Parser → Session Tracker → IDS/ML → Classifier → Risk Scorer → Response Engine
                                                          ↓                                    ↓
                                                   PostgreSQL + Elasticsearch          Firewall + Incidents
                                                          ↓
                                                    Redis Pub/Sub → WebSocket → Dashboard
```

## 3. Features

### Core Detection
- **Real-Time Packet Sniffing**: Live traffic monitoring directly from network interfaces
- **Deep Packet Inspection (DPI)**: Detailed protocol hierarchy, payload extraction, and connection tracking across 15+ protocols
- **AI/ML Threat Detection**: Intelligent identification of unknown attacks using XGBoost + Random Forest ensemble models
- **Intrusion Detection System (IDS)**: Pattern matching and behavioral detection with CVSS scoring
- **Sigma & YARA Rules**: Signature-based detection for payloads and log events

### Threat Intelligence
- **MITRE ATT&CK Integration**: Automated threat mapping to MITRE techniques and tactics
- **MITRE ATT&CK Navigator** *(Upgrade 7)*: Full 14-tactic matrix heatmap with detection coverage visualization
- **Zero-Trust Risk Scoring**: Dynamic risk scores per IP based on 6 weighted factors
- **Threat Feeds**: Real-time IOC feeds with automatic updates

### Response & Containment
- **Automated Response Engine** *(Upgrade 6)*: Risk-based auto-response with:
  - IP blocking via platform firewall (iptables/PF/Windows)
  - Host isolation (VLAN quarantine flagging)
  - Account disable requests
  - Auto-incident creation and analyst notification
  - Configurable thresholds and per-classification playbooks
  - Full audit trail with reversal support
- **Automated Firewall Integration**: Auto-blocks critical threats with cross-platform support

### Dashboard & Reporting
- **Live SOC Dashboard**: Real-time attack feed, animated world map, interactive charts
- **PCAP Intelligence Reports**: Detailed forensic analysis and threat verdict of uploaded packet captures
- **Incident Timelines**: Correlated security incidents with attack stage reconstruction
- **PDF Report Generation**: Exportable executive-summary incident reports
- **AI Security Assistant**: LLM-powered alert explanation and remediation recommendations

### Security Hardening *(Upgrade 8)*
- **JWT Refresh Tokens**: Rotating refresh tokens with reuse detection
- **API Key Authentication**: Programmatic access via `X-API-Key` header
- **Rate Limiting**: Per-endpoint sliding-window rate limiter (e.g., 5 login attempts/min)
- **Security Headers**: X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy
- **Non-Root Containers**: All Docker containers run as non-root users
- **Secrets Management**: Environment variable-based configuration via `.env`
- **Resource Limits**: Memory and CPU limits on all containers

## 4. Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend API | FastAPI (Python 3.10+) |
| Frontend | React + Vite |
| Database | PostgreSQL 15 |
| Search | Elasticsearch 8.11 |
| Message Queue | Redis 7 (Pub/Sub + Streams) |
| ML Models | scikit-learn + XGBoost |
| AI Assistant | LangChain + OpenAI |
| Packet Capture | Scapy |
| Containerization | Docker + Docker Compose |

## 5. API Reference

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/health` | Health check | No |
| `POST` | `/api/auth/login` | Login (JWT) | No |
| `POST` | `/api/auth/refresh` | Refresh token rotation | No |
| `POST` | `/api/auth/api-keys` | Create API key | Admin |
| `GET` | `/api/packets` | Query captured packets | JWT |
| `GET` | `/api/alerts` | List security alerts | JWT |
| `GET` | `/api/incidents` | List incidents | JWT |
| `POST` | `/api/pcap/upload` | Upload & analyze PCAP | JWT |
| `GET` | `/api/risk/scores` | Zero-Trust risk scores | JWT |
| `GET` | `/api/mitre/matrix` | ATT&CK matrix heatmap | JWT |
| `GET` | `/api/mitre/coverage` | Per-tactic coverage stats | JWT |
| `GET` | `/api/response/actions` | Recent auto-response actions | JWT |
| `POST` | `/api/response/config` | Update response engine config | Admin |
| `GET` | `/api/firewall/blocked` | List blocked IPs | JWT |
| `GET` | `/api/network/graph` | Network topology graph | JWT |
| `GET` | `/api/ml/status` | ML model status | JWT |
| `POST` | `/api/ai/explain` | AI alert explanation | JWT |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `ws://host:8000/ws/packets` | Real-time packet stream |
| `ws://host:8000/ws/alerts` | Live classified alert feed |

## 6. Installation

### Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/ayush001844/Deep-Packet-Inspection-SIEM.git
   cd Deep-Packet-Inspection-SIEM
   ```

2. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env to set your secrets (JWT key, DB password, etc.)
   ```

3. Start all services:
   ```bash
   docker-compose up --build -d
   ```
   This starts: FastAPI Backend, React Frontend, PostgreSQL, Elasticsearch, Redis, Kibana.

4. Access the interfaces:
   - **SOC Dashboard**: `http://localhost` (port 80)
   - **API Documentation**: `http://localhost:8000/docs`
   - **Kibana**: `http://localhost:5601`

### Local Development

Prerequisites: Python 3.10+, Node.js 20+, PostgreSQL 15, Redis 7

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd dashboard
npm install --legacy-peer-deps
npm run dev
```

## 7. Configuration

All configuration is managed through environment variables. See `.env.example` for a complete reference.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/soc` | PostgreSQL connection string |
| `JWT_SECRET_KEY` | *(insecure default)* | JWT signing key — **change in production** |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | Elasticsearch connection |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection |
| `RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `OPENAI_API_KEY` | *(empty)* | OpenAI API key for AI assistant |
| `SSL_CERTFILE` | *(empty)* | TLS certificate path for HTTPS |
| `SSL_KEYFILE` | *(empty)* | TLS private key path for HTTPS |

## 8. Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test suites
python -m pytest tests/test_detection.py -v   # Detection + MITRE + Response Engine
python -m pytest tests/test_risk.py -v        # Risk scoring engine
python -m pytest tests/test_api.py -v         # REST API + auth + modules
python -m pytest tests/test_capture.py -v     # Packet capture + PCAP analyzer
```

Test coverage:
- **test_detection.py**: AlertClassifier, IDS rules, MITRE mapping, MITRE Navigator, Response Engine
- **test_risk.py**: Risk scoring arithmetic, risk levels, geo-risk, sorting, entry structure
- **test_api.py**: Health endpoint, firewall, response engine, MITRE navigator, rate limiter, auth module
- **test_capture.py**: Sniffer lifecycle, PCAP analysis, threat summary structure

## 9. Security Notes

- **Default Credentials**: `admin/admin` and `analyst/analyst` — change immediately in production
- **JWT Secret**: Set `JWT_SECRET_KEY` to a strong random string in `.env`
- **Database**: Change `POSTGRES_PASSWORD` from the default
- **HTTPS**: Configure `SSL_CERTFILE` and `SSL_KEYFILE` for production TLS
- **Rate Limiting**: Enabled by default; configure limits in `backend/rate_limiter.py`
- **API Keys**: Use `POST /api/auth/api-keys` to create keys for programmatic access

## 10. Demo
- Navigate to the **Overview** page to watch the live attack feed and world map update in real-time via WebSockets
- Go to the **PCAP Analysis** page and upload `sample_traffic.pcap` or `ddos_attack.pcap` to see the PCAP Intelligence engine evaluate the file
- Visit the **ATT&CK Matrix** page to see the MITRE heatmap showing detected techniques across all 14 tactics
- Check **Settings** to configure the Automated Response Engine thresholds

## 11. Project Structure

```
Deep-Packet-Inspection-SIEM/
├── backend/
│   ├── ai/                    # LLM-powered security assistant
│   ├── capture/               # Scapy sniffer + PCAP analyzer
│   ├── db/                    # PostgreSQL + Elasticsearch persistence
│   ├── detection/             # IDS, classifier, risk scoring, MITRE, incidents
│   │   ├── mitre.py           # MITRE technique-tactic mapping
│   │   ├── mitre_navigator.py # Full ATT&CK matrix heatmap (Upgrade 7)
│   │   ├── risk_scoring.py    # Zero-Trust per-IP scoring
│   │   └── ...
│   ├── dpi/                   # Protocol parser + session tracker
│   ├── firewall/              # Cross-platform firewall (iptables/PF/Windows)
│   ├── ml/                    # XGBoost + RandomForest models
│   ├── mq/                    # Redis Pub/Sub + Streams
│   ├── reporting/             # PDF report generation
│   ├── response/              # Automated Response Engine (Upgrade 6)
│   │   └── response_engine.py # Block IP, isolate host, disable account, create incident
│   ├── threat/                # Threat feeds + CVSS scoring
│   ├── workers/               # Background detection workers
│   ├── auth.py                # JWT + refresh tokens + API keys (Upgrade 8)
│   ├── rate_limiter.py        # Sliding-window rate limiter (Upgrade 8)
│   ├── main.py                # FastAPI application entry point
│   ├── Dockerfile             # Non-root, multi-stage build (Upgrade 8)
│   └── requirements.txt
├── dashboard/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── MitreNavigator.jsx  # ATT&CK matrix heatmap (Upgrade 7)
│   │   │   └── ...
│   │   ├── components/
│   │   └── index.css          # Design system
│   ├── Dockerfile             # Non-root nginx (Upgrade 8)
│   └── nginx.conf
├── tests/
│   ├── conftest.py            # Shared fixtures + DB mocking
│   ├── test_detection.py      # Detection + MITRE + Response Engine
│   ├── test_risk.py           # Risk scoring
│   ├── test_api.py            # REST API + auth + modules
│   └── test_capture.py        # Capture + PCAP analysis
├── docker-compose.yml         # Hardened with secrets + resource limits (Upgrade 8)
├── .env.example               # Environment variable template (Upgrade 8)
└── README.md
```

## 12. Future Work
- **Distributed Sensors**: Lightweight capture agents feeding centrally into DeepGuard
- **Advanced Threat Hunting UI**: Kibana-style drag-and-drop filtering
- **SOAR Integration**: Full Security Orchestration, Automation and Response playbooks
- **Active Directory Integration**: Real account disable/enable via LDAP
