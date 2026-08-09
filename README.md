# DeepGuard 
**AI Powered Deep Packet Inspection SIEM**

---

## 1. Overview
DeepGuard is an enterprise-grade Security Information and Event Management (SIEM) system with deep packet inspection capabilities. It captures network traffic in real-time, analyzes it across multiple protocols (TCP, UDP, HTTP, DNS, TLS, SSH, ICMP), and leverages both signature-based rules (IDS) and Machine Learning models to detect anomalies and cyber threats such as DDoS, SQL Injection, and Command & Control (C2) beaconing. All detected threats are mapped to the MITRE ATT&CK framework and presented in a sleek, zero-trust SOC command center dashboard.

## 2. Architecture
The system follows a scalable microservices architecture:
- **Capture Engine**: Uses `scapy` to sniff packets from network interfaces or analyze uploaded `.pcap` files.
- **DPI & Session Tracker**: Parses layer 7 protocols and tracks flow statistics over time.
- **Detection Pipeline**:
  - **IDS Rules**: Pattern matching and behavioral checks.
  - **ML Predictor**: Random Forest + XGBoost models to classify anomalous flows.
  - **Classifier**: Enriches alerts with MITRE ATT&CK tactics, techniques, and severity.
- **Message Queue**: Redis Pub/Sub decoupling for high-performance WebSocket streaming.
- **Database**: PostgreSQL (for structured data) and Elasticsearch (for rapid log searching and aggregations).
- **Frontend**: A modern React (Vite) dashboard built for SOC analysts, featuring a live attack map, real-time threat feed, and PCAP intelligence reporting.

## 3. Features
- **Real-Time Packet Sniffing**: Live traffic monitoring directly from network interfaces.
- **Deep Packet Inspection (DPI)**: Detailed protocol hierarchy, payload extraction, and connection tracking.
- **AI/ML Threat Detection**: Intelligent identification of unknown attacks based on flow behavior.
- **MITRE ATT&CK Integration**: Automated threat mapping to MITRE techniques.
- **Zero-Trust Risk Scoring**: Dynamic risk scores assigned to IPs based on threat feed hits, anomalous volumes, and geo-risk.
- **PCAP Intelligence Reports**: Detailed forensic analysis and threat verdict of uploaded packet capture files.
- **Live SOC Dashboard**: Real-time attack feed, animated world map, glowing threat statistics, and interactive charts.
- **Automated Firewall Integration**: Auto-blocks critical threats.
- **Dockerized Deployment**: Fully containerized stack using `docker-compose`.

## 4. Screenshots
*(Add screenshots of your system here)*
- **SOC Overview Dashboard**: Live attack map and active threat feeds.
- **PCAP Analysis**: Threat verdict, risk indicators, and protocol pie charts.
- **Incident Timelines**: Correlated security incidents and flow history.

## 5. Installation

DeepGuard is fully containerized. To get started:

1. Clone the repository:
   ```bash
   git clone https://github.com/ayush001844/Deep-Packet-Inspection-SIEM.git
   cd Deep-Packet-Inspection-SIEM
   ```

2. Start the services using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
   *This will bring up the FastAPI Backend, React Frontend, PostgreSQL, Elasticsearch, and Redis.*

3. Access the interfaces:
   - **SOC Dashboard**: `http://localhost:5173` (or port mapped in your setup)
   - **API Documentation**: `http://localhost:8000/docs`
   - **Kibana (Optional)**: `http://localhost:5601`

*(Note: For local development without Docker, ensure Python 3.9+, Node.js, PostgreSQL, and Redis are installed locally).*

## 6. Demo
- Navigate to the **Overview** page to watch the live attack feed and world map update in real-time via WebSockets.
- Go to the **PCAP Analysis** page and upload `sample_traffic.pcap` or `ddos_attack.pcap` to see the PCAP Intelligence engine evaluate the file, assign a threat verdict, and list top talkers.

## 7. Future Work
- **Sigma and YARA integration**: Expanding signature matching for payloads and log events.
- **Distributed Sensors**: Deploying lightweight capture agents across multiple networks to feed centrally into DeepGuard.
- **Advanced Threat Hunting UI**: Adding Kibana-style drag-and-drop filtering to the dashboard.
- **Automated Reporting**: Export PDF reports for executive summaries of incidents.
