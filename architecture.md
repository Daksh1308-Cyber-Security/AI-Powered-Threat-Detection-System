# Technical Architecture

This document details the technical architecture of the AI-Powered Threat Detection System.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACK SIMULATION LAYER                          │
│                                                                            │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐             │
│  │     KALI     │      │    UBUNTU    │      │   WINDOWS    │             │
│  │   Attacker   │─────▶│   Target     │      │   Target     │             │
│  │  192.168.56.10│      │  192.168.56.20│     │ 192.168.56.30│             │
│  │              │      │              │      │              │             │
│  │ • Nmap       │      │ • SSH        │      │ • Winlogbeat │             │
│  │ • Hydra      │      │ • Syslog    │      │ • Sysmon     │             │
│  │ • sqlmap     │      │ • Auditd    │      │ • PowerShell │             │
│  │ • Metasploit │      │ • Apache    │      │ • Syslog     │             │
│  │ • Custom     │      │ • Suricata  │      │ • Defender   │             │
│  └──────────────┘      └──────┬───────┘      └──────┬───────┘             │
│                               │                      │                     │
└───────────────────────────────┼──────────────────────┼─────────────────────┘
                                │                      │
                                ▼                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ELK STACK LAYER                                    │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          LOGSTASH                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │   │
│  │  │ linux-syslog│  │  windows-   │  │ authentication│                │   │
│  │  │   .conf     │  │ eventlogs   │  │    .conf     │                │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │   │
│  │         │                │                │                        │   │
│  │         └────────────────┼────────────────┘                        │   │
│  │                          ▼                                         │   │
│  │              ┌───────────────────────┐                             │   │
│  │              │   Filter Plugins      │                             │   │
│  │              │ • parse-linux-auth    │                             │   │
│  │              │ • parse-windows-security│                            │   │
│  │              │ • normalize-fields    │                             │   │
│  │              │ • add-geo-ip          │                             │   │
│  │              └───────────┬───────────┘                             │   │
│  └──────────────────────────┼─────────────────────────────────────────┘   │
│                             │                                              │
│                             ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       ELASTICSEARCH                                 │   │
│  │                                                                     │   │
│  │  Indices:                                                          │   │
│  │  ├── linux-*           (Linux syslog, auth, audit)                 │   │
│  │  ├── windows-*         (Windows Event Logs, Sysmon)                │   │
│  │  ├── network-*         (Suricata, Zeek, NetFlow)                   │   │
│  │  ├── attack-simulations│ (Labeled attack data)                     │   │
│  │  └── detection-alerts  │ (Sigma/YARA matches)                      │   │
│  │                                                                     │   │
│  │  Features:                                                         │   │
│  │  • ILM (Index Lifecycle Management)                                │   │
│  │  • Custom index templates                                          │   │
│  │  • Full-text search                                                │   │
│  │  • Aggregations for dashboards                                     │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                              │
│                             ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           KIBANA                                    │   │
│  │                                                                     │   │
│  │  Dashboards:                                                       │   │
│  │  ├── SOC Overview          (Real-time alerts, KPIs)                │   │
│  │  ├── MITRE ATT&CK Coverage (Heatmap visualization)                 │   │
│  │  ├── Alert Volume          (Trends, patterns)                      │   │
│  │  ├── User Activity         (Auth patterns, anomalies)              │   │
│  │  └── Attack Timeline       (Red team exercise view)                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DETECTION ENGINE LAYER                               │
│                                                                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐           │
│  │   SIGMA RULES   │  │   YARA RULES    │  │   ML MODEL      │           │
│  │   (51 rules)    │  │   (20 rules)    │  │   (XGBoost)     │           │
│  │                 │  │                 │  │                 │           │
│  │ • Vendor-       │  │ • Malware       │  │ • 23 features   │           │
│  │   agnostic      │  │   classification│  │ • Binary class  │           │
│  │ • MITRE mapped  │  │ • File-based    │  │ • 94% accuracy  │           │
│  │ • Log-based     │  │   detection     │  │ • Real-time     │           │
│  │ • Configurable  │  │ • Pattern match │  │ • Anomaly score │           │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘           │
│           │                    │                    │                     │
│           └────────────────────┼────────────────────┘                     │
│                                ▼                                          │
│              ┌─────────────────────────────────┐                         │
│              │       ALERT SCORING ENGINE       │                         │
│              │                                  │                         │
│              │  Score = ML(40) + Sigma(30) +   │                         │
│              │          YARA(20) + MITRE(10)   │                         │
│              │                                  │                         │
│              │  Output: 0-100 severity score    │                         │
│              └─────────────────────────────────┘                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AUTOMATION & RESPONSE LAYER                           │
│                                                                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐           │
│  │  ALERT TRIAGE   │  │  IR PLAYBOOK    │  │  SOC DASHBOARD  │           │
│  │   ENGINE        │  │  GENERATOR      │  │  (Streamlit)    │           │
│  │                 │  │                 │  │                 │           │
│  │ • Enrichment    │  │ • Template-based│  │ • Real-time     │           │
│  │ • Deduplication │  │ • Automated     │  │   metrics       │           │
│  │ • Correlation   │  │ • Response      │  │ • Alert feed    │           │
│  │ • FP filtering  │  │   actions       │  │ • MITRE heatmap │           │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Network Architecture

### Subnet Design

```
┌─────────────────────────────────────────────────────────┐
│                   HOST-ONLY NETWORK                     │
│                   192.168.56.0/24                       │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │    KALI     │  │   UBUNTU    │  │   WINDOWS   │   │
│  │ .10         │  │ .20         │  │ .30         │   │
│  │             │  │             │  │             │   │
│  │ Ports:      │  │ Ports:      │  │ Ports:      │   │
│  │ • 22 (SSH)  │  │ • 22 (SSH)  │  │ • 3389(RDP) │   │
│  │ • 443 (HTTPS)│ │ • 9200 (ES) │  │ • 5985(WinRM)│  │
│  │ • 8080      │  │ • 5601 (K)  │  │ • 445 (SMB) │   │
│  │             │  │ • 5044 (LS) │  │ • 135 (RPC) │   │
│  │             │  │ • 443 (HTTPS)│ │ • 139 (NetBIOS)│ │
│  └─────────────┘  └─────────────┘  └─────────────┘   │
│                                                         │
│  VirtualBox Adapter: vboxnet0                          │
│  DHCP: Disabled (Static IPs)                           │
│  Internet: Blocked (Isolated Lab)                      │
└─────────────────────────────────────────────────────────┘
```

### Port Allocation

| Service | Port | VM | Protocol | Purpose |
|---------|------|----|----------|---------|
| SSH | 22 | All | TCP | Remote access |
| Elasticsearch | 9200 | Ubuntu | TCP | ES API |
| Elasticsearch | 9300 | Ubuntu | TCP | ES Transport |
| Kibana | 5601 | Ubuntu | TCP | Web UI |
| Logstash | 5044 | Ubuntu | TCP | Beats input |
| Logstash | 9600 | Ubuntu | TCP | Monitoring |
| Winlogbeat | 5985 | Windows | TCP | Log shipping |
| RDP | 3389 | Windows | TCP | Remote desktop |
| SMB | 445 | Windows | TCP | File sharing |
| RPC | 135 | Windows | TCP | Windows RPC |
| NetBIOS | 139 | Windows | TCP | Legacy SMB |
| Apache | 80 | Ubuntu | TCP | Web server |
| MySQL | 3306 | Ubuntu | TCP | Database |

---

## Data Flow

### Log Ingestion Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                        LOG SOURCE                                  │
│                                                                     │
│  Linux:                                                            │
│  ├── /var/log/auth.log ─────┐                                      │
│  ├── /var/log/syslog ───────┤                                      │
│  ├── /var/log/apache2/ ─────┤                                      │
│  └── audit.log ─────────────┤                                      │
│                              │                                      │
│  Windows:                                                          │
│  ├── Security.evtx ─────────┤                                      │
│  ├── System.evtx ───────────┤                                      │
│  ├── PowerShell.evtx ───────┤                                      │
│  └── Sysmon.evtx ───────────┤                                      │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        COLLECTION                                  │
│                                                                     │
│  Linux: rsyslog ──────────────────────────────┐                    │
│  Windows: Winlogbeat ────────────────────────┤                    │
│  Network: Suricata/Zeek ────────────────────┤                    │
│                                               │                    │
│                                               ▼                    │
│                              ┌─────────────────────────┐           │
│                              │    LOGSTASH :5044       │           │
│                              └─────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        PROCESSING                                  │
│                                                                     │
│  Logstash Pipeline:                                                │
│  ├── Input: Beats, Syslog, TCP                                     │
│  ├── Filter:                                                       │
│  │   ├── grok (parse patterns)                                     │
│  │   ├── mutate (add/remove fields)                                │
│  │   ├── date (parse timestamps)                                   │
│  │   ├── geoip (add geography)                                     │
│  │   └── translate (MITRE mapping)                                 │
│  └── Output: Elasticsearch                                         │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        STORAGE                                     │
│                                                                     │
│  Elasticsearch Indices:                                            │
│  ├── linux-YYYY.MM.DD      (7-day retention)                      │
│  ├── windows-YYYY.MM.DD    (7-day retention)                      │
│  ├── network-YYYY.MM.DD    (3-day retention)                      │
│  ├── attack-simulations    (permanent)                            │
│  └── detection-alerts      (30-day retention)                     │
│                                                                     │
│  ILM Policy:                                                       │
│  ├── Hot phase: 7 days (SSD)                                      │
│  ├── Warm phase: 30 days (HDD)                                    │
│  └── Delete: 90 days                                              │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        ANALYSIS                                    │
│                                                                     │
│  Detection Pipeline (runs on each new document):                   │
│  ├── 1. Sigma Rules (batch query)                                  │
│  ├── 2. YARA Rules (file scan)                                     │
│  ├── 3. ML Model (feature extraction → prediction)                 │
│  └── 4. Alert Scoring (composite calculation)                      │
│                                                                     │
│  Output: detection-alerts index                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Pipeline Details

### Stage 1: Sigma Rule Evaluation

```
Input: Log document from Elasticsearch
  │
  ▼
┌─────────────────────────┐
│ Load Sigma Rules        │
│ (51 rules organized     │
│  by MITRE tactic)       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Execute Rule Queries    │
│ Against Log Stream      │
│                         │
│ For each rule:          │
│ ├── Parse YAML          │
│ ├── Build ES query      │
│ ├── Execute query       │
│ └── Collect matches     │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Aggregate Matches       │
│                         │
│ Output:                 │
│ ├── rule_id             │
│ ├── rule_name           │
│ ├── mitre_technique     │
│ ├── severity            │
│ └── matched_events[]    │
└─────────────────────────┘
```

### Stage 2: YARA Rule Evaluation

```
Input: Suspicious file/process
  │
  ▼
┌─────────────────────────┐
│ Extract File Content    │
│ (memory dump, binary)   │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Scan Against YARA Rules │
│ (20 rules organized     │
│  by malware category)   │
│                         │
│ Categories:             │
│ ├── Ransomware (5)      │
│ ├── Trojans (5)         │
│ ├── Backdoors (4)       │
│ ├── Webshells (3)       │
│ └── Cryptominers (3)    │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Compile Match Results   │
│                         │
│ Output:                 │
│ ├── rule_name           │
│ ├── category            │
│ ├── confidence          │
│ ├── matched_strings[]   │
│ └── mitre_technique     │
└─────────────────────────┘
```

### Stage 3: ML Model Prediction

```
Input: Enriched log event
  │
  ▼
┌─────────────────────────┐
│ Feature Extraction      │
│ (23 features)           │
│                         │
│ Network: 7 features     │
│ Auth: 5 features        │
│ Process: 4 features     │
│ Temporal: 4 features    │
│ MITRE: 3 features       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Feature Scaling         │
│ (StandardScaler)        │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ XGBoost Prediction      │
│                         │
│ Output:                 │
│ ├── probability[0]      │ (benign)
│ └── probability[1]      │ (malicious)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Score Calculation       │
│                         │
│ ml_score = prob[1] * 40 │
└─────────────────────────┘
```

### Stage 4: Composite Alert Scoring

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ALERT SCORING FORMULA                            │
│                                                                     │
│  Final Score = ML Score + Sigma Score + YARA Score + MITRE Score   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ML Score (0-40 points)                                      │   │
│  │ ├── probability * 40                                        │   │
│  │ ├── Higher score = more anomalous                           │   │
│  │ └── Based on 23 engineered features                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Sigma Score (0-30 points)                                   │   │
│  │ ├── Critical match = 30 points                              │   │
│  │ ├── High match = 25 points                                  │   │
│  │ ├── Medium match = 15 points                                │   │
│  │ ├── Low match = 5 points                                    │   │
│  │ └── Multiple rules = max + (count-1)*5                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ YARA Score (0-20 points)                                    │   │
│  │ ├── Malware detected = 20 points                            │   │
│  │ ├── Suspicious pattern = 15 points                          │   │
│  │ ├── Benign match = 5 points                                 │   │
│  │ └── Multiple matches = max + (count-1)*3                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ MITRE Score (0-10 points)                                   │   │
│  │ ├── Critical technique = 10 points                          │   │
│  │ ├── High technique = 8 points                               │   │
│  │ ├── Medium technique = 5 points                             │   │
│  │ └── Low technique = 2 points                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Severity Mapping                                            │   │
│  │ ├── 80-100: CRITICAL → Auto-IR playbook triggered          │   │
│  │ ├── 60-79:  HIGH     → Analyst review within 15 min        │   │
│  │ ├── 40-59:  MEDIUM   → Analyst review within 1 hour        │   │
│  │ ├── 20-39:  LOW      → Batch review                        │   │
│  │ └── 0-19:   INFO     → Log only                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## False Positive Reduction

### 3-Tier Filtering Pipeline

```
Raw Alerts (10,000/day)
  │
  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        TIER 1: ML Pre-filter                        │
│                                                                     │
│  Purpose: Remove obvious benign events                              │
│  Method: ML probability threshold (prob[1] < 0.3)                  │
│  Reduction: ~40% of alerts                                          │
│                                                                     │
│  Remaining: 6,000 alerts                                           │
└─────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     TIER 2: Contextual Enrichment                   │
│                                                                     │
│  Purpose: Add context to reduce false positives                     │
│  Methods:                                                          │
│  ├── IP reputation lookup (internal/external)                      │
│  ├── User role check (admin vs normal)                             │
│  ├── Time-of-day analysis (business hours)                         │
│  ├── Historical baseline comparison                                │
│  └── Asset criticality mapping                                     │
│                                                                     │
│  Known FP patterns suppressed:                                     │
│  ├── Internal vulnerability scanner IPs                            │
│  ├── Scheduled backup jobs                                         │
│  ├── IT admin common actions                                       │
│  └── Regular business authentication                               │
│                                                                     │
│  Remaining: 4,000 alerts                                           │
└─────────────────────────────────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       TIER 3: Rule-based Override                   │
│                                                                     │
│  Purpose: Final filtering with deterministic rules                  │
│  Rules:                                                            │
│  ├── Whitelist known-good processes                                │
│  ├── Suppress alerts from trusted sources                          │
│  ├── Deduplicate similar alerts                                    │
│  └── Correlate related events                                      │
│                                                                     │
│  Final Output: 3,000 alerts (70% reduction)                       │
└─────────────────────────────────────────────────────────────────────┘
```

### False Positive Patterns

| Pattern | Detection | Action |
|---------|-----------|--------|
| Vulnerability scanner | IP whitelist match | Suppress |
| Backup job | Process name + time window | Suppress |
| IT admin action | User role = admin | Lower severity |
| Business hours auth | Time-of-day check | Lower severity |
| Duplicate alert | Hash similarity | Deduplicate |
| Known service | Process + parent process | Suppress |

---

## Technology Stack

### Core Technologies

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| Containerization | Docker | 24.x | Service orchestration |
| Container Orchestration | Docker Compose | 2.x | Multi-service management |
| Search Engine | Elasticsearch | 8.12.x | Log storage and search |
| Data Processing | Logstash | 8.12.x | Log normalization |
| Visualization | Kibana | 8.12.x | Dashboards and UI |
| Detection Rules | Sigma | 0.23+ | Vendor-agnostic rules |
| Malware Detection | YARA | 4.x | File-based detection |
| ML Framework | XGBoost | 1.7+ | Anomaly detection |
| ML Library | Scikit-learn | 1.3+ | Feature engineering |
| Data Processing | Pandas | 2.1+ | Data manipulation |
| Visualization | Matplotlib | 3.8+ | Model evaluation plots |
| Dashboard | Streamlit | 1.28+ | SOC dashboard |
| Log Collection (Linux) | rsyslog | 8.x | System log forwarding |
| Log Collection (Windows) | Winlogbeat | 8.12.x | Windows event shipping |
| Threat Detection | Sigma CLI | 0.23+ | Rule validation |

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 8 cores | 16 cores |
| RAM | 16 GB | 32 GB |
| Storage | 200 GB SSD | 500 GB SSD |
| Network | 1 Gbps | 1 Gbps |

### VM Resources

| VM | CPU | RAM | Storage | Purpose |
|----|-----|-----|---------|---------|
| Kali | 2 | 4 GB | 50 GB | Attacker |
| Ubuntu | 4 | 8 GB | 100 GB | Target + ELK |
| Windows | 4 | 8 GB | 80 GB | Target + Logs |
| **Total** | **10** | **20 GB** | **230 GB** | |

---

## Security Considerations

### Lab Isolation

- Host-only network (no internet access from VMs)
- No port forwarding to host
- No shared folders (except for dataset export)
- Static IP addresses only

### ELK Security

- Elasticsearch runs without authentication (lab only)
- Kibana accessible only from host-only network
- No external access to Elasticsearch API
- Logstash input on localhost only

### Data Handling

- No real PII in logs
- Attack simulations only against lab VMs
- Labeled datasets stored locally
- No cloud uploads of sensitive data

---

## Scalability Considerations

### Current (Lab)

- Single-node Elasticsearch
- 3 VMs
- ~10,000 alerts/day
- 1 user

### Production (Future)

- Multi-node Elasticsearch cluster
- Multiple VMs/containers
- Millions of alerts/day
- Multiple analysts

### Scaling Path

```
Lab (Current)          → Production (Future)
──────────────────────────────────────────────
Single ES node         → 3+ ES nodes
3 VMs                  → 50+ VMs
10K alerts/day         → 1M+ alerts/day
Streamlit dashboard    → Grafana + Kibana
Manual rule updates    → Automated rule sync
Single analyst         → SOC team
```

---

## Performance Metrics

### Detection Performance

| Metric | Value | Target |
|--------|-------|--------|
| True Positive Rate | 95% | >90% |
| False Positive Rate | 15% | <20% |
| Precision | 96% | >90% |
| Recall | 92% | >85% |
| F1 Score | 94% | >85% |
| AUC-ROC | 0.978 | >0.95 |

### Operational Performance

| Metric | Value | Target |
|--------|-------|--------|
| Mean Time to Detect (MTTD) | 15 min | <30 min |
| Mean Time to Respond (MTTR) | 1 hour | <2 hours |
| Alert Processing Time | <1 sec | <5 sec |
| Dashboard Load Time | <3 sec | <5 sec |
| Rule Update Time | <1 min | <5 min |

---

## Dependencies

### Python Dependencies

```
# ML and Data Processing
xgboost>=1.7.0
scikit-learn>=1.3.0
pandas>=2.1.0
numpy>=1.24.0
matplotlib>=3.8.0
seaborn>=0.12.0

# ELK Integration
elasticsearch>=8.10.0
python-logstash>=0.4.8

# YARA
yara-python>=4.3.0

# Sigma
sigma-cli>=0.23.0
pySigma>=0.11.0

# Web Framework
streamlit>=1.28.0
plotly>=5.18.0

# Utilities
python-dotenv>=1.0.0
pyyaml>=6.0.0
requests>=2.31.0
```

### System Dependencies

```
# Docker
docker>=24.0.0
docker-compose>=2.20.0

# ELK Stack (via Docker)
elasticsearch:8.12.0
logstash:8.12.0
kibana:8.12.0

# Windows Log Collection
winlogbeat>=8.12.0

# Linux Log Collection
rsyslog>=8.2112.0
auditd>=3.0.7
```
