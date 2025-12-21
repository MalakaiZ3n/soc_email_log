# soc_email_log
logging suspicious emails for security operations analysis

# SOC Email Log - Phishing Threat Intelligence Platform

##  Mission
A practical threat intelligence platform for tracking, analyzing, and documenting phishing campaigns - built by an aspiring SOC analyst to demonstrate real-world threat hunting capabilities.


**Core SOC Analyst:**
-  Incident documentation and tracking
-  Indicator of Compromise (IOC) extraction
-  Pattern detection and anomaly analysis
-  Threat intelligence enrichment
-  Detection logic creation
-  Stakeholder reporting

##  Features

### Current Capabilities
- **Email Threat Log**: Comprehensive tracking of suspicious emails with metadata
- **Automated IOC Extraction**: Automatically identifies domains, IPs, URLs, and file hashes
- **Threat Intelligence Enrichment**: Integrates with VirusTotal, AbuseIPDB, and other feeds
- **Pattern Detection Engine**: Identifies phishing campaigns and attack clusters
- **Detection Rules**: Creates reusable detection logic from analyzed threats
- **Visual Dashboard**: Real-time threat metrics and trend analysis

### Threat Hunter Workflow
```
1. Log suspicious email → 2. Extract IOCs → 3. Enrich with threat intel
                                                         ↓
6. Generate reports    ← 5. Create detections  ← 4. Analyze patterns
```

##  Real-World Impact

**Metrics from my analysis:**
-  Emails analyzed: [Your count]
-  Phishing campaigns identified: [Your count]
-  Unique IOCs extracted: [Your count]
-  Detection rules created: [Your count]

##  Technical Stack

- **Backend**: Python 3.x, Flask
- **Database**: SQLite (easily migrates to PostgreSQL)
- **Analysis**: Pandas, NumPy
- **Visualization**: Plotly, Chart.js
- **Threat Intel APIs**: VirusTotal, AbuseIPDB, URLScan.io
- **Pattern Detection**: Custom algorithms + ML clustering

##  Project Structure

```
soc_email_log/
├── run.py                          # Start the web server
├── models.py                       # Database models
├── routes.py                       # Web routes/views
├── requirements.txt                # Python dependencies
├── threat_intel.py                 # IOC extraction engine
├── pattern_detection.py            # Anomaly detection
├── import_from_sheets.py           # Data import script
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── header_parser.py            # Email header parser
│   └── templates/                  # HTML templates
│       ├── base.html
│       ├── dashboard.html
│       ├── log_email.html
│       ├── list_emails.html
│       ├── view_email.html
│       ├── stats.html
│       └── search_results.html
└── phishing_logs.db               # SQLite database (created automatically)
```

##  Learning Journey

**Key Insights Discovered:**
1. [Pattern you found - e.g., "70% of phishing attacks target specific domains"]
2. [Detection technique - e.g., "Sender domain age is a strong indicator"]
3. [Campaign insight - e.g., "Identified 3 distinct threat actor patterns"]

**Skills Developed:**
- Threat intelligence analysis
- Security automation with Python
- API integration for enrichment
- Documentation for incident response
- Pattern recognition in attack data

##  Roadmap

**Phase 1: Foundation** 
- [x] Email log tracking
- [x] Basic IOC extraction
- [x] Database design

**Phase 2: Intelligence** (Current)
- [ ] Threat intel API integration
- [ ] Pattern detection algorithms
- [ ] Campaign clustering

**Phase 3: Automation**
- [ ] Automated email ingestion
- [ ] Real-time alerting
- [ ] SIEM integration

**Phase 4: Advanced Hunting**
- [ ] Machine learning for anomaly detection
- [ ] Behavioral analysis
- [ ] Threat actor profiling


This project is meant to:
- **Investigate anomalies** that don't fit patterns 
- **Build detection logic** from real-world threats 
- **Research attack techniques** through hands-on analysis 
- **Create documentation** others can use 
- **Solve puzzles** by connecting threat data 

---

##  Usage

```bash
# Setup
git clone https://github.com/[your-username]/soc_email_log
cd soc_email_log
pip install -r requirements.txt

# Import your existing phishing data
python data/import_from_sheets.py

# Run the application
python run.py

# Access dashboard
http://localhost:5000
```
