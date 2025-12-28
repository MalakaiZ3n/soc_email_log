# soc_email_log
logging suspicious emails for security operations analysis

# SOC Email Log - Phishing Threat Intelligence Platform

##  Mission
A practical threat intelligence platform for tracking, analyzing, and documenting phishing campaigns - designed to help learn a SOC analyst role for real-world threat hunting capabilities.


**Core SOC Analyst Skills:**
-  Incident documentation and tracking
-  Indicator of Compromise (IOC) extraction
-  Pattern detection and anomaly analysis
-  Threat intelligence enrichment
-  Detection logic creation
-  Stakeholder reporting

##  Features

### Current Capabilities
- **Email Threat Log**: Comprehensive tracking of suspicious emails with metadata
- **Automated IOC Extraction**: Automatically identifies domains, IPs, URLs, email addresses, and file hashes from email headers
- **Header Analysis**: Parse and analyze raw email headers to identify spoofing and infrastructure
- **Malware Tracking**: Track file hashes and VirusTotal scan results for malicious attachments
- **Full CRUD Operations**: Create, Read, Update, and Delete email logs with edit history
- **Threat Intelligence Enrichment**: Direct links to VirusTotal, AbuseIPDB for IOC reputation checks
- **Pattern Detection Engine**: Identifies phishing campaigns and attack clusters
- **Visual Dashboard**: Real-time threat metrics and trend analysis
- **Search & Analytics**: Query emails by domain, IP, sender with advanced analytics

### Threat Hunter Workflow
```
1. Extract email headers → 2. Parse & auto-extract IOCs → 3. Enrich with threat intel
                                                               ↓
6. Generate reports      ← 5. Create detections       ← 4. Analyze patterns
```

##  Email Header Analysis

### Safe Header Extraction

**Critical SOC Skill:** Understanding how to safely extract and analyze email headers without executing malicious content.

**Recommended Methods:**

**Gmail (Safest):**
1. Open suspicious email (**don't click links!**)
2. Click **⋮** (three dots) → **"Show original"**
3. Click **"Copy to clipboard"**
4. Paste into SOC Email Log

**Outlook Desktop:**
1. **File** → **Properties** → Scroll to **"Internet headers"**
2. Select all (Ctrl+A) and copy (Ctrl+C)
3. Paste into your analysis tool

**Outlook Web:**
1. Click **⋮** → **"View"** → **"View message source"**
2. Copy all text

**Proofpoint/Email Gateway:**
1. Download original message as `.eml` file
2. **Open with text editor** (NOT email client!)
3. Copy headers (everything before first blank line)

**Why these methods are safe:**
-  Read-only views with no active content
-  No risk of executing malicious attachments
-  No link clicks or network requests
-  Plain text only

---

### What the Parser Extracts

**Automatically identified from raw headers:**

```
✓ From/To addresses          ✓ Sender IP (IPv4 & IPv6)
✓ Subject line               ✓ Mail server infrastructure  
✓ Sender domain              ✓ SMTP envelope sender (Return-Path)
✓ Authentication results     ✓ Message routing path
✓ File hashes                ✓ All domains in header
```

**Example Header Parsing:**
```
Input: Raw email header (paste from "Show Original")
  ↓
Parser extracts:
  • From: phisher@sketchy.com
  • To: victim@company.com
  • Sender IP: 203.0.113.42
  • Mail Server: mail.sketchy.com
  • Return-Path: different@evil.com  ← SPOOFING DETECTED!
  • SPF: fail  ← Not authorized!
  • 10+ IOCs extracted automatically
```

---

### Red Flags Automatically Detected

**The system identifies these threat indicators:**

🚩 **Spoofing Detection**
```
Return-Path: <phisher@evil.com>
From: "Your Bank" <security@yourbank.com>
```
→ **Mismatch detected!** Email claims to be from bank but sent from evil.com

🚩 **Failed Authentication**
```
SPF: fail    ← IP not authorized for this domain
DKIM: fail   ← No valid signature
DMARC: fail  ← Fails domain policy
```
→ **Triple fail = almost certainly malicious**

🚩 **Suspicious Infrastructure**
- Unknown sender IPs
- Mail servers that don't match sender domain
- Private IPs in Received headers (impossible!)
- Unusual routing patterns

🚩 **Time Anomalies**
- Email "received" before it was "sent"
- Suspicious timezone patterns

---

### Understanding Key Header Fields

**Return-Path vs From (Critical for Spoofing Detection):**

** Legitimate Email:**
```
Return-Path: <noreply@company.com>
From: "Company Support" <noreply@company.com>
```
→ Domains match! 

** Phishing Email:**
```
Return-Path: <random123@throwaway.tk>
From: "Your Bank" <security@yourbank.com>
```
→ **SPOOFING!** Return-Path reveals real sender 

**Why this matters:**
- `From:` header is what users see (easily faked)
- `Return-Path:` is the real SMTP sender (harder to spoof)
- Legitimate services align these fields
- Phishers rarely bother to match them

---

**Authentication Results (SPF/DKIM/DMARC):**

These verify the sender is who they claim to be:

**SPF (Sender Policy Framework):**
- `spf=pass`  IP authorized to send for this domain
- `spf=fail`  IP NOT authorized (likely spoofing!)

**DKIM (DomainKeys Identified Mail):**
- `dkim=pass`  Valid cryptographic signature
- `dkim=fail`  Invalid/missing signature

**DMARC (Domain Message Authentication):**
- `dmarc=pass`  Meets domain security policy
- `dmarc=fail`  Violates domain policy

**Verdict Guide:**
- All pass → Probably legitimate (verify context!)
- All fail → Almost certainly malicious
- Mixed → Investigate further

---

**Sender IP & Mail Server:**

**What to check:**
- Is IP from expected country?
- Is it residential (suspicious for business email)?
- Is it on blocklists? (Check VirusTotal)
- Does mail server match sender domain?

**Example Analysis:**
```
From: security@microsoft.com
Sender IP: 185.xxx.xxx.xxx (Russia)
Mail Server: sketchy-host.tk
```
→ **Multiple red flags!** Microsoft doesn't use Russian IPs or .tk domains

---

### Reading "Received" Headers

**Critical Concept:** Headers are added **bottom-to-top** as email travels.

**Read them BACKWARDS to trace the path:**

```
Received: by mx.google.com              ← Step 4 (END - your inbox)
    Wed, 24 Dec 2025 17:46:16 +0000
    
Received: from proofpoint.com           ← Step 3 (security gateway)
    Wed, 24 Dec 2025 17:46:15 +0000
    
Received: from mail.microsoft.com       ← Step 2 (transit)
    Wed, 24 Dec 2025 17:46:12 +0000
    
Received: from [163.5.221.43] (evil.com) ← Step 1 (START - actual sender!)
    Wed, 24 Dec 2025 17:46:11 +0000
```

**Email Journey Example:**
1. Originated from IP `163.5.221.43` at 17:46:11
2. Passed through Microsoft at 17:46:12 (1 sec)
3. Scanned by Proofpoint at 17:46:15 (3 sec)
4. Delivered to your inbox at 17:46:16 (1 sec)

**Total travel time: 5 seconds  (normal)**

---

### Real Example: Phishing Email Analysis

**Header snippet:**
```
Return-Path: <noreply@service-update-6483.tk>
From: "Microsoft Security Team" <security@microsoft.com>
Subject: Urgent: Verify Your Account

Received: from [45.67.89.123] (unknown)
    
Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=noreply@service-update-6483.tk
    dkim=fail
    dmarc=fail header.from=microsoft.com
    
Message-ID: <random12345@service-update-6483.tk>
```

**Analysis:**

| Finding | Red Flag | Assessment |
|---------|----------|------------|
| Return-Path (.tk domain) | 🚩 | Free domain service |
| From (microsoft.com) | - | Looks legitimate |
| **Mismatch:** Return ≠ From | 🚩 | **SPOOFING!** |
| SPF fail | 🚩 | Not authorized |
| DKIM fail | 🚩 | No valid signature |
| DMARC fail | 🚩 | Fails policy |
| Unknown sender IP | 🚩 | No reverse DNS |
| Message-ID (.tk) | 🚩 | Doesn't match From |

**Verdict: 100% PHISHING**

---

###  Complete Header Analysis Guide

**Want to learn more?** Check out the comprehensive guide:

**[ Email Header Analysis Guide](HEADER_ANALYSIS_GUIDE.md)**

**Covers:**
- Detailed safe extraction methods for multiple email platforms
- Step-by-step header reading tutorial
- Complete authentication explanation (SPF/DKIM/DMARC)
- Infrastructure analysis techniques
- Multiple real-world phishing examples
- SOC analyst workflow and best practices
- Pro tips for threat hunting
- Practice exercises

---

##  Real-World Impact

**Platform Capabilities:**
-  **Auto-extracts 10-15+ IOCs per email** in seconds
-  **Tracks malware** via file hash correlation
-  **One-click VirusTotal lookups** for instant threat intel
-  **Progressive investigation** tracking via edit feature
-  **Campaign correlation** across multiple emails
-  **Analytics dashboard** for threat pattern visualization

**Demonstrates Enterprise SOC Skills:**
- Email threat intelligence analysis
- Header forensics and authentication verification
- IOC extraction automation
- Threat infrastructure mapping
- Campaign tracking and correlation
- Professional incident documentation

**Metrics from Analysis:**
-  Emails analyzed: [Your count]
-  Phishing campaigns identified: [Your count]
-  Unique IOCs extracted: [Your count]
-  Detection rules created: [Your count]

##  Technical Stack

- **Backend**: Python 3.13, Flask 3.1.0
- **Database**: SQLAlchemy ORM with SQLite (production-ready for PostgreSQL)
- **Email Parsing**: Custom RFC 5322 header parser with IPv4/IPv6 support
- **IOC Extraction**: Regex-based pattern matching engine
- **Frontend**: Modern responsive design with dark theme
- **Analysis**: Pattern detection, clustering algorithms
- **Threat Intel Integration**: VirusTotal, AbuseIPDB (direct links)

##  Project Structure

```
soc_email_log/
├── run.py                          # Flask application entry point
├── models.py                       # SQLAlchemy database models
├── threat_intel.py                 # IOC extraction engine
├── requirements.txt                # Production dependencies
├── requirements-full.txt           # All dependencies
├── requirements-core.txt           # Minimal dependencies
├── HEADER_ANALYSIS_GUIDE.md        #  Email header analysis tutorial
├── MALWARE_TRACKING_GUIDE.md       #  Malware analysis features
├── EDIT_FEATURE_GUIDE.md           #  Progressive investigation guide
├── app/
│   ├── __init__.py                 # Flask app factory
│   ├── routes.py                   # Web routes and controllers
│   ├── header_parser.py            # Email header parser (IPv4/IPv6)
│   └── templates/                  # Jinja2 HTML templates
│       ├── base.html               # Base template with navigation
│       ├── dashboard.html          # Threat overview dashboard
│       ├── log_email.html          # Email logging workflow
│       ├── edit_email.html         # Edit existing logs
│       ├── list_emails.html        # Email list view
│       ├── view_email.html         # Detailed email analysis
│       ├── stats.html              # Analytics and metrics
│       └── search_results.html     # Search results view
└── instance/
    └── phishing_logs.db            # SQLite database (auto-created)
```

##  Learning Journey

**Key Insights Discovered:**
1. Most phishing emails fail all three authentication checks (SPF/DKIM/DMARC)
2. Return-Path mismatch is the #1 indicator of email spoofing
3. Sender infrastructure reuse helps correlate phishing campaigns
4. IPv6 adoption in threat actor infrastructure is increasing

**Skills Developed:**
- **Threat Analysis**: Email header forensics, authentication verification (SPF/DKIM/DMARC)
- **Technical Skills**: Full-stack web development, database design, regex pattern matching
- **SOC Operations**: Incident documentation, threat intelligence enrichment, campaign correlation
- **Security Automation**: IOC extraction automation, progressive investigation workflows

**Real Findings:**
- Identified phishing campaigns using same sender infrastructure
- Tracked malware distribution via file hash correlation
- Documented patterns in spoofed sender domains
- Built detection logic from observed attack patterns

##  Roadmap

**Phase 1: Foundation**  Complete
- [x] Email log tracking with full CRUD
- [x] Advanced IOC extraction (domains, IPs, emails, hashes)
- [x] Database design with relationships
- [x] Email header parser with IPv6 support
- [x] Malware tracking (file hashes, VirusTotal)
- [x] Edit feature for progressive investigations

**Phase 2: Intelligence**  Current
- [x] VirusTotal integration (manual lookup links)
- [ ] Automated VirusTotal API integration
- [ ] AbuseIPDB API integration
- [ ] Pattern detection algorithms
- [ ] Campaign clustering
- [ ] Detection rule generation

**Phase 3: Automation**  Planned
- [ ] Automated email ingestion via IMAP
- [ ] Real-time alerting system
- [ ] SIEM integration (Splunk, QRadar)
- [ ] Bulk import from email security gateways
- [ ] CSV/JSON export for threat sharing

**Phase 4: Advanced Hunting**  Future
- [ ] Machine learning for anomaly detection
- [ ] Behavioral analysis engine
- [ ] Threat actor profiling
- [ ] YARA rule generation
- [ ] MISP threat feed integration

##  Philosophy

This project demonstrates that SOC analysis is about:
-  **Investigating anomalies** that don't fit patterns 
-  **Building detection logic** from real-world threats 
-  **Researching attack techniques** through hands-on analysis 
-  **Creating documentation** others can use 
-  **Solving puzzles** by connecting threat data points

**Not just theory - practical threat hunting in action.**

---

##  Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/[your-username]/soc_email_log
cd soc_email_log

# Install dependencies
pip install -r requirements-full.txt

# Alternative: Core dependencies only (if pandas issues)
pip install -r requirements-core.txt

# Run the application
python run.py

# Access the dashboard
# Open browser: http://localhost:5000
```

### First Steps

1. **Log your first email:**
   - Get raw headers: Gmail → ⋮ → "Show original" → Copy
   - Navigate to "Log Email"
   - Paste headers → Click "Parse Header"
   - Review auto-extracted IOCs
   - Add your analysis notes
   - Save

2. **Explore the platform:**
   - **Dashboard**: Overview of logged threats
   - **Analytics**: Threat patterns and metrics
   - **Search**: Find emails by domain, IP, sender
   - **Edit**: Update logs as investigations progress

3. **Track malware:**
   - Get file hash of suspicious attachment
   - Upload to VirusTotal for scan
   - Edit email log to add hash and VT results
   - Click "Search on VirusTotal" for instant lookup

### Example Workflow

```bash
# 1. Receive suspicious email
# 2. Extract headers safely (Show Original in Gmail)
# 3. Paste into SOC Email Log
# 4. System auto-extracts:
#    - 7 domains
#    - 2 IP addresses  
#    - 4 email addresses
#    - 1 file hash
# 5. Add analysis notes
# 6. Check VirusTotal for IOC reputation
# 7. Track investigation progress via Edit feature
# 8. Correlate with other emails via Search
```

##  Features in Detail

### Automated IOC Extraction
Automatically identifies and extracts:
- **Domains**: Sender domains, mail server hostnames, URL domains
- **IP Addresses**: IPv4 and IPv6 from Received headers
- **Email Addresses**: From, To, Return-Path, envelope senders
- **File Hashes**: MD5, SHA1, SHA256 from attachments

### Email Header Analysis
- Parse RFC 5322 format headers
- Extract sender IP (IPv4 and IPv6 support)
- Identify mail server infrastructure
- Verify SPF/DKIM/DMARC authentication
- Detect Return-Path vs From mismatches (spoofing)
- Track message routing path

### Malware Tracking
- Store file hashes of malicious attachments
- Record VirusTotal detection ratios
- One-click VirusTotal search from email details
- Track malware variants across campaigns

### Progressive Investigation
- Edit emails to add findings as investigations develop
- Track investigation timeline via updated_at timestamps
- Document progressive analysis in analyst notes
- Maintain complete audit trail

### Campaign Correlation
- Search by sender domain to find related emails
- Track infrastructure reuse across attacks
- Identify coordinated phishing campaigns
- Analyze threat actor patterns

##  Contributing

This is a personal learning project demonstrating SOC analyst capabilities. Feedback and suggestions are welcome!

##  License

MIT License - Feel free to learn from and adapt this project

##  About

Built to learn practical threat hunting skills for cybersecurity threat analysis. This platform showcases:

- Real-world threat intelligence workflows
- Practical email forensics capabilities
- Professional incident documentation
- Automation and tool development skills
- Understanding of attacker infrastructure and TTPs

**Goal**: Learn SOC Analyst and Threat Intelligence roles through hands-on threat hunting rather than just certifications.

---

##  Documentation

- **[ Email Header Analysis Guide](HEADER_ANALYSIS_GUIDE.md)** - Complete guide to reading and analyzing email headers
- **[ Malware Tracking Guide](MALWARE_TRACKING_GUIDE.md)** - File hash analysis and VirusTotal integration
- **[ Edit Feature Guide](EDIT_FEATURE_GUIDE.md)** - Progressive investigation workflows


---

*Fighting cybercrime one phishing email at a time* 