#  Email Header Analysis Guide

**A SOC analyst's guide to reading, extracting, and analyzing email headers for threat intelligence**

---

## Table of Contents
1. [Safe Header Extraction](#safe-header-extraction)
2. [Email Header Anatomy](#email-header-anatomy)
3. [Reading Headers Step-by-Step](#reading-headers-step-by-step)
4. [Key Fields for Threat Analysis](#key-fields-for-threat-analysis)
5. [Red Flags & Indicators](#red-flags--indicators)
6. [Practical Analysis Examples](#practical-analysis-examples)
7. [Analysis Workflow](#header-analysis-workflow)
8. [Pro Tips](#pro-tips)

---

##  Safe Header Extraction

### Why Headers Matter
Email headers contain the **forensic evidence** of an email's journey - where it came from, how it got to you, and whether it's legitimate. This is the data SOC analysts use to:
- Identify spoofing attempts
- Track threat actor infrastructure
- Verify email authenticity
- Build detection rules
- Correlate phishing campaigns

### Safe Extraction Methods

#### Gmail (Recommended - Safest)

**Method: Show Original**
1. Open the suspicious email (**don't click any links!**)
2. Click **⋮** (three dots) in top right corner
3. Click **"Show original"**
4. New tab opens with full headers in plain text
5. Click **"Copy to clipboard"** button at top
6. Paste into your SOC Email Log

**Why it's safe:**
-  Read-only view with no active content
-  No risk of executing malicious attachments
-  No link clicks or network requests
-  Pure text format only

---

#### Outlook Desktop

**Method 1: Properties Dialog (Preferred)**
1. Open email in Outlook
2. Click **File** → **Info** → **Properties**
3. Scroll to **"Internet headers"** text box at bottom
4. **Select all** (Ctrl+A) and **copy** (Ctrl+C)
5. Paste into your analysis tool

**Method 2: View Source**
1. Open email
2. Right-click the email
3. Select **"View Source"**
4. Copy all text

**Why it's safe:**
-  Viewing properties doesn't execute anything
-  No network requests initiated
-  Headers are static text data

---

#### Outlook Web (Office 365)

**Method:**
1. Open the email
2. Click **⋮** (three dots) at top
3. Select **"View"** → **"View message source"**
4. Copy all the text shown
5. Paste into your tool

**Why it's safe:**
-  Browser sandbox protection
-  Read-only interface
-  No downloads or executions

---

#### Proofpoint / Email Security Gateway

**Method 1: Download Original Message**
1. Find email in Proofpoint quarantine/logs
2. Look for **"Download"** or **"Release"** options
3. Click **"Download original message"** link
4. Downloads as `.eml` file
5. **Open with text editor** (Notepad++, VS Code, etc.)
   - **DO NOT** double-click to open in email client!
6. Copy headers (everything before first blank line)

**Method 2: View Message Source**
1. In Proofpoint interface, locate the message
2. Look for **"View Source"** or **"Message Details"**
3. Copy the raw message content

**Why it's safe:**
-  .eml files are text - safe to view in text editor
-  Don't open in email client (prevents execution)
-  Can analyze in isolated VM for extra safety

---

##  Email Header Anatomy

### Basic Structure

```
Return-Path: <sender@malicious.com>          ← SMTP envelope sender (where bounces go)
Delivered-To: you@company.com                ← Final recipient (your mailbox)
Received: from mail.server.com               ← Mail server in the path
    ([203.0.113.42])                         ← Sender IP address (critical!)
    by mx.google.com                         ← Receiving server
    Wed, 24 Dec 2025 17:46:15 +0000          ← Timestamp of this hop
From: "Friendly Name" <sender@domain.com>    ← Display sender (what you see)
To: you@company.com                          ← Display recipient
Subject: Urgent Account Action Required      ← Email subject line
Date: Wed, 24 Dec 2025 17:46:11 +0000        ← When email was sent
Message-ID: <unique-id@server.com>          ← Unique message identifier
Content-Type: text/html                      ← Email format
Authentication-Results: ...                   ← SPF/DKIM/DMARC results
```

---

##  Reading Headers Step-by-Step

### 1. Understanding "Received" Headers (Most Important!)

**Critical Concept:** Headers are added **bottom-to-top** as the email travels through servers. 

**Read them BACKWARDS to trace the email's path:**

```
Received: by mx.google.com                     ← Step 4 (END - your inbox)
    Wed, 24 Dec 2025 17:46:16 +0000
    
Received: from proofpoint.com                  ← Step 3 (security gateway)
    by mx.google.com
    Wed, 24 Dec 2025 17:46:15 +0000
    
Received: from mail.microsoft.com              ← Step 2 (Microsoft servers)
    by proofpoint.com
    Wed, 24 Dec 2025 17:46:12 +0000
    
Received: from [163.5.221.43] (attacker.com)   ← Step 1 (START - actual sender!)
    by mail.microsoft.com
    Wed, 24 Dec 2025 17:46:11 +0000
```

**Email Journey (read bottom to top):**
1. Sent from IP `163.5.221.43` at 17:46:11
2. Passed through Microsoft at 17:46:12 (1 sec later)
3. Scanned by Proofpoint at 17:46:15 (3 sec later)
4. Delivered to Gmail at 17:46:16 (1 sec later)

**Total travel time: 5 seconds**  (normal for email)

---

### 2. Extracting Sender IP

**The last (bottom) "Received" header shows the original sender:**

```
Received: from mail.attacker.com ([203.0.113.42])
    by mx.company.com
```

**Extract:** `203.0.113.42`

**IPv6 Example:**
```
Received: from mail.server.com ([2a01:111:f403:d405::3])
    by mx.company.com
```

**Extract:** `2a01:111:f403:d405::3`

**What to check:**
- Is the IP from the expected country?
- Is it residential (suspicious for business email)?
- Is it on any blocklists?
- Use VirusTotal or AbuseIPDB for reputation

---

### 3. Mail Server Identification

**Look in "Received" headers for server hostnames:**

```
Received: from mail-japaneastazolkn190130003.outbound.protection.outlook.com
```

**What this tells you:**
- `.outlook.com` = Microsoft infrastructure (legitimate)
- Long random hostname = typical for cloud services
- Check if domain matches claimed sender

**Suspicious example:**
```
From: security@microsoft.com
Received: from sketchy-server-123.tk
```
→ **RED FLAG!** Microsoft doesn't send from `.tk` domains

---

##  Key Fields for Threat Analysis

### Return-Path vs From Address

**The most important check for spoofing:**

```
Return-Path: <actual-sender@evilphisher.com>   ← Real SMTP sender
From: "Your Bank" <security@yourbank.com>      ← What you see (easily faked!)
```

** Legitimate email:**
```
Return-Path: <noreply@yourbank.com>
From: "Your Bank" <noreply@yourbank.com>
```
→ Match!  Domains align

**🚩 Phishing email:**
```
Return-Path: <x94hf@random-domain.tk>
From: "Your Bank" <security@yourbank.com>
```
→ **MISMATCH!** 🚨 This is spoofing!

**Why this matters:**
- `From:` header is what users see (easily spoofed)
- `Return-Path:` is the real SMTP sender (harder to fake)
- Legitimate services align these fields
- Phishers rarely bother to match them

---

### Authentication Results (SPF, DKIM, DMARC)

**Email authentication verifies the sender is who they claim to be:**

```
Authentication-Results: mx.google.com;
    spf=pass smtp.mailfrom=sender@company.com
    dkim=pass header.i=@company.com
    dmarc=pass header.from=company.com
```

#### SPF (Sender Policy Framework)
**What it checks:** Is this IP authorized to send for this domain?

- `spf=pass`  IP is authorized by domain owner
- `spf=fail`  IP is NOT authorized (likely spoofing!)
- `spf=softfail`  Questionable (domain policy allows but suspicious)
- `spf=none`  Domain has no SPF record

**Example:**
```
spf=fail smtp.mailfrom=phisher@gmail.com
```
→ Gmail didn't send this! Someone spoofed it.

---

#### DKIM (DomainKeys Identified Mail)
**What it checks:** Is the email cryptographically signed by the sending domain?

- `dkim=pass` ✅ Valid signature from domain
- `dkim=fail` 🚩 Invalid signature (tampered or forged)
- `dkim=none` ⚠️ No signature present

**Example:**
```
dkim=pass header.i=@company.com
```
→ Email was signed by company.com and hasn't been modified

---

#### DMARC (Domain-based Message Authentication)
**What it checks:** Does the email meet the domain owner's policy?

- `dmarc=pass` ✅ Passes domain policy
- `dmarc=fail` 🚩 Fails domain policy
- `dmarc=none` ⚠️ Domain has no DMARC policy

**Verdict:**
- **All pass** → Probably legitimate ✅
- **All fail** → Definitely suspicious 🚨
- **Mixed** → Investigate further ⚠️

---

### Message-ID

**Should match the sending domain:**

```
Message-ID: <abc123@company.com>
From: support@company.com
```
→ Good! ✅ Domains match

```
Message-ID: <xyz789@random-server.tk>
From: security@microsoft.com
```
→ **RED FLAG!** 🚩 Microsoft doesn't use `.tk` servers

---

## 🚩 Red Flags & Indicators

### 1. Mismatched Sender Information

**Spoofing Pattern:**
```
Return-Path: <hacker123@throwaway.tk>
From: "CEO John Smith" <ceo@yourcompany.com>
```

**What this means:**
- Email **displays** as from your CEO
- Actually **sent from** throwaway.tk
- Classic CEO fraud / BEC (Business Email Compromise)

**🚨 Always suspicious when Return-Path ≠ From domain**

---

### 2. Failed Authentication

**All authentications failing:**
```
Authentication-Results: mx.company.com;
    spf=fail
    dkim=fail
    dmarc=fail
```

**What this means:**
- IP not authorized to send for this domain
- No valid cryptographic signature
- Fails domain's security policy

**🚨 Triple fail = almost certainly malicious**

---

### 3. Suspicious Received Path

**Private IP in headers (impossible!):**
```
Received: from [192.168.1.1]
    by mx.company.com
```
→ **FAKE!** Private IPs can't be external senders

**Unidentified server:**
```
Received: from unknown [1.2.3.4]
```
→ Server has no reverse DNS (suspicious)

**Too many hops or weird routing:**
```
Received: from russia.com
Received: from china.net
Received: from brazil.org
    (for a simple US to US email?)
```
→ Unusual routing pattern may indicate compromised servers

---

### 4. Time Anomalies

**Time travel (email received before sent!):**
```
Date: Wed, 24 Dec 2025 17:46:11 +0000
Received: ... Wed, 24 Dec 2025 15:00:00 +0000
```
→ Email "received" 2 hours before it was "sent"? 🚩

**Timestamps should progress forward:**
```
Sent:      10:00:00  ✅
Hop 1:     10:00:02  ✅
Hop 2:     10:00:05  ✅
Delivered: 10:00:08  ✅
```

**Not:**
```
Sent:      10:00:00
Delivered: 09:55:00  🚩 Impossible!
```

---

### 5. Suspicious Domains

**Free/Disposable domains for "business" email:**
```
From: "Microsoft Security" <security@tempmail.tk>
```
→ Microsoft doesn't use .tk domains! 🚩

**Recently registered domains:**
```
From: urgent-verification@customer-service-bank-2024.info
```
→ Check domain age (WHOIS) - new domains are suspicious

**Domain name tricks:**
```
From: security@micr0soft.com  (zero instead of 'o')
From: support@paypa1.com      (number 1 instead of 'l')
From: alert@goog1e.com        (number 1 instead of 'l')
```
→ Typosquatting / lookalike domains

---

## 📚 Practical Analysis Examples

### Example 1: Obvious Phishing

```
Return-Path: <noreply@service-update-6483.tk>
From: "Microsoft Security Team" <security@microsoft.com>
Subject: Urgent: Verify Your Account
Date: Wed, 24 Dec 2025 10:00:00 +0000

Received: from [45.67.89.123] (unknown)
    by mx.company.com
    Wed, 24 Dec 2025 10:05:00 +0000
    
Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=noreply@service-update-6483.tk
    dkim=fail
    dmarc=fail header.from=microsoft.com
    
Message-ID: <random12345@service-update-6483.tk>
```

**Analysis:**

| Field | Value | Assessment |
|-------|-------|------------|
| Return-Path | .tk free domain | 🚩 Suspicious |
| From | microsoft.com | ✅ Looks legit |
| **Mismatch** | Return ≠ From | 🚨 **SPOOFING!** |
| SPF | fail | 🚩 Not authorized |
| DKIM | fail | 🚩 No signature |
| DMARC | fail | 🚩 Fails policy |
| Sender IP | Unknown/no rDNS | 🚩 Suspicious |
| Message-ID | .tk domain | 🚩 Doesn't match From |

**Verdict: 🚨 100% PHISHING**

**Why:**
- Return-Path uses free .tk domain
- Pretends to be from Microsoft
- All authentication fails
- Message-ID doesn't match claimed sender

---

### Example 2: Legitimate Email

```
Return-Path: <noreply@github.com>
From: "GitHub" <noreply@github.com>
Subject: Your pull request was merged
Date: Wed, 24 Dec 2025 10:00:00 +0000

Received: from mail-sor-f41.google.com ([209.85.220.41])
    by mx.company.com
    Wed, 24 Dec 2025 10:00:05 +0000
    
Received: from github.com (mail-lb-234.github.net [192.30.252.234])
    by mail-sor-f41.google.com
    Wed, 24 Dec 2025 10:00:02 +0000
    
Authentication-Results: mx.company.com;
    spf=pass smtp.mailfrom=noreply@github.com
    dkim=pass header.i=@github.com
    dmarc=pass header.from=github.com
    
Message-ID: <abc123@github.com>
```

**Analysis:**

| Field | Value | Assessment |
|-------|-------|------------|
| Return-Path | github.com | ✅ Legitimate |
| From | github.com | ✅ Matches |
| **Match** | Return = From | ✅ Aligned |
| SPF | pass | ✅ Authorized |
| DKIM | pass | ✅ Signed |
| DMARC | pass | ✅ Policy OK |
| Sender IP | GitHub network | ✅ Expected |
| Message-ID | github.com | ✅ Matches |

**Verdict: ✅ LEGITIMATE**

**Why:**
- Return-Path and From align
- All authentication passes
- Sent from GitHub's infrastructure
- Message-ID matches sending domain

---

### Example 3: Compromised Account

```
Return-Path: <colleague@company.com>
From: "Your Colleague" <colleague@company.com>
Subject: Urgent: Wire Transfer Needed
Date: Wed, 24 Dec 2025 15:00:00 +0000

Received: from [185.234.xxx.xxx] (russia-hosting.ru)
    by mx.company.com
    Wed, 24 Dec 2025 15:00:05 +0000
    
Authentication-Results: mx.company.com;
    spf=pass smtp.mailfrom=colleague@company.com
    dkim=pass header.i=@company.com
    dmarc=pass header.from=company.com
```

**Analysis:**

| Field | Value | Assessment |
|-------|-------|------------|
| Return-Path | company.com | ✅ Matches |
| From | company.com | ✅ Matches |
| SPF | pass | ✅ (but misleading) |
| DKIM | pass | ✅ (but misleading) |
| DMARC | pass | ✅ (but misleading) |
| **Sender IP** | **Russia** | 🚩🚩🚩 **SUSPICIOUS!** |
| Timing | Sent at 3 AM local | 🚩 Unusual |
| Content | Wire transfer | 🚩 High-risk action |

**Verdict: ⚠️ LIKELY COMPROMISED ACCOUNT**

**Why:**
- Authentication passes (it IS from the real account)
- But sent from unexpected location (Russia)
- Unusual time for employee to send email
- High-risk request (wire transfer)

**This is why you can't rely only on authentication!**

**Next steps:**
- Contact colleague via phone/Slack (not email!)
- Verify they actually sent this
- Likely their account was compromised

---

## 🔄 Header Analysis Workflow

**Standard SOC analyst process:**

### 1. Initial Triage
- [ ] Extract headers safely
- [ ] Identify sender (From field)
- [ ] Check subject for suspicious content
- [ ] Note date/time received

### 2. Authentication Check
- [ ] Compare Return-Path and From address
  - Match? ✅ Good sign
  - Mismatch? 🚩 Investigate further
- [ ] Check SPF result
  - Pass? ✅
  - Fail? 🚩 Likely spoofing
- [ ] Check DKIM result
  - Pass? ✅
  - Fail? 🚩 Unsigned or tampered
- [ ] Check DMARC result
  - Pass? ✅
  - Fail? 🚩 Violates policy

### 3. Infrastructure Analysis
- [ ] Extract sender IP from last Received header
- [ ] Check IP reputation (VirusTotal, AbuseIPDB)
- [ ] Verify geolocation makes sense
- [ ] Identify mail servers in path
- [ ] Check for suspicious routing

### 4. Pattern Detection
- [ ] Check Message-ID domain matches sender
- [ ] Look for time anomalies
- [ ] Verify mail server legitimacy
- [ ] Check for typosquatting in domains
- [ ] Look for unusual header artifacts

### 5. Verdict & Documentation
- [ ] Assign confidence level (Low/Medium/High threat)
- [ ] Document findings in SOC Email Log
- [ ] Extract IOCs for threat intel
- [ ] Create detection rules if applicable
- [ ] Escalate if needed

---

## 💡 Pro Tips

### 1. Return-Path is Your Truth Anchor
**Always check this first:**
- What users see: `From:` header
- What SMTP sees: `Return-Path:` header
- If they don't match → investigate immediately

### 2. Read Received Headers Bottom-to-Top
**Email journey:**
```
Bottom = Origin (attacker's system)
  ↓
Middle = Transit (mail servers)
  ↓
Top = Destination (your inbox)
```

### 3. Authentication Tells a Story
```
All pass → Probably legitimate (but verify context!)
All fail → Almost certainly malicious
Mixed → Needs investigation
```

### 4. Context Matters
**Even legitimate-looking emails can be threats:**
- Compromised accounts pass authentication
- Check sender IP location
- Verify timing makes sense
- Validate request via separate channel

### 5. Trust but Verify
**Don't blindly trust:**
- Green checkmarks in email clients
- Authentication passes
- Familiar sender names

**Always verify:**
- Sender infrastructure
- Email content matches sender
- Request makes sense in context

### 6. Build Your Threat Intel
**Track patterns:**
- Sender IPs used in campaigns
- Common phishing domains
- Mail server infrastructure
- Authentication patterns

**Use your SOC Email Log to:**
- Correlate related threats
- Identify campaign clusters
- Build detection rules
- Create threat reports

---

## 🎓 Practice Exercise

**Try this with your next suspicious email:**

1. **Extract headers** using the safe methods above
2. **Find these critical fields:**
   - Return-Path
   - From
   - Last Received header (sender IP)
   - Authentication-Results (SPF/DKIM/DMARC)
   - Message-ID

3. **Answer these questions:**
   - Do Return-Path and From match?
   - Does authentication pass or fail?
   - Where did the email originate (sender IP)?
   - Does the mail server make sense for the sender?
   - Are there any red flags?

4. **Make a verdict:**
   - Legitimate
   - Suspicious (investigate further)
   - Malicious (confirmed threat)

5. **Document in your SOC Email Log**
   - Paste headers for auto-extraction
   - Add your analysis notes
   - Track the threat

---

## 📖 Additional Resources

**Standards & RFCs:**
- RFC 5322: Internet Message Format
- RFC 7208: SPF
- RFC 6376: DKIM
- RFC 7489: DMARC

**Threat Intel Services:**
- VirusTotal: IP/domain reputation
- AbuseIPDB: IP reputation
- MXToolbox: Email diagnostics
- WHOIS: Domain registration info

**Practice:**
- Log every suspicious email you get
- Analyze headers before deleting
- Build your pattern recognition
- Document your findings

---

## 🎯 Key Takeaways

**Email headers are forensic evidence that reveal:**
1. **True sender** (not always what you see in From field)
2. **Email's journey** (every server it passed through)
3. **Authentication status** (legitimate or spoofed)
4. **Threat indicators** (suspicious IPs, domains, patterns)
5. **Campaign correlation** (infrastructure reuse, timing)

**Master these skills:**
- Safe header extraction
- Authentication verification (SPF/DKIM/DMARC)
- Infrastructure analysis (IPs, mail servers)
- Spoofing detection (Return-Path vs From)
- Pattern recognition (campaign indicators)

**Remember:**
- Headers don't lie (they can't be easily faked)
- Authentication isn't foolproof (compromised accounts pass)
- Context matters (verify unusual requests separately)
- Document everything (build your threat intelligence)

---

*Now you can read email headers like a SOC analyst!* 🔍

**Return to [README](README.md) | Next: [Malware Tracking Guide](MALWARE_TRACKING_GUIDE.md)**
