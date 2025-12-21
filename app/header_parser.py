"""
Email Header Parser for SOC Email Log

Extracts key fields from raw email headers for threat analysis.
This is what makes the analyst's job faster - auto-extraction of indicators.
"""

import re
from datetime import datetime
from email import message_from_string
from email.utils import parsedate_to_datetime


class EmailHeaderParser:
    """
    Parse email headers and extract threat-relevant fields.
    
    SOC analysts need quick access to:
    - Sender information (spoofing detection)
    - Mail server infrastructure (threat actor infrastructure)
    - Routing path (attack origin)
    - Authentication results (legitimacy checks)
    """
    
    @staticmethod
    def parse(raw_header):
        """
        Parse raw email header text and extract key fields.
        
        Args:
            raw_header: String containing email header
            
        Returns:
            Dict with extracted fields
        """
        if not raw_header or not raw_header.strip():
            return EmailHeaderParser._empty_result()
        
        try:
            # Parse using Python's email library
            msg = message_from_string(raw_header)
            
            result = {
                'from_address': EmailHeaderParser._extract_from(msg),
                'to_address': EmailHeaderParser._extract_to(msg),
                'subject': EmailHeaderParser._extract_subject(msg),
                'sender_domain': EmailHeaderParser._extract_sender_domain(msg),
                'sender_ip': EmailHeaderParser._extract_sender_ip(raw_header),
                'mail_server': EmailHeaderParser._extract_mail_server(msg),
                'smtp_sender': EmailHeaderParser._extract_smtp_sender(msg),
                'received_date': EmailHeaderParser._extract_date(msg),
                'authentication_results': EmailHeaderParser._extract_auth_results(msg),
                'return_path': EmailHeaderParser._extract_return_path(msg),
                'message_id': msg.get('Message-ID', ''),
                'raw_header': raw_header,
                'parsing_success': True,
                'suspicious_indicators': []
            }
            
            # Add suspicious indicators
            result['suspicious_indicators'] = EmailHeaderParser._detect_suspicious_patterns(result, msg)
            
            return result
            
        except Exception as e:
            return {
                **EmailHeaderParser._empty_result(),
                'parsing_success': False,
                'parsing_error': str(e)
            }
    
    @staticmethod
    def _empty_result():
        """Return empty result structure."""
        return {
            'from_address': '',
            'to_address': '',
            'subject': '',
            'sender_domain': '',
            'sender_ip': '',
            'mail_server': '',
            'smtp_sender': '',
            'received_date': None,
            'authentication_results': '',
            'return_path': '',
            'message_id': '',
            'raw_header': '',
            'parsing_success': False,
            'suspicious_indicators': []
        }
    
    @staticmethod
    def _extract_from(msg):
        """Extract From address."""
        from_header = msg.get('From', '')
        # Extract email from "Name <email@domain.com>" format
        match = re.search(r'<(.+?)>', from_header)
        if match:
            return match.group(1)
        # Try to find email pattern
        match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', from_header)
        return match.group(0) if match else from_header
    
    @staticmethod
    def _extract_to(msg):
        """Extract To address."""
        to_header = msg.get('To', '')
        match = re.search(r'<(.+?)>', to_header)
        if match:
            return match.group(1)
        match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', to_header)
        return match.group(0) if match else to_header
    
    @staticmethod
    def _extract_subject(msg):
        """Extract subject line."""
        return msg.get('Subject', '').strip()
    
    @staticmethod
    def _extract_sender_domain(msg):
        """Extract sender domain from From address."""
        from_addr = EmailHeaderParser._extract_from(msg)
        if '@' in from_addr:
            return from_addr.split('@')[-1].strip().lower()
        return ''
    
    @staticmethod
    def _extract_sender_ip(raw_header):
        """
        Extract sender IP from Received headers.
        Looks for the FIRST external IP (closest to actual sender).
        Supports both IPv4 and IPv6 addresses.
        """
        # Find all Received headers (they're in reverse chronological order)
        received_headers = re.findall(r'Received:.*?(?=\nReceived:|\n[A-Z]|\Z)', raw_header, re.DOTALL | re.IGNORECASE)
        
        # Check the LAST Received header (first hop from sender)
        if received_headers:
            last_received = received_headers[-1]
            
            # IPv6 patterns (check first - more specific)
            ipv6_patterns = [
                r'\[([0-9a-fA-F:]+::[0-9a-fA-F:]*)\]',  # [IPv6]
                r'\[([0-9a-fA-F]{1,4}:[0-9a-fA-F:]+)\]',  # [full IPv6]
                r'\(([0-9a-fA-F:]+::[0-9a-fA-F:]*)\)',  # (IPv6)
            ]
            
            for pattern in ipv6_patterns:
                matches = re.findall(pattern, last_received)
                for ip in matches:
                    if ':' in ip and len(ip) > 4:  # Basic IPv6 validation
                        return ip
            
            # IPv4 patterns
            ip_patterns = [
                r'from.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',  # [IP]
                r'from.*?\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)',  # (IP)
                r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'  # Any IP
            ]
            
            for pattern in ip_patterns:
                matches = re.findall(pattern, last_received)
                for ip in matches:
                    if EmailHeaderParser._is_public_ip(ip):
                        return ip
        
        return ''
    
    @staticmethod
    def _is_public_ip(ip):
        """Check if IP is public (not private/internal)."""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False
            
            # Check for private ranges
            if octets[0] == 10:
                return False
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return False
            if octets[0] == 192 and octets[1] == 168:
                return False
            if octets[0] == 127:  # Localhost
                return False
            if octets[0] == 0:  # Invalid
                return False
            
            return True
        except:
            return False
    
    @staticmethod
    def _extract_mail_server(msg):
        """Extract mail server hostname from Received headers."""
        received = msg.get_all('Received', [])
        if received:
            # Check multiple Received headers to find actual mail server
            # Skip internal servers (Gmail, etc.) and find external sender's server
            for received_header in received:
                # Look for "from hostname" pattern
                match = re.search(r'from\s+([a-zA-Z0-9][\w\-\.]+\.[a-zA-Z]{2,})', received_header, re.IGNORECASE)
                if match:
                    hostname = match.group(1)
                    # Skip localhost and generic internal names
                    if not hostname.startswith('localhost') and len(hostname) > 5:
                        return hostname
        return ''
    
    @staticmethod
    def _extract_smtp_sender(msg):
        """Extract SMTP envelope sender (Return-Path)."""
        return_path = msg.get('Return-Path', '')
        # Clean up <email@domain.com> format
        match = re.search(r'<(.+?)>', return_path)
        if match:
            return match.group(1)
        return return_path.strip()
    
    @staticmethod
    def _extract_date(msg):
        """Extract and parse received date."""
        date_header = msg.get('Date', '')
        try:
            return parsedate_to_datetime(date_header)
        except:
            return None
    
    @staticmethod
    def _extract_auth_results(msg):
        """Extract authentication results (SPF, DKIM, DMARC)."""
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            # Summarize key results
            spf = 'SPF: Pass' if 'spf=pass' in auth_results.lower() else 'SPF: Fail' if 'spf=fail' in auth_results.lower() else ''
            dkim = 'DKIM: Pass' if 'dkim=pass' in auth_results.lower() else 'DKIM: Fail' if 'dkim=fail' in auth_results.lower() else ''
            dmarc = 'DMARC: Pass' if 'dmarc=pass' in auth_results.lower() else 'DMARC: Fail' if 'dmarc=fail' in auth_results.lower() else ''
            
            results = [r for r in [spf, dkim, dmarc] if r]
            return ', '.join(results) if results else auth_results[:100]
        return ''
    
    @staticmethod
    def _extract_return_path(msg):
        """Extract Return-Path."""
        return msg.get('Return-Path', '').strip()
    
    @staticmethod
    def _detect_suspicious_patterns(result, msg):
        """
        Detect suspicious patterns in the email header.
        This helps analysts quickly spot red flags.
        """
        indicators = []
        
        # Check for mismatched From and Return-Path
        from_addr = result['from_address']
        return_path = result['smtp_sender']
        
        if from_addr and return_path and from_addr != return_path:
            from_domain = from_addr.split('@')[-1] if '@' in from_addr else ''
            return_domain = return_path.split('@')[-1] if '@' in return_path else ''
            
            if from_domain != return_domain:
                indicators.append({
                    'type': 'domain_mismatch',
                    'severity': 'High',
                    'description': f'From domain ({from_domain}) differs from Return-Path domain ({return_domain})',
                    'threat': 'Possible spoofing attempt'
                })
        
        # Check authentication failures
        auth = result.get('authentication_results', '').lower()
        if 'fail' in auth or 'none' in auth:
            indicators.append({
                'type': 'auth_failure',
                'severity': 'Medium',
                'description': 'Email authentication checks failed',
                'threat': 'Sender may not be legitimate'
            })
        
        # Check for suspicious subject keywords
        subject = result.get('subject', '').lower()
        phishing_keywords = ['urgent', 'verify', 'suspended', 'unusual activity', 'confirm', 'password']
        found_keywords = [kw for kw in phishing_keywords if kw in subject]
        
        if found_keywords:
            indicators.append({
                'type': 'suspicious_subject',
                'severity': 'Low',
                'description': f'Subject contains phishing keywords: {", ".join(found_keywords)}',
                'threat': 'Common social engineering tactic'
            })
        
        # Check for foreign sender IP (basic check)
        sender_ip = result.get('sender_ip', '')
        if sender_ip and not sender_ip.startswith(('209.', '208.', '192.', '10.')):
            # This is simplistic - in production you'd use geolocation
            indicators.append({
                'type': 'external_ip',
                'severity': 'Info',
                'description': f'Email originated from external IP: {sender_ip}',
                'threat': 'Verify sender legitimacy'
            })
        
        return indicators


# Example usage and testing
if __name__ == '__main__':
    # Test with a sample header
    sample_header = """From: "Security Team" <noreply@suspicious-domain.com>
To: victim@company.com
Subject: Urgent: Verify your account immediately
Date: Fri, 20 Dec 2024 10:30:00 +0000
Return-Path: <bounce@different-domain.net>
Message-ID: <abc123@mail.server.com>
Authentication-Results: spf=fail; dkim=none; dmarc=fail
Received: from mail.suspicious-domain.com ([203.0.113.42])
    by mx.company.com with SMTP id xyz789
    for <victim@company.com>; Fri, 20 Dec 2024 10:30:00 +0000"""

    parser = EmailHeaderParser()
    result = parser.parse(sample_header)
    
    print("=== Parsed Email Header ===")
    print(f"From: {result['from_address']}")
    print(f"Sender Domain: {result['sender_domain']}")
    print(f"Sender IP: {result['sender_ip']}")
    print(f"Mail Server: {result['mail_server']}")
    print(f"SMTP Sender: {result['smtp_sender']}")
    print(f"Subject: {result['subject']}")
    print(f"Authentication: {result['authentication_results']}")
    
    print("\n=== Suspicious Indicators ===")
    for indicator in result['suspicious_indicators']:
        print(f"[{indicator['severity']}] {indicator['description']}")