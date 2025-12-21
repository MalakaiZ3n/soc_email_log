"""
Threat Intelligence Engine for SOC Email Log

This module handles the core threat hunting functions:
1. Automated IOC extraction from email data
2. Threat intelligence enrichment via external APIs
3. Reputation scoring and context building

Demonstrates: Pattern recognition, API integration, security automation
"""

import re
import requests
import hashlib
from datetime import datetime
from urllib.parse import urlparse
import time


class IOCExtractor:
    """
    Automatically extracts Indicators of Compromise (IOCs) from email data.
    This is a fundamental SOC analyst skill - identifying threat indicators.
    """
    
    # Regex patterns for common IOC types
    PATTERNS = {
        'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }
    
    # Known legitimate domains to exclude (reduce false positives)
    WHITELIST_DOMAINS = {
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'office365.com', 'outlook.com', 'gmail.com', 'yahoo.com'
    }
    
    @classmethod
    def extract_from_email(cls, email_data):
        """
        Extract all IOCs from email metadata and content.
        
        Args:
            email_data: Dict containing email fields (subject, header, body, etc.)
            
        Returns:
            Dict of IOC type -> list of unique IOCs
        """
        iocs = {
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'emails': set(),
            'hashes': set()
        }
        
        # Combine all text fields for comprehensive extraction
        searchable_text = ' '.join([
            str(email_data.get('subject', '')),
            str(email_data.get('header_text', '')),
            str(email_data.get('sender_domain', '')),
            str(email_data.get('sender_ip', '')),
            str(email_data.get('mail_server', ''))
        ])
        
        # Extract IPs
        ips = re.findall(cls.PATTERNS['ipv4'], searchable_text)
        iocs['ips'] = cls._filter_private_ips(ips)
        
        # Extract URLs
        urls = re.findall(cls.PATTERNS['url'], searchable_text)
        iocs['urls'] = set(urls)
        
        # Extract domains (excluding whitelisted)
        domains = re.findall(cls.PATTERNS['domain'], searchable_text)
        iocs['domains'] = cls._filter_domains(domains)
        
        # Extract email addresses
        emails = re.findall(cls.PATTERNS['email'], searchable_text)
        iocs['emails'] = set(emails)
        
        # Extract file hashes (if any)
        hashes = cls._extract_hashes(searchable_text)
        iocs['hashes'] = hashes
        
        return {k: list(v) for k, v in iocs.items()}
    
    @classmethod
    def _filter_private_ips(cls, ips):
        """Remove private/internal IP addresses - focus on external threats."""
        filtered = set()
        for ip in ips:
            octets = ip.split('.')
            if len(octets) != 4:
                continue
            first_octet = int(octets[0])
            
            # Skip private ranges (10.x, 172.16-31.x, 192.168.x)
            if first_octet == 10:
                continue
            if first_octet == 172 and 16 <= int(octets[1]) <= 31:
                continue
            if first_octet == 192 and int(octets[1]) == 168:
                continue
            if first_octet == 127:  # localhost
                continue
                
            filtered.add(ip)
        return filtered
    
    @classmethod
    def _filter_domains(cls, domains):
        """Remove whitelisted domains to reduce noise."""
        filtered = set()
        for domain in domains:
            domain_lower = domain.lower()
            # Check if domain or any parent domain is whitelisted
            is_whitelisted = any(
                domain_lower.endswith(white_domain) 
                for white_domain in cls.WHITELIST_DOMAINS
            )
            if not is_whitelisted:
                filtered.add(domain_lower)
        return filtered
    
    @classmethod
    def _extract_hashes(cls, text):
        """Extract file hashes (MD5, SHA1, SHA256) from text."""
        hashes = set()
        hashes.update(re.findall(cls.PATTERNS['md5'], text))
        hashes.update(re.findall(cls.PATTERNS['sha1'], text))
        hashes.update(re.findall(cls.PATTERNS['sha256'], text))
        return hashes


class ThreatIntelEnricher:
    """
    Enriches IOCs with threat intelligence from external sources.
    Demonstrates API integration and intelligence-driven analysis.
    """
    
    def __init__(self, virustotal_api_key=None, abuseipdb_api_key=None):
        """
        Initialize with API keys for threat intel sources.
        
        In production, these would be environment variables.
        For learning: Get free keys at virustotal.com and abuseipdb.com
        """
        self.vt_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.session = requests.Session()
    
    def enrich_domain(self, domain):
        """
        Enrich domain with VirusTotal data.
        
        Returns:
            Dict with threat intelligence data
        """
        if not self.vt_api_key:
            return self._mock_enrichment(domain, 'domain')
        
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'reputation_score': self._calculate_reputation(stats),
                    'malicious_count': stats.get('malicious', 0),
                    'total_scans': sum(stats.values()),
                    'categories': data.get('data', {}).get('attributes', {}).get('categories', {}),
                    'threat_category': self._determine_category(stats),
                    'is_malicious': stats.get('malicious', 0) > 0,
                    'enriched_at': datetime.utcnow()
                }
            
            time.sleep(15)  # VirusTotal rate limit: 4 requests/minute on free tier
            
        except Exception as e:
            print(f"Error enriching domain {domain}: {e}")
        
        return self._mock_enrichment(domain, 'domain')
    
    def enrich_ip(self, ip_address):
        """
        Enrich IP address with AbuseIPDB data.
        
        Returns:
            Dict with threat intelligence data
        """
        if not self.abuseipdb_api_key:
            return self._mock_enrichment(ip_address, 'ip')
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {'Key': self.abuseipdb_api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                return {
                    'reputation_score': 100 - data.get('abuseConfidenceScore', 0),
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'threat_category': 'Malicious' if data.get('abuseConfidenceScore', 0) > 75 else 'Suspicious',
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                    'enriched_at': datetime.utcnow()
                }
        
        except Exception as e:
            print(f"Error enriching IP {ip_address}: {e}")
        
        return self._mock_enrichment(ip_address, 'ip')
    
    def _calculate_reputation(self, stats):
        """
        Calculate reputation score (0-100) based on analysis results.
        Higher = more trustworthy, Lower = more suspicious
        """
        total = sum(stats.values())
        if total == 0:
            return 50  # Unknown/neutral
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        threat_ratio = (malicious + suspicious) / total
        reputation = 100 - (threat_ratio * 100)
        
        return round(reputation, 2)
    
    def _determine_category(self, stats):
        """Categorize threat based on detection stats."""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious > 5:
            return 'Malicious'
        elif malicious > 0 or suspicious > 3:
            return 'Suspicious'
        elif suspicious > 0:
            return 'Potentially Unwanted'
        else:
            return 'Clean'
    
    def _mock_enrichment(self, ioc_value, ioc_type):
        """
        Returns mock data for development/testing without API keys.
        This allows you to build and test without waiting for API access.
        """
        return {
            'reputation_score': 45.0,
            'threat_category': 'Suspicious',
            'is_malicious': True,
            'enriched_at': datetime.utcnow(),
            'note': 'Mock data - configure API keys for real enrichment'
        }


class PatternAnalyzer:
    """
    Analyzes IOCs to identify patterns and relationships.
    This is where threat hunting becomes intelligence.
    """
    
    @staticmethod
    def analyze_sender_patterns(emails):
        """
        Identify patterns in sender behavior across multiple emails.
        
        Returns:
            Dict of pattern insights
        """
        patterns = {
            'unique_senders': set(),
            'unique_domains': set(),
            'sender_frequency': {},
            'domain_frequency': {},
            'suspicious_patterns': []
        }
        
        for email in emails:
            sender = email.get('from_address', '')
            domain = email.get('sender_domain', '')
            
            patterns['unique_senders'].add(sender)
            patterns['unique_domains'].add(domain)
            
            # Track frequency
            patterns['sender_frequency'][sender] = patterns['sender_frequency'].get(sender, 0) + 1
            patterns['domain_frequency'][domain] = patterns['domain_frequency'].get(domain, 0) + 1
        
        # Identify suspicious patterns
        for domain, count in patterns['domain_frequency'].items():
            if count >= 5:  # Same domain sending multiple phishing emails
                patterns['suspicious_patterns'].append({
                    'pattern_type': 'high_volume_domain',
                    'domain': domain,
                    'email_count': count,
                    'severity': 'High'
                })
        
        return patterns
    
    @staticmethod
    def cluster_campaigns(emails, similarity_threshold=0.7):
        """
        Group emails into campaigns based on shared characteristics.
        
        This is a simplified version - production would use ML clustering.
        """
        campaigns = []
        
        # Group by similar subjects (simple approach)
        subject_groups = {}
        for email in emails:
            subject = email.get('subject', '').lower()
            # Extract keywords (simplified)
            keywords = set(subject.split())
            
            matched = False
            for existing_subject, group in subject_groups.items():
                existing_keywords = set(existing_subject.split())
                similarity = len(keywords & existing_keywords) / len(keywords | existing_keywords)
                
                if similarity >= similarity_threshold:
                    group.append(email)
                    matched = True
                    break
            
            if not matched:
                subject_groups[subject] = [email]
        
        # Convert to campaign format
        campaign_id = 1
        for subject, emails_in_group in subject_groups.items():
            if len(emails_in_group) >= 2:  # At least 2 emails to be a campaign
                campaigns.append({
                    'campaign_id': f'CAMP-{campaign_id:04d}',
                    'email_count': len(emails_in_group),
                    'common_subject_pattern': subject[:50],
                    'first_seen': min(e.get('received_date', datetime.now()) for e in emails_in_group),
                    'last_seen': max(e.get('received_date', datetime.now()) for e in emails_in_group)
                })
                campaign_id += 1
        
        return campaigns


# Example usage for testing
if __name__ == '__main__':
    # Test IOC extraction
    test_email = {
        'subject': 'Urgent: Verify your account at http://suspicious-site.com',
        'sender_domain': 'phishing-test.com',
        'sender_ip': '192.168.1.1',  # Will be filtered as private
        'header_text': 'From: attacker@malicious-domain.net via 203.0.113.42'
    }
    
    extractor = IOCExtractor()
    iocs = extractor.extract_from_email(test_email)
    
    print("Extracted IOCs:")
    for ioc_type, values in iocs.items():
        if values:
            print(f"  {ioc_type}: {values}")
    
    # Test enrichment (without API keys = mock data)
    enricher = ThreatIntelEnricher()
    if iocs['domains']:
        domain_intel = enricher.enrich_domain(iocs['domains'][0])
        print(f"\nDomain Intelligence for {iocs['domains'][0]}:")
        print(f"  Reputation: {domain_intel['reputation_score']}")
        print(f"  Category: {domain_intel['threat_category']}")