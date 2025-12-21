"""
Pattern Detection Engine for SOC Email Log

This module identifies anomalies and suspicious patterns in phishing data.
Demonstrates threat hunting thinking: "What doesn't fit the pattern?"

Key capabilities:
- Temporal anomaly detection (unusual timing)
- Volume spike detection (campaign identification)
- Behavioral pattern analysis
- Statistical outlier detection
"""

from datetime import datetime, timedelta
from collections import Counter, defaultdict
import statistics
from typing import List, Dict, Any


class AnomalyDetector:
    """
    Detects anomalies in email threat data.
    This is core threat hunting - finding what doesn't fit normal patterns.
    """
    
    @staticmethod
    def detect_volume_spikes(emails, time_window_hours=24):
        """
        Identify unusual spikes in phishing email volume.
        
        Spike detection helps identify:
        - Active phishing campaigns
        - Coordinated attacks
        - Threat actor activity surges
        
        Args:
            emails: List of email records
            time_window_hours: Time window to analyze
            
        Returns:
            List of detected spikes with timestamps and severity
        """
        if not emails:
            return []
        
        # Group emails by hour
        hourly_counts = defaultdict(int)
        for email in emails:
            timestamp = email.get('received_date')
            if timestamp:
                hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                hourly_counts[hour_key] += 1
        
        # Calculate baseline (mean and std dev)
        counts = list(hourly_counts.values())
        if len(counts) < 3:
            return []  # Need enough data for meaningful statistics
        
        mean_count = statistics.mean(counts)
        std_dev = statistics.stdev(counts) if len(counts) > 1 else 0
        
        # Identify spikes (> 2 standard deviations above mean)
        threshold = mean_count + (2 * std_dev)
        
        spikes = []
        for hour, count in hourly_counts.items():
            if count > threshold and count >= 3:  # At least 3 emails to be notable
                severity = 'Critical' if count > mean_count + (3 * std_dev) else 'High'
                spikes.append({
                    'timestamp': hour,
                    'email_count': count,
                    'baseline_mean': round(mean_count, 2),
                    'deviation': round((count - mean_count) / std_dev, 2) if std_dev > 0 else 0,
                    'severity': severity,
                    'pattern_type': 'volume_spike',
                    'description': f'Unusual spike: {count} emails vs baseline of {round(mean_count, 1)}'
                })
        
        return sorted(spikes, key=lambda x: x['timestamp'], reverse=True)
    
    @staticmethod
    def detect_temporal_anomalies(emails):
        """
        Identify unusual timing patterns in phishing attempts.
        
        Most phishing follows patterns:
        - Business hours for credential harvesting
        - Night/weekend for less monitoring
        
        Deviations can indicate:
        - Automated campaigns
        - Different threat actor TTPs
        - Targeted vs opportunistic attacks
        """
        if not emails:
            return []
        
        anomalies = []
        
        # Analyze by day of week
        day_counts = Counter()
        hour_counts = Counter()
        
        for email in emails:
            timestamp = email.get('received_date')
            if timestamp:
                day_counts[timestamp.strftime('%A')] += 1
                hour_counts[timestamp.hour] += 1
        
        # Expected pattern: Most activity during business days
        weekend_count = day_counts.get('Saturday', 0) + day_counts.get('Sunday', 0)
        weekday_count = sum(day_counts.values()) - weekend_count
        
        if weekend_count > weekday_count:
            anomalies.append({
                'pattern_type': 'unusual_weekend_activity',
                'severity': 'Medium',
                'weekend_emails': weekend_count,
                'weekday_emails': weekday_count,
                'description': 'Higher activity on weekends than weekdays - may indicate automated campaign',
                'threat_intel': 'Automated phishing campaigns often run 24/7'
            })
        
        # Expected pattern: Activity during business hours (9 AM - 5 PM)
        business_hours = sum(hour_counts[h] for h in range(9, 18))
        off_hours = sum(hour_counts.values()) - business_hours
        
        if off_hours > business_hours:
            anomalies.append({
                'pattern_type': 'unusual_off_hours_activity',
                'severity': 'Medium',
                'off_hours_emails': off_hours,
                'business_hours_emails': business_hours,
                'description': 'Most activity outside business hours',
                'threat_intel': 'May indicate international threat actor or automated system'
            })
        
        # Identify the "hot hours" for attacks
        if hour_counts:
            peak_hour = max(hour_counts.items(), key=lambda x: x[1])
            anomalies.append({
                'pattern_type': 'peak_activity_time',
                'severity': 'Info',
                'peak_hour': peak_hour[0],
                'email_count': peak_hour[1],
                'description': f'Peak phishing activity at {peak_hour[0]:02d}:00 ({peak_hour[1]} emails)',
                'actionable': 'Consider increasing monitoring during this time window'
            })
        
        return anomalies
    
    @staticmethod
    def detect_sender_anomalies(emails):
        """
        Identify unusual sender patterns that may indicate threats.
        
        Analyzes:
        - High-frequency senders (spam/campaign indicators)
        - Domain diversity (distributed attack)
        - Email address patterns (generation techniques)
        """
        if not emails:
            return []
        
        anomalies = []
        
        sender_counts = Counter(email.get('from_address', '') for email in emails)
        domain_counts = Counter(email.get('sender_domain', '') for email in emails)
        
        # Detect high-frequency senders (potential campaign)
        high_freq_senders = [(sender, count) for sender, count in sender_counts.items() if count >= 5]
        
        for sender, count in high_freq_senders:
            anomalies.append({
                'pattern_type': 'high_frequency_sender',
                'severity': 'High',
                'sender': sender,
                'email_count': count,
                'description': f'Sender {sender} appears in {count} phishing emails',
                'threat_intel': 'May indicate active campaign or compromised account',
                'recommended_action': 'Block sender and investigate related IOCs'
            })
        
        # Detect domain diversity patterns
        unique_domains = len(domain_counts)
        total_emails = len(emails)
        
        if unique_domains > total_emails * 0.8:  # High diversity
            anomalies.append({
                'pattern_type': 'high_domain_diversity',
                'severity': 'Medium',
                'unique_domains': unique_domains,
                'total_emails': total_emails,
                'diversity_ratio': round(unique_domains / total_emails, 2),
                'description': 'Very high sender domain diversity',
                'threat_intel': 'Indicates distributed campaign using many compromised/disposable domains',
                'detection_strategy': 'Focus on content patterns rather than sender reputation'
            })
        elif unique_domains < total_emails * 0.2:  # Low diversity
            anomalies.append({
                'pattern_type': 'low_domain_diversity',
                'severity': 'High',
                'unique_domains': unique_domains,
                'total_emails': total_emails,
                'diversity_ratio': round(unique_domains / total_emails, 2),
                'description': 'Low sender domain diversity - concentrated campaign',
                'threat_intel': 'Indicates coordinated campaign from limited infrastructure',
                'detection_strategy': 'Domain-based blocking will be highly effective'
            })
        
        return anomalies
    
    @staticmethod
    def detect_content_anomalies(emails):
        """
        Analyze email content for suspicious patterns.
        
        Looks for:
        - Unusual subject line patterns
        - Attachment type trends
        - Keyword clustering
        """
        if not emails:
            return []
        
        anomalies = []
        
        # Analyze subjects for common keywords (campaign indicators)
        all_subjects = ' '.join(email.get('subject', '').lower() for email in emails)
        
        # Common phishing keywords
        phishing_keywords = {
            'urgent', 'verify', 'suspended', 'unusual', 'activity', 'confirm',
            'update', 'secure', 'account', 'password', 'reset', 'expired',
            'action required', 'immediately', 'security alert', 'click here'
        }
        
        keyword_matches = {}
        for keyword in phishing_keywords:
            count = all_subjects.count(keyword)
            if count > 0:
                keyword_matches[keyword] = count
        
        if keyword_matches:
            top_keywords = sorted(keyword_matches.items(), key=lambda x: x[1], reverse=True)[:5]
            anomalies.append({
                'pattern_type': 'common_phishing_keywords',
                'severity': 'Info',
                'top_keywords': dict(top_keywords),
                'description': 'Most common social engineering keywords detected',
                'threat_intel': 'Reveals social engineering tactics used in campaigns',
                'detection_opportunity': 'Can build subject-line based detection rules'
            })
        
        # Analyze attachment types
        attachment_counts = Counter(
            email.get('attachment_type', 'None') 
            for email in emails 
            if email.get('attachment_type')
        )
        
        if attachment_counts:
            # High-risk attachment types
            risky_types = {'exe', 'zip', 'rar', 'js', 'vbs', 'bat', 'scr', 'doc', 'xls'}
            risky_found = {ext: count for ext, count in attachment_counts.items() 
                          if any(risk in ext.lower() for risk in risky_types)}
            
            if risky_found:
                anomalies.append({
                    'pattern_type': 'risky_attachment_types',
                    'severity': 'High',
                    'attachment_types': risky_found,
                    'description': 'High-risk attachment types detected',
                    'threat_intel': 'These file types can execute malicious code',
                    'recommended_action': 'Implement attachment filtering rules'
                })
        
        return anomalies


class BehavioralAnalyzer:
    """
    Analyzes attacker behavior patterns across campaigns.
    This is advanced threat hunting - understanding TTPs (Tactics, Techniques, Procedures).
    """
    
    @staticmethod
    def analyze_attack_patterns(emails):
        """
        Identify attacker tactics and techniques from email data.
        
        Returns insights about:
        - Social engineering themes
        - Infrastructure patterns
        - Campaign evolution
        """
        if not emails:
            return {}
        
        analysis = {
            'total_emails_analyzed': len(emails),
            'time_span': None,
            'social_engineering_themes': [],
            'infrastructure_analysis': {},
            'campaign_sophistication': 'Unknown'
        }
        
        # Time span analysis
        timestamps = [e.get('received_date') for e in emails if e.get('received_date')]
        if timestamps:
            analysis['time_span'] = {
                'first_seen': min(timestamps),
                'last_seen': max(timestamps),
                'duration_days': (max(timestamps) - min(timestamps)).days
            }
        
        # Identify social engineering themes from subjects
        subjects = [email.get('subject', '').lower() for email in emails]
        
        theme_keywords = {
            'Account Security': ['verify', 'suspended', 'locked', 'security', 'unusual activity'],
            'Urgent Action': ['urgent', 'immediate', 'action required', 'expire'],
            'Financial': ['payment', 'invoice', 'refund', 'billing', 'transaction'],
            'Shipping': ['delivery', 'package', 'shipment', 'tracking'],
            'IT Support': ['helpdesk', 'support', 'reset password', 'update']
        }
        
        for theme, keywords in theme_keywords.items():
            matches = sum(1 for subject in subjects if any(kw in subject for kw in keywords))
            if matches > 0:
                analysis['social_engineering_themes'].append({
                    'theme': theme,
                    'email_count': matches,
                    'percentage': round((matches / len(emails)) * 100, 1)
                })
        
        # Infrastructure sophistication
        unique_domains = len(set(email.get('sender_domain', '') for email in emails))
        unique_ips = len(set(email.get('sender_ip', '') for email in emails if email.get('sender_ip')))
        
        analysis['infrastructure_analysis'] = {
            'unique_sender_domains': unique_domains,
            'unique_sender_ips': unique_ips,
            'infrastructure_diversity': 'High' if unique_domains > len(emails) * 0.5 else 'Low'
        }
        
        # Sophistication assessment
        has_varied_infrastructure = unique_domains > 5
        has_varied_themes = len(analysis['social_engineering_themes']) > 2
        
        if has_varied_infrastructure and has_varied_themes:
            analysis['campaign_sophistication'] = 'High - Diverse tactics and infrastructure'
        elif has_varied_infrastructure or has_varied_themes:
            analysis['campaign_sophistication'] = 'Medium - Some variation in approach'
        else:
            analysis['campaign_sophistication'] = 'Low - Repetitive patterns (easier to detect)'
        
        return analysis
    
    @staticmethod
    def generate_threat_report(emails, anomalies):
        """
        Generate an executive-level threat intelligence report.
        This demonstrates the documentation and communication skills SOC analysts need.
        """
        report = {
            'report_generated': datetime.utcnow(),
            'executive_summary': '',
            'key_findings': [],
            'threat_landscape': {},
            'recommended_actions': [],
            'detection_opportunities': []
        }
        
        # Executive summary
        total_emails = len(emails)
        high_severity_anomalies = sum(1 for a in anomalies if a.get('severity') == 'High')
        
        report['executive_summary'] = (
            f"Analysis of {total_emails} phishing emails revealed {len(anomalies)} distinct patterns, "
            f"including {high_severity_anomalies} high-severity anomalies requiring immediate attention."
        )
        
        # Key findings from anomalies
        for anomaly in anomalies:
            if anomaly.get('severity') in ['High', 'Critical']:
                report['key_findings'].append({
                    'finding': anomaly.get('description'),
                    'severity': anomaly.get('severity'),
                    'threat_intel': anomaly.get('threat_intel', 'N/A')
                })
        
        # Behavioral analysis
        behavior = BehavioralAnalyzer.analyze_attack_patterns(emails)
        report['threat_landscape'] = behavior
        
        # Recommended actions
        for anomaly in anomalies:
            if anomaly.get('recommended_action'):
                report['recommended_actions'].append({
                    'action': anomaly['recommended_action'],
                    'priority': anomaly['severity'],
                    'rationale': anomaly.get('description')
                })
        
        # Detection opportunities
        for anomaly in anomalies:
            if anomaly.get('detection_opportunity') or anomaly.get('detection_strategy'):
                report['detection_opportunities'].append({
                    'opportunity': anomaly.get('detection_opportunity') or anomaly.get('detection_strategy'),
                    'pattern_type': anomaly.get('pattern_type')
                })
        
        return report


# Example usage
if __name__ == '__main__':
    # Simulate some test data
    from datetime import datetime, timedelta
    
    test_emails = [
        {
            'received_date': datetime.now() - timedelta(hours=i),
            'from_address': f'phish{i % 3}@malicious.com',
            'sender_domain': f'malicious{i % 2}.com',
            'subject': 'Urgent: Verify your account immediately',
            'attachment_type': 'None'
        }
        for i in range(20)
    ]
    
    # Add a spike
    for i in range(10):
        test_emails.append({
            'received_date': datetime.now() - timedelta(hours=5, minutes=i*5),
            'from_address': 'campaign@attacker.com',
            'sender_domain': 'attacker.com',
            'subject': 'Security Alert: Action Required',
            'attachment_type': 'zip'
        })
    
    detector = AnomalyDetector()
    
    print("=== VOLUME SPIKE DETECTION ===")
    spikes = detector.detect_volume_spikes(test_emails)
    for spike in spikes:
        print(f"\n{spike['severity']} - {spike['description']}")
        print(f"  Timestamp: {spike['timestamp']}")
        print(f"  Deviation: {spike['deviation']} standard deviations")
    
    print("\n=== TEMPORAL ANOMALIES ===")
    temporal = detector.detect_temporal_anomalies(test_emails)
    for anomaly in temporal:
        print(f"\n{anomaly['pattern_type']}:")
        print(f"  {anomaly['description']}")
        if 'threat_intel' in anomaly:
            print(f"  Intel: {anomaly['threat_intel']}")
    
    print("\n=== SENDER ANOMALIES ===")
    sender_anomalies = detector.detect_sender_anomalies(test_emails)
    for anomaly in sender_anomalies:
        print(f"\n{anomaly['severity']} - {anomaly['pattern_type']}")
        print(f"  {anomaly['description']}")
    
    print("\n=== BEHAVIORAL ANALYSIS ===")
    analyzer = BehavioralAnalyzer()
    behavior = analyzer.analyze_attack_patterns(test_emails)
    print(f"Campaign sophistication: {behavior['campaign_sophistication']}")
    print(f"Infrastructure diversity: {behavior['infrastructure_analysis']['infrastructure_diversity']}")