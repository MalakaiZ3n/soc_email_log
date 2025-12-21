"""
Database models for phishing threat intelligence platform.

This schema is designed to support threat hunting workflows:
- Comprehensive email threat logging
- IOC (Indicator of Compromise) tracking
- Campaign correlation
- Detection rule management
"""

from datetime import datetime
import os
import sys

# Import db from app if running as part of Flask app
try:
    from app import db
except ImportError:
    # Fallback for standalone usage
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()


class PhishingEmail(db.Model):
    """
    Core threat log - Each record represents a suspicious email analyzed.
    Maps directly to SOC incident documentation requirements.
    """
    __tablename__ = 'phishing_emails'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Email Metadata
    from_address = db.Column(db.String(255), nullable=False, index=True)
    to_address = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.Text, nullable=False)
    received_date = db.Column(db.DateTime, nullable=False, index=True)
    
    # Sender Infrastructure
    sender_domain = db.Column(db.String(255), index=True)
    sender_ip = db.Column(db.String(45))  # IPv6 compatible
    mail_server = db.Column(db.String(255))
    smtp_sender = db.Column(db.String(255))
    
    # Email Content Analysis
    header_text = db.Column(db.Text)
    body_preview = db.Column(db.Text)
    attachment_type = db.Column(db.String(50))
    file_hash = db.Column(db.String(128))  # MD5/SHA1/SHA256 hash of attachment
    virustotal_results = db.Column(db.Text)  # VirusTotal scan results or link
    
    # Threat Classification
    threat_type = db.Column(db.String(50), default='Phishing', index=True)
    confidence_score = db.Column(db.Float)  # 0-100 threat confidence
    severity = db.Column(db.String(20))  # Low, Medium, High, Critical
    
    # Analysis Notes
    analyst_notes = db.Column(db.Text)
    identified_pattern = db.Column(db.String(255))
    
    # Campaign Tracking
    campaign_id = db.Column(db.String(50), index=True)  # Link related emails
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    iocs = db.relationship('IOC', backref='email', lazy='dynamic', cascade='all, delete-orphan')
    detections = db.relationship('DetectionRule', secondary='email_detections', backref='triggered_emails')
    
    def __repr__(self):
        return f'<PhishingEmail {self.id}: {self.subject[:50]}>'


class IOC(db.Model):
    """
    Indicators of Compromise extracted from phishing emails.
    Critical for threat intelligence sharing and detection building.
    """
    __tablename__ = 'iocs'
    
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('phishing_emails.id'), nullable=False)
    
    # IOC Details
    ioc_type = db.Column(db.String(50), nullable=False, index=True)  # domain, ip, url, hash, email
    ioc_value = db.Column(db.String(500), nullable=False, index=True)
    
    # Threat Intelligence Enrichment
    reputation_score = db.Column(db.Float)  # From VirusTotal, AbuseIPDB, etc.
    threat_category = db.Column(db.String(100))  # Malware, Phishing, Spam, etc.
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    
    # External Intelligence
    virustotal_detections = db.Column(db.Integer)
    virustotal_total = db.Column(db.Integer)
    abuseipdb_score = db.Column(db.Integer)
    
    # Context
    extraction_context = db.Column(db.String(255))  # Where in email was this found
    is_malicious = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    enriched_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<IOC {self.ioc_type}: {self.ioc_value}>'


class DetectionRule(db.Model):
    """
    Detection logic created from analyzed threats.
    These rules can be used to automatically identify similar threats.
    """
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Rule Metadata
    rule_name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='Medium')
    
    # Detection Logic
    rule_type = db.Column(db.String(50), nullable=False)  # regex, yara, behavioral, ml
    rule_pattern = db.Column(db.Text, nullable=False)
    
    # Matching Criteria
    target_field = db.Column(db.String(50))  # subject, sender, header, body
    match_condition = db.Column(db.String(50))  # contains, regex, exact, threshold
    
    # Performance Metrics
    true_positives = db.Column(db.Integer, default=0)
    false_positives = db.Column(db.Integer, default=0)
    accuracy_rate = db.Column(db.Float)
    
    # Rule Status
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(100), default='analyst')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_triggered = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<DetectionRule: {self.rule_name}>'


class ThreatCampaign(db.Model):
    """
    Groups related phishing emails into campaigns for pattern analysis.
    Critical for understanding threat actor behaviors and tactics.
    """
    __tablename__ = 'threat_campaigns'
    
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.String(50), unique=True, nullable=False)
    
    # Campaign Characteristics
    campaign_name = db.Column(db.String(200))
    threat_actor = db.Column(db.String(100))  # If known
    target_industry = db.Column(db.String(100))
    
    # Tactics, Techniques, and Procedures (TTPs)
    attack_vector = db.Column(db.String(100))
    payload_type = db.Column(db.String(100))
    social_engineering_theme = db.Column(db.String(200))
    
    # Timeline
    first_observed = db.Column(db.DateTime)
    last_observed = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Impact
    email_count = db.Column(db.Integer, default=0)
    affected_users = db.Column(db.Integer, default=0)
    
    # Analysis
    analyst_assessment = db.Column(db.Text)
    mitigation_steps = db.Column(db.Text)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ThreatCampaign: {self.campaign_name}>'


# Association table for many-to-many relationship between emails and detection rules
email_detections = db.Table('email_detections',
    db.Column('email_id', db.Integer, db.ForeignKey('phishing_emails.id'), primary_key=True),
    db.Column('rule_id', db.Integer, db.ForeignKey('detection_rules.id'), primary_key=True),
    db.Column('detected_at', db.DateTime, default=datetime.utcnow)
)


class ThreatIntelFeed(db.Model):
    """
    Tracks threat intelligence sources and their reliability.
    Helps assess confidence in enrichment data.
    """
    __tablename__ = 'threat_intel_feeds'
    
    id = db.Column(db.Integer, primary_key=True)
    feed_name = db.Column(db.String(100), unique=True, nullable=False)
    feed_type = db.Column(db.String(50))  # api, feed, manual
    
    # Reliability Metrics
    accuracy_rating = db.Column(db.Float)
    false_positive_rate = db.Column(db.Float)
    last_updated = db.Column(db.DateTime)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    api_key_configured = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ThreatIntelFeed: {self.feed_name}>'