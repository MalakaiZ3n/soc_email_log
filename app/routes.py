"""
Flask Routes for SOC Email Log

Handles web requests for logging and viewing phishing emails.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime
import sys
import os

# Import from parent directory (project root)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, PhishingEmail, IOC
from threat_intel import IOCExtractor, ThreatIntelEnricher
from .header_parser import EmailHeaderParser

# Create blueprint
main = Blueprint('main', __name__)

# Initialize tools
header_parser = EmailHeaderParser()
ioc_extractor = IOCExtractor()
enricher = ThreatIntelEnricher()


@main.route('/')
def index():
    """Dashboard - Overview of logged emails."""
    total_emails = PhishingEmail.query.count()
    recent_emails = PhishingEmail.query.order_by(PhishingEmail.created_at.desc()).limit(10).all()
    
    # Quick stats
    stats = {
        'total_emails': total_emails,
        'this_week': PhishingEmail.query.filter(
            PhishingEmail.created_at >= datetime.now().replace(hour=0, minute=0, second=0)
        ).count(),
        'unique_domains': db.session.query(PhishingEmail.sender_domain).distinct().count(),
        'unique_ips': db.session.query(PhishingEmail.sender_ip).distinct().count()
    }
    
    return render_template('dashboard.html', stats=stats, recent_emails=recent_emails)


@main.route('/log', methods=['GET', 'POST'])
def log_email():
    """
    Log a new phishing email.
    
    Workflow:
    1. Analyst pastes email header
    2. System parses and extracts fields
    3. Shows preview for verification
    4. Analyst adds notes
    5. Save to database
    """
    if request.method == 'GET':
        return render_template('log_email.html')
    
    # POST - Handle form submission
    if 'parse_header' in request.form:
        # Step 1: Parse the pasted header
        raw_header = request.form.get('raw_header', '')
        parsed_data = header_parser.parse(raw_header)
        
        return render_template('log_email.html', 
                             parsed_data=parsed_data, 
                             raw_header=raw_header)
    
    elif 'save_email' in request.form:
        # Step 2: Save to database
        try:
            # Create email record
            email = PhishingEmail(
                from_address=request.form.get('from_address'),
                to_address=request.form.get('to_address'),
                subject=request.form.get('subject'),
                sender_domain=request.form.get('sender_domain'),
                sender_ip=request.form.get('sender_ip') or None,
                mail_server=request.form.get('mail_server'),
                smtp_sender=request.form.get('smtp_sender'),
                header_text=request.form.get('raw_header'),
                threat_type=request.form.get('threat_type', 'Phishing'),
                file_hash=request.form.get('file_hash') or None,
                virustotal_results=request.form.get('virustotal_results') or None,
                analyst_notes=request.form.get('analyst_notes'),
                received_date=datetime.now()  # You could parse from header if needed
            )
            
            db.session.add(email)
            db.session.flush()  # Get the ID
            
            # Extract and save IOCs
            email_data = {
                'subject': email.subject,
                'header_text': email.header_text,
                'sender_domain': email.sender_domain,
                'sender_ip': email.sender_ip,
                'mail_server': email.mail_server
            }
            
            iocs = ioc_extractor.extract_from_email(email_data)
            
            # Save IOCs to database
            ioc_count = 0
            for ioc_type, ioc_list in iocs.items():
                for ioc_value in ioc_list:
                    ioc = IOC(
                        email_id=email.id,
                        ioc_type=ioc_type.rstrip('s'),  # domains -> domain
                        ioc_value=ioc_value,
                        extraction_context='web_interface'
                    )
                    db.session.add(ioc)
                    ioc_count += 1
            
            db.session.commit()
            
            flash(f'✓ Email logged successfully! Extracted {ioc_count} IOCs.', 'success')
            return redirect(url_for('main.view_email', email_id=email.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving email: {str(e)}', 'error')
            return redirect(url_for('main.log_email'))
    
    return redirect(url_for('main.log_email'))


@main.route('/emails')
def list_emails():
    """View all logged emails."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get emails with pagination
    pagination = PhishingEmail.query.order_by(
        PhishingEmail.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    emails = pagination.items
    
    return render_template('list_emails.html', 
                         emails=emails, 
                         pagination=pagination)


@main.route('/email/<int:email_id>')
def view_email(email_id):
    """View details of a specific email."""
    email = PhishingEmail.query.get_or_404(email_id)
    
    # Get associated IOCs
    iocs = IOC.query.filter_by(email_id=email_id).all()
    
    # Group IOCs by type
    iocs_by_type = {}
    for ioc in iocs:
        if ioc.ioc_type not in iocs_by_type:
            iocs_by_type[ioc.ioc_type] = []
        iocs_by_type[ioc.ioc_type].append(ioc)
    
    return render_template('view_email.html', 
                         email=email, 
                         iocs_by_type=iocs_by_type)


@main.route('/email/<int:email_id>/delete', methods=['POST'])
def delete_email(email_id):
    """Delete an email record."""
    email = PhishingEmail.query.get_or_404(email_id)
    
    try:
        db.session.delete(email)
        db.session.commit()
        flash('Email deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting email: {str(e)}', 'error')
    
    return redirect(url_for('main.list_emails'))


@main.route('/email/<int:email_id>/edit', methods=['GET', 'POST'])
def edit_email(email_id):
    """Edit an existing email record."""
    email = PhishingEmail.query.get_or_404(email_id)
    
    if request.method == 'POST':
        try:
            # Update email fields
            email.from_address = request.form.get('from_address')
            email.to_address = request.form.get('to_address')
            email.subject = request.form.get('subject')
            email.sender_domain = request.form.get('sender_domain')
            email.sender_ip = request.form.get('sender_ip') or None
            email.mail_server = request.form.get('mail_server')
            email.smtp_sender = request.form.get('smtp_sender')
            email.threat_type = request.form.get('threat_type', 'Phishing')
            email.file_hash = request.form.get('file_hash') or None
            email.virustotal_results = request.form.get('virustotal_results') or None
            email.analyst_notes = request.form.get('analyst_notes')
            email.header_text = request.form.get('raw_header')
            
            # Update the updated_at timestamp
            email.updated_at = datetime.now()
            
            db.session.commit()
            flash('Email updated successfully!', 'success')
            return redirect(url_for('main.view_email', email_id=email.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating email: {str(e)}', 'error')
    
    # GET request - show edit form
    return render_template('edit_email.html', email=email)


@main.route('/search')
def search():
    """Search emails by various criteria."""
    query = request.args.get('q', '')
    search_field = request.args.get('field', 'all')
    
    if not query:
        return redirect(url_for('main.list_emails'))
    
    # Build search query
    if search_field == 'sender':
        results = PhishingEmail.query.filter(
            PhishingEmail.from_address.contains(query)
        ).all()
    elif search_field == 'domain':
        results = PhishingEmail.query.filter(
            PhishingEmail.sender_domain.contains(query)
        ).all()
    elif search_field == 'subject':
        results = PhishingEmail.query.filter(
            PhishingEmail.subject.contains(query)
        ).all()
    else:  # Search all fields
        results = PhishingEmail.query.filter(
            db.or_(
                PhishingEmail.from_address.contains(query),
                PhishingEmail.sender_domain.contains(query),
                PhishingEmail.subject.contains(query),
                PhishingEmail.analyst_notes.contains(query)
            )
        ).all()
    
    return render_template('search_results.html', 
                         query=query, 
                         results=results, 
                         search_field=search_field)


@main.route('/api/parse-header', methods=['POST'])
def api_parse_header():
    """API endpoint to parse email header (AJAX)."""
    data = request.get_json()
    raw_header = data.get('header', '')
    
    if not raw_header:
        return jsonify({'error': 'No header provided'}), 400
    
    parsed = header_parser.parse(raw_header)
    return jsonify(parsed)


@main.route('/stats')
def stats():
    """View statistics and analytics."""
    # This would connect to your pattern_detection.py
    # For now, basic stats
    
    total_emails = PhishingEmail.query.count()
    
    # Top sender domains
    from sqlalchemy import func
    top_domains = db.session.query(
        PhishingEmail.sender_domain,
        func.count(PhishingEmail.id).label('count')
    ).group_by(PhishingEmail.sender_domain).order_by(
        func.count(PhishingEmail.id).desc()
    ).limit(10).all()
    
    # Emails over time (last 30 days)
    from datetime import timedelta
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_by_day = db.session.query(
        func.date(PhishingEmail.created_at).label('date'),
        func.count(PhishingEmail.id).label('count')
    ).filter(
        PhishingEmail.created_at >= thirty_days_ago
    ).group_by(
        func.date(PhishingEmail.created_at)
    ).all()
    
    return render_template('stats.html',
                         total_emails=total_emails,
                         top_domains=top_domains,
                         recent_by_day=recent_by_day)