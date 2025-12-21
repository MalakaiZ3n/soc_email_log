"""
SOC Email Log - Application Entry Point

Run this file to start the web application.

Usage:
    python run.py

Then open your browser to: http://localhost:5000
"""

import os
import sys

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app

# Create the Flask app
app = create_app()

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║                  SOC Email Log                             ║
║           Phishing Threat Intelligence Platform            ║
╚════════════════════════════════════════════════════════════╝

Starting server...

Dashboard:     http://localhost:5000
Log Email:     http://localhost:5000/log
View Emails:   http://localhost:5000/emails
Analytics:     http://localhost:5000/stats

Press CTRL+C to stop the server
""")
    
    # Run the development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True  # Set to False in production
    )