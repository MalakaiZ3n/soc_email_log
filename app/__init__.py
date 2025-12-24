"""
Flask Application Factory for SOC Email Log

This initializes the Flask app with database and configuration.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize extensions
db = SQLAlchemy()


def create_app():
    """Create and configure the Flask application."""

    # Explicitly set template and static folders
    template_dir = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), 'templates')

    app = Flask(__name__, template_folder=template_dir)

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URI',
        'sqlite:///phishing_logs.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions with app
    db.init_app(app)

    # Register blueprints/routes
    from .routes import main  # Use relative import
    app.register_blueprint(main)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app
