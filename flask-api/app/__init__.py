from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from app.error_handlers import register_error_handlers

def create_app(config_name='default'):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configure performance settings
    app.config.update({
        'JSONIFY_PRETTYPRINT_REGULAR': False,
        'JSON_SORT_KEYS': True,
        'TEMPLATES_AUTO_RELOAD': False
    })
    
    # Setup CORS with more restricted settings
    cors_origins = [
        'chrome-extension://*',  # Allow all extensions during development
        'http://localhost:5000',  # For development
        'http://127.0.0.1:5000'   # Also include this
    ]
    CORS(app, origins=cors_origins, supports_credentials=True)
    
    # Setup rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["10 per minute"],
        storage_uri="memory://"
    )
    
    # Setup security headers with Talisman
    csp = {
        'default-src': "'self'",
        'connect-src': ["'self'"],
        'script-src': ["'self'"],
        'img-src': ["'self'", "data:"],
        'style-src': ["'self'", "'unsafe-inline'"]  # Allowing inline styles for simplicity
    }
    Talisman(
        app,
        content_security_policy=csp,
        force_https=False,  # Set to True in production
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,  # 1 year
        frame_options='DENY'
    )
    
    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp  

    app.register_blueprint(api_bp, url_prefix='/v1')
    app.register_blueprint(auth_bp, url_prefix='/v1/auth')

    # Register error handlers
    register_error_handlers(app)

    return app