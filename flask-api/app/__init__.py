from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

def create_app(config_name='default'):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configure performance settings
    app.config.update({
        'JSONIFY_PRETTYPRINT_REGULAR': False,
        'JSON_SORT_KEYS': True,
        'TEMPLATES_AUTO_RELOAD': False
    })
    
    # Setup CORS - will refine with specific origins later
    CORS(app)
    
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
        'script-src': ["'self'"]
    }
    Talisman(app, content_security_policy=csp, force_https=True)
    
    # Register blueprints
    from app.routes.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/v1')
    
    return app