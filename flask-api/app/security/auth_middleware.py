# Save to: flask-api/app/security/auth_middleware.py

from functools import wraps
from flask import request, jsonify, g
from .jwt_utils import get_token_from_header, validate_token

def auth_required(f):
    """Decorator to require authentication on routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        if not token:
            return jsonify({
                "error": {
                    "code": "PHISH-401",
                    "message": "Authentication required"
                }
            }), 401
        
        payload = validate_token(token)
        if not payload:
            return jsonify({
                "error": {
                    "code": "PHISH-401",
                    "message": "Invalid or expired token"
                }
            }), 401
        
        # Store user info in g for access in the route
        g.user_id = payload['user_id']
        return f(*args, **kwargs)
    
    return decorated