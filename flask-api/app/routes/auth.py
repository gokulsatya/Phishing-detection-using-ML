# Save to: flask-api/app/routes/auth.py

from flask import Blueprint, request, jsonify
from app.security.jwt_utils import generate_token
import uuid

# For a simple prototype, we'll use a mock user
# In a real app, you'd use a database
MOCK_USERS = {
    "demo@phishguard.example.com": {
        "password": "securePassword123",
        "user_id": "usr_" + str(uuid.uuid4())
    }
}

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login endpoint that returns a JWT token"""
    if not request.is_json:
        return jsonify({
            "error": {
                "code": "PHISH-400",
                "message": "Request must be JSON"
            }
        }), 400
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    # Validate credentials
    if not email or not password:
        return jsonify({
            "error": {
                "code": "PHISH-422",
                "message": "Missing email or password"
            }
        }), 422
    
    # Check credentials (mock implementation)
    user = MOCK_USERS.get(email)
    if not user or user['password'] != password:
        return jsonify({
            "error": {
                "code": "PHISH-401",
                "message": "Invalid credentials"
            }
        }), 401
    
    # Generate token
    token = generate_token(user['user_id'])
    
    return jsonify({
        "token": token,
        "expires_in": 1800,  # 30 minutes
        "user_id": user['user_id']
    }), 200

@auth_bp.route('/token/refresh', methods=['POST'])
def refresh_token():
    """Endpoint to refresh an existing token"""
    # Implementation details would go here
    # This would validate the current token and issue a new one
    return jsonify({"status": "Not implemented yet"}), 501