# Save to: flask-api/app/security/jwt_utils.py
import os
import jwt
import datetime
from flask import current_app, request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# JWT configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-replace-in-production')  # Use environment variable in production
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXPIRATION', 1800))  # 30 minutes

def generate_token(user_id):
    """Generate a new JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def validate_token(token):
    """Validate a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def get_token_from_header():
    """Extract token from Authorization header"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    
    # Check for Bearer token format
    parts = auth_header.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        return None
    
    return parts[1]