# Update: flask-api/app/routes/api.py

from flask import Blueprint, request, jsonify, abort, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.security.auth_middleware import auth_required
from app.security.request_validator import validate_prediction_request
from app.security.input_validator import sanitize_url, sanitize_email_content
from app.models.phishing_model import PhishingModel

# Create blueprint
api_bp = Blueprint('api', __name__)

# Initialize model
model = PhishingModel()

@api_bp.route('/predict', methods=['POST'])
@auth_required  # Add authentication requirement
def predict():
    """
    Endpoint for phishing prediction
    Accepts email content or URL for analysis
    Returns prediction results with confidence score
    """
    if not request.is_json:
        return jsonify({
            "error": {
                "code": "PHISH-400", 
                "message": "Request must be JSON"
            }
        }), 400
    
    data = request.get_json()
    
    # Validate request data
    validation_errors = validate_prediction_request(data)
    if validation_errors:
        return jsonify({
            "error": {
                "code": "PHISH-422", 
                "message": "Validation error",
                "details": validation_errors
            }
        }), 422
    
    try:
        # Sanitize inputs
        content = sanitize_email_content(data.get('email_content', ''))
        url = sanitize_url(data.get('url', ''))
        scan_type = data.get('scan_type', 'REGULAR')
        
        # Use the model to get prediction
        if url:
            result = model.predict(url=url)
        elif content:
            result = model.predict(content=content)
        else:
            return jsonify({
                "error": {
                    "code": "PHISH-422", 
                    "message": "Missing required field: email_content or url"
                }
            }), 422
        
        # Add user ID from authentication token
        result["user_id"] = g.user_id
        
        return jsonify(result), 200
        
    except Exception as e:
        # Log the error (implementation pending)
        # In a production environment, you'd want to log the actual error
        return jsonify({
            "error": {
                "code": "PHISH-500", 
                "message": "Internal server error"
            }
        }), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        "status": "healthy", 
        "version": "1.0.0"
    }), 200