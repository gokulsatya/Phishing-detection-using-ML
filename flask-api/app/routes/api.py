# Update: flask-api/app/routes/api.py

from flask import Blueprint, request, jsonify, abort, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.security.auth_middleware import auth_required
from app.security.request_validator import validate_prediction_request
from app.security.input_validator import sanitize_url, sanitize_email_content
from app.models.phishing_model import PhishingModel
import time
from app.models.telemetry import telemetry_manager

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
    start_time = time.time()

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
       # Use the model to get prediction
        result = model.predict(content=content, url=url)
        
        # Add user ID from authentication token
        result["user_id"] = g.user_id
        
        # Add model information
        result["model_version"] = model.model_version
        
        # Record telemetry (response time in milliseconds)
        response_time_ms = (time.time() - start_time) * 1000
        telemetry_manager.record_prediction(result, response_time_ms)
        
        return jsonify(result), 200
        
    except Exception as e:
        # Log the error (implementation pending)
        # In a production environment, you'd want to log the actual error
        print(f"Error processing prediction request: {e}")
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

@api_bp.route('/feedback', methods=['POST'])
@auth_required
def submit_feedback():
    """
    Endpoint for submitting feedback on phishing predictions
    Used to improve model accuracy over time
    """
    if not request.is_json:
        return jsonify({
            "error": {
                "code": "PHISH-400", 
                "message": "Request must be JSON"
            }
        }), 400
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['scan_id', 'is_correct']
    for field in required_fields:
        if field not in data:
            return jsonify({
                "error": {
                    "code": "PHISH-422", 
                    "message": f"Missing required field: {field}"
                }
            }), 422
    
    try:
        # Extract data
        scan_id = data.get('scan_id')
        is_correct = data.get('is_correct')
        comment = data.get('comment', '')
        
        # In a production system, this would be stored in a database
        # For now, we'll just log it
        print(f"Feedback received: scan_id={scan_id}, is_correct={is_correct}, comment={comment}")
        
        # Return success response
        return jsonify({
            "status": "success",
            "message": "Feedback submitted successfully"
        }), 200
        
    except Exception as e:
        # Log the error
        print(f"Error processing feedback: {e}")
        return jsonify({
            "error": {
                "code": "PHISH-500", 
                "message": "Internal server error"
            }
        }), 500

# Add a new endpoint for telemetry statistics
@api_bp.route('/stats', methods=['GET'])
@auth_required
def get_stats():
    """Get API usage statistics"""
    try:
        stats = telemetry_manager.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        print(f"Error retrieving statistics: {e}")
        return jsonify({
            "error": {
                "code": "PHISH-500", 
                "message": "Internal server error"
            }
        }), 500
