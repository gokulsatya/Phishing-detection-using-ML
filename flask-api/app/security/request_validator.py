# Save to: flask-api/app/security/request_validator.py

from flask import request, jsonify
from .input_validator import validate_url, validate_email_content

def validate_prediction_request(request_data):
    """Validate prediction request data"""
    errors = []
    
    # Check for required fields
    if not ('email_content' in request_data or 'url' in request_data):
        errors.append("Missing required field: email_content or url")
    
    # Validate URL if present
    if 'url' in request_data:
        url = request_data.get('url')
        if not validate_url(url):
            errors.append("Invalid URL format")
    
    # Validate email content if present
    if 'email_content' in request_data:
        content = request_data.get('email_content')
        if not validate_email_content(content):
            errors.append("Invalid or empty email content")
    
    return errors