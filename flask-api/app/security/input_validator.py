# Save to: flask-api/app/security/input_validator.py

import re
from flask import request, jsonify

# Validation patterns
URL_PATTERN = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
# Simple email pattern - in production, use a more comprehensive one or a library
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

def validate_url(url):
    """Validate a URL string"""
    if not url or not isinstance(url, str):
        return False
    
    return bool(re.match(URL_PATTERN, url))

def validate_email_content(content):
    """Validate email content"""
    if not content or not isinstance(content, str):
        return False
    
    # Basic validation - content should not be empty
    # In a real app, you'd do more sophisticated validation
    return len(content.strip()) > 0

def sanitize_url(url):
    """Sanitize a URL string"""
    if not url or not isinstance(url, str):
        return ""
    
    # Basic sanitization
    # Remove whitespace and common script tags
    sanitized = url.strip()
    sanitized = re.sub(r'<script.*?>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized

def sanitize_email_content(content):
    """Sanitize email content"""
    if not content or not isinstance(content, str):
        return ""
    
    # Basic sanitization
    # Remove script tags and other potentially dangerous content
    sanitized = content.strip()
    sanitized = re.sub(r'<script.*?>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    return sanitized