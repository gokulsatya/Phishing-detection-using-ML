import re
from datetime import datetime
import uuid
import numpy as np
from urllib.parse import urlparse
import joblib
import os

class PhishingModel:
    """Interface to the phishing detection ML model"""
    
    def __init__(self):
        """Initialize the model"""
        # This will be expanded later to load the actual trained model
        self.model_version = "1.0.0"
        self.is_ready = True

        # Add this list of suspicious terms
        self.suspicious_terms = [
        'login', 'verify', 'account', 'banking', 'update', 'security',
        'password', 'confirm', 'bank', 'paypal', 'credit', 'secure'
        ]
    
        print(f"Phishing model initialized: version {self.model_version}")
    
    def extract_url_features(self, url):
       """Extract features from URL for phishing detection"""
       features = {}
    
       try:
           parsed_url = urlparse(url)
        
           # Domain based features
           domain = parsed_url.netloc
           features['domain_length'] = len(domain)
           features['has_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
           features['has_at_symbol'] = 1 if '@' in url else 0
           features['has_double_slash'] = 1 if '//' in parsed_url.path else 0
           features['domain_dash_count'] = domain.count('-')
           features['domain_subdomain_count'] = domain.count('.') - 1 if '.' in domain else 0
        
           # Path based features
           features['path_length'] = len(parsed_url.path)
           features['has_suspicious_path'] = 0
           for term in self.suspicious_terms:
               if term in parsed_url.path.lower():
                   features['has_suspicious_path'] = 1
                   break
        
            # Query parameters
           features['query_length'] = len(parsed_url.query)
           features['has_suspicious_query'] = 0
           for term in self.suspicious_terms:
               if term in parsed_url.query.lower():
                   features['has_suspicious_query'] = 1
                   break
        
           return features
        
       except Exception as e:
           print(f"Error extracting URL features: {e}")
           # Return default features on error
           return {
               'domain_length': 0, 'has_ip_address': 0, 'has_at_symbol': 0,
               'has_double_slash': 0, 'domain_dash_count': 0, 'domain_subdomain_count': 0,
               'path_length': 0, 'has_suspicious_path': 0, 'query_length': 0,
               'has_suspicious_query': 0
            }

    def extract_email_features(self, content):
       """Extract features from email content for phishing detection"""
       features = {}
    
       try:
           # Length based features
           features['content_length'] = len(content)
        
           # Suspicious content features
           features['has_urgent_language'] = 1 if re.search(r'urgent|immediate|alert|attention|important', content.lower()) else 0
           features['has_action_language'] = 1 if re.search(r'click|download|confirm|verify|validate|update', content.lower()) else 0
           features['has_threat_language'] = 1 if re.search(r'suspend|cancel|terminate|delete|blocked|unauthorized', content.lower()) else 0
        
           # Link features
           features['url_count'] = len(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content))
        
           # Personal info request features
           features['has_credential_request'] = 1 if re.search(r'password|login|credential|username', content.lower()) else 0
           features['has_personal_info_request'] = 1 if re.search(r'ssn|social security|credit card|billing|address', content.lower()) else 0
        
           return features
        
       except Exception as e:
           print(f"Error extracting email features: {e}")
           # Return default features on error
           return {
               'content_length': 0, 'has_urgent_language': 0, 'has_action_language': 0,
               'has_threat_language': 0, 'url_count': 0, 'has_credential_request': 0,
               'has_personal_info_request': 0
            }

    def predict(self, content=None, url=None, metadata=None):
       """
       Make prediction based on content, URL, or metadata
       Returns prediction result with confidence score
       """
       # Create result structure
       result = {
           "prediction": "legitimate",
           "confidence": 0.5,
           "scan_id": str(uuid.uuid4()),
           "scan_time": datetime.utcnow().isoformat() + "Z",
           "features_analyzed": []
        }
    
        # Rule-based scoring system (would be ML model in production)
       score = 0.0
       feature_count = 0
       features_analyzed = []
    
       # URL analysis
       if url:
           features_analyzed.append("url_analysis")
           url_features = self.extract_url_features(url)
        
           # Simple scoring based on features (replace with ML model prediction)
           if url_features['has_ip_address']:
               score += 0.25
           if url_features['has_at_symbol']:
               score += 0.2
           if url_features['has_double_slash']:
               score += 0.15
           if url_features['domain_length'] > 30:
               score += 0.15
           if url_features['domain_dash_count'] > 2:
               score += 0.1
           if url_features['domain_subdomain_count'] > 3:
               score += 0.15
           if url_features['has_suspicious_path']:
               score += 0.2
           if url_features['has_suspicious_query']:
               score += 0.1
        
           feature_count += 8
    
       # Email content analysis
       if content:
           features_analyzed.append("content_analysis")
           email_features = self.extract_email_features(content)
        
           # Simple scoring based on features (replace with ML model prediction)
           if email_features['has_urgent_language']:
               score += 0.15
           if email_features['has_action_language']:
               score += 0.1
           if email_features['has_threat_language']:
               score += 0.2
           if email_features['url_count'] > 3:
               score += 0.15
           if email_features['has_credential_request']:
               score += 0.25
           if email_features['has_personal_info_request']:
               score += 0.2
        
           feature_count += 6
    
       # Calculate final score and prediction
       if feature_count > 0:
           normalized_score = score / feature_count
        
           if normalized_score > 0.15:
               result["prediction"] = "phishing"
               # Scale confidence between 0.6 and 0.95 based on score
               result["confidence"] = 0.6 + (normalized_score * 0.35)
           else:
               result["prediction"] = "legitimate"
               # Scale confidence between 0.6 and 0.9
               result["confidence"] = 0.6 + ((1 - normalized_score) * 0.3)
    
       result["features_analyzed"] = features_analyzed
       return result