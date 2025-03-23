import re
from datetime import datetime
import uuid
import numpy as np
from urllib.parse import urlparse
import joblib
import os
# Try importing TensorFlow with fallback
try:
    import tensorflow as tf
    from tensorflow import keras
    TENSORFLOW_AVAILABLE = True
except ImportError:
    print("WARNING: TensorFlow not available - LSTM model will be disabled")
    TENSORFLOW_AVAILABLE = False


class PhishingModel:
    """Interface to the phishing detection ML models"""
    
    def __init__(self):
        """Initialize both Random Forest and LSTM models"""
        # Define model paths
        base_path = os.path.join(os.path.dirname(__file__), '../data/models/')
        os.makedirs(base_path, exist_ok=True)
        
        self.rf_model_path = os.path.join(base_path, 'rf_model.pkl')
        self.tfidf_path = os.path.join(base_path, 'tfidf.pkl')
        
        # Only set LSTM paths if TensorFlow is available
        if TENSORFLOW_AVAILABLE:
            self.lstm_model_path = os.path.join(base_path, 'lstm_model.h5')
            self.tokenizer_path = os.path.join(base_path, 'tokenizer.pkl')
        
        # Load models
        self.rf_model = None
        self.tfidf_vectorizer = None
        self.lstm_model = None
        self.tokenizer = None
        
        # Try to load Random Forest model
        try:
            self.rf_model = joblib.load(self.rf_model_path)
            self.tfidf_vectorizer = joblib.load(self.tfidf_path)
            print("Random Forest model loaded successfully")
        except Exception as e:
            print(f"Error loading Random Forest model: {e}")
        
        # Try to load LSTM model
        if TENSORFLOW_AVAILABLE:
            try:
                self.lstm_model = keras.models.load_model(self.lstm_model_path)
                self.tokenizer = joblib.load(self.tokenizer_path)
                print("LSTM model loaded successfully")
            except Exception as e:
                print(f"Error loading LSTM model: {e}")
        
        self.model_version = "1.0.0"
        self.is_ready = (self.rf_model is not None and self.tfidf_vectorizer is not None) or \
                        (self.lstm_model is not None and self.tokenizer is not None)
        
        # Suspicious terms list for feature extraction
        self.suspicious_terms = [
            'login', 'verify', 'account', 'banking', 'update', 'security',
            'password', 'confirm', 'bank', 'paypal', 'credit', 'secure'
        ]
        
        print(f"Phishing model initialized: version {self.model_version}")
        print(f"Models loaded: RF={self.rf_model is not None}, LSTM={self.lstm_model is not None}")
        print(f"System status: {'ready' if self.is_ready else 'fallback mode'}")
    
    def extract_features_for_rf(self, content=None, url=None):
        """Extract and prepare features for Random Forest model"""
        if not self.tfidf_vectorizer:
            return None
        
        # Prepare input text based on available data
        text = ""
        if url:
            text += url + " "
        if content:
            text += content
        
        if not text.strip():
            return None
        
        # Use TF-IDF vectorizer to transform text
        features = self.tfidf_vectorizer.transform([text])
        return features
    
    def extract_features_for_lstm(self, content=None, url=None):
        """Extract and prepare features for LSTM model"""
        if not self.tokenizer:
            return None
        
        # Prepare input text based on available data
        text = ""
        if url:
            text += url + " "
        if content:
            text += content
        
        if not text.strip():
            return None
        
        # Tokenize and pad the text
        max_length = 200  # Adjust this to match your LSTM model's expected input length
        sequences = self.tokenizer.texts_to_sequences([text])
        padded_sequences = keras.preprocessing.sequence.pad_sequences(
            sequences, maxlen=max_length, padding='post'
        )
        return padded_sequences
    
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
        Make prediction using ensemble of models
        Returns prediction result with confidence score
        """
        # Create result structure
        result = {
            "prediction": "legitimate",
            "confidence": 0.5,
            "scan_id": str(uuid.uuid4()),
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "features_analyzed": [],
            "model_used": "fallback"
        }
        
        # If models are loaded, use them for prediction
        rf_prediction = None
        rf_confidence = None
        lstm_prediction = None
        lstm_confidence = None
        
        # Try Random Forest prediction
        if self.rf_model is not None and self.tfidf_vectorizer is not None:
            try:
                rf_features = self.extract_features_for_rf(content, url)
                if rf_features is not None:
                    # Get prediction (0 = legitimate, 1 = phishing)
                    rf_prediction = int(self.rf_model.predict(rf_features)[0])
                    
                    # Get confidence scores
                    rf_probs = self.rf_model.predict_proba(rf_features)[0]
                    rf_confidence = rf_probs[rf_prediction]
                    
                    result["features_analyzed"].append("text_patterns")
            except Exception as e:
                print(f"Error in Random Forest prediction: {e}")
        
        # Try LSTM prediction
        if self.lstm_model is not None and self.tokenizer is not None:
            try:
                lstm_features = self.extract_features_for_lstm(content, url)
                if lstm_features is not None:
                    # Get prediction (value between 0 and 1, where >0.5 is phishing)
                    lstm_raw_prediction = self.lstm_model.predict(lstm_features)[0][0]
                    lstm_prediction = 1 if lstm_raw_prediction > 0.5 else 0
                    
                    # Get confidence
                    if lstm_prediction == 1:
                        lstm_confidence = float(lstm_raw_prediction)
                    else:
                        lstm_confidence = 1.0 - float(lstm_raw_prediction)
                    
                    result["features_analyzed"].append("sequential_patterns")
            except Exception as e:
                print(f"Error in LSTM prediction: {e}")
        
        # Combine predictions if both models worked
        if rf_prediction is not None and lstm_prediction is not None:
            # We have both predictions, use ensemble
            result["model_used"] = "ensemble"
            
            # Weight the models (adjust based on your model performance)
            rf_weight = 0.6
            lstm_weight = 0.4
            
            # Calculate weighted vote
            ensemble_score = (rf_prediction * rf_weight) + (lstm_prediction * lstm_weight)
            ensemble_confidence = (rf_confidence * rf_weight) + (lstm_confidence * lstm_weight)
            
            # Set final prediction
            if ensemble_score >= 0.5:
                result["prediction"] = "phishing"
            else:
                result["prediction"] = "legitimate"
                
            result["confidence"] = ensemble_confidence
        
        # If only one model worked, use its prediction
        elif rf_prediction is not None:
            result["model_used"] = "random_forest"
            result["prediction"] = "phishing" if rf_prediction == 1 else "legitimate"
            result["confidence"] = rf_confidence
        
        elif lstm_prediction is not None:
            result["model_used"] = "lstm"
            result["prediction"] = "phishing" if lstm_prediction == 1 else "legitimate"
            result["confidence"] = lstm_confidence
        
        # If no ML models worked, use the rule-based approach
        else:
            # URL analysis
            if url:
                result["features_analyzed"].append("url_analysis")
                url_features = self.extract_url_features(url)
                
                # Simple scoring based on features
                score = 0.0
                feature_count = 0
                
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
                result["features_analyzed"].append("content_analysis")
                email_features = self.extract_email_features(content)
                
                # Simple scoring based on features
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
        
        return result