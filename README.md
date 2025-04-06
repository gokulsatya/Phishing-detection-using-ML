# PhishGuard: ML-Powered Phishing Detection System

PhishGuard is a comprehensive phishing detection solution that combines machine learning, browser extension technology, and API services to protect users from phishing attempts in real-time.

## Features

- **Real-time URL Analysis**: Detects suspicious URLs and warns users before they interact with potentially malicious websites
- **Email Content Scanning**: Analyzes email content for phishing indicators in popular webmail services
- **Chrome Extension**: Seamless integration with Chrome browser for real-time protection
- **Machine Learning Backend**: Employs both Random Forest and LSTM models for high-accuracy detection
- **Secure API**: Flask-based REST API with robust security measures and rate limiting

## Architecture

The system consists of two main components:

1. **Chrome Extension (Frontend)**
   - Real-time DOM scanning for suspicious content
   - Background service worker for continuous protection
   - User-friendly popup interface with threat visualization
   - Secure communication with backend API

2. **Flask API (Backend)**
   - ML-powered phishing detection endpoints
   - JWT authentication and request validation
   - Usage telemetry and feedback collection
   - Robust error handling and rate limiting

## Technical Stack

- **Frontend**: JavaScript, HTML/CSS
- **Backend**: Python 3.10+, Flask
- **Machine Learning**: TensorFlow (LSTM), scikit-learn (Random Forest)
- **Security**: JWT, TLS 1.3, input validation/sanitization
- **Testing**: pytest, Jest

## Installation

### Chrome Extension

1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the `chrome-extension` directory

### Flask API

1. Navigate to the `flask-api` directory
2. Create a virtual environment: `python -m venv venv`
3. Activate the environment:
   - Windows: `venv\Scripts\activate`
   - Unix/MacOS: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run the API: `python run.py`

## Configuration

- Edit `.env` file to configure API settings
- Modify extension settings through the options page

## Security Features

- TLS 1.3 encryption for API communication
- JWT-based authentication with automatic token refresh
- Input validation and sanitization
- Rate limiting to prevent abuse
- Content security policies via Flask-Talisman

## License

MIT
