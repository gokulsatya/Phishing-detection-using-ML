# Save to: flask-api/app/error_handlers.py

from flask import jsonify

def register_error_handlers(app):
    """Register global error handlers for the Flask app"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "error": {
                "code": "PHISH-400",
                "message": str(error) or "Bad request"
            }
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "error": {
                "code": "PHISH-401",
                "message": str(error) or "Authentication required"
            }
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "error": {
                "code": "PHISH-403",
                "message": str(error) or "Access forbidden"
            }
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": {
                "code": "PHISH-404",
                "message": str(error) or "Resource not found"
            }
        }), 404
    
    @app.errorhandler(422)
    def unprocessable_entity(error):
        return jsonify({
            "error": {
                "code": "PHISH-422",
                "message": str(error) or "Validation error"
            }
        }), 422
    
    @app.errorhandler(429)
    def too_many_requests(error):
        return jsonify({
            "error": {
                "code": "PHISH-429",
                "message": str(error) or "Too many requests",
                "retry_after": getattr(error, "retry_after", 60)
            }
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        # In production, you'd log the error here
        return jsonify({
            "error": {
                "code": "PHISH-500",
                "message": "Internal server error"
            }
        }), 500