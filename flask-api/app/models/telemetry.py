# Save to: flask-api/app/models/telemetry.py

import time
import threading
import json
from datetime import datetime
import os

class TelemetryManager:
    """Manages API usage telemetry and analytics"""
    
    def __init__(self):
        self.data = {
            "api_calls": 0,
            "phishing_detections": 0,
            "legitimate_detections": 0,
            "average_response_time": 0,
            "start_time": datetime.utcnow().isoformat() + "Z"
        }
        self.response_times = []
        self.max_response_times = 1000  # Store last 1000 response times
        self.lock = threading.Lock()
        self.telemetry_path = os.path.join(os.path.dirname(__file__), '../data/telemetry.json')
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.telemetry_path), exist_ok=True)
        
        # Load previous telemetry if it exists
        self._load_telemetry()
        
        # Start background thread to save telemetry periodically
        self.should_run = True
        self.save_thread = threading.Thread(target=self._background_save)
        self.save_thread.daemon = True
        self.save_thread.start()
    
    def record_prediction(self, result, response_time_ms):
        """Record a prediction result and its response time"""
        with self.lock:
            self.data["api_calls"] += 1
            
            if result.get("prediction") == "phishing":
                self.data["phishing_detections"] += 1
            else:
                self.data["legitimate_detections"] += 1
            
            # Update response times
            self.response_times.append(response_time_ms)
            if len(self.response_times) > self.max_response_times:
                self.response_times.pop(0)
            
            # Recalculate average
            if self.response_times:
                self.data["average_response_time"] = sum(self.response_times) / len(self.response_times)
    
    def get_statistics(self):
        """Get current telemetry statistics"""
        with self.lock:
            stats = self.data.copy()
            
            # Calculate percentage of phishing detections
            total_detections = stats["phishing_detections"] + stats["legitimate_detections"]
            if total_detections > 0:
                stats["phishing_percentage"] = (stats["phishing_detections"] / total_detections) * 100
            else:
                stats["phishing_percentage"] = 0
                
            # Add uptime
            start_time = datetime.fromisoformat(stats["start_time"].replace("Z", "+00:00"))
            uptime_seconds = (datetime.utcnow() - start_time).total_seconds()
            stats["uptime_hours"] = uptime_seconds / 3600
            
            return stats
    
    def _load_telemetry(self):
        """Load telemetry data from file"""
        try:
            if os.path.exists(self.telemetry_path):
                with open(self.telemetry_path, 'r') as f:
                    saved_data = json.load(f)
                    self.data.update(saved_data)
                    print(f"Loaded telemetry data: {self.data['api_calls']} API calls recorded")
            else:
                print("No telemetry data found, starting fresh")
        except Exception as e:
            print(f"Error loading telemetry: {e}")
    
    def _save_telemetry(self):
        """Save telemetry data to file"""
        try:
            with open(self.telemetry_path, 'w') as f:
                json.dump(self.data, f)
        except Exception as e:
            print(f"Error saving telemetry: {e}")
    
    def _background_save(self):
        """Background thread to periodically save telemetry"""
        while self.should_run:
            time.sleep(60)  # Save every minute
            self._save_telemetry()
    
    def shutdown(self):
        """Shutdown the telemetry manager and save data"""
        self.should_run = False
        self._save_telemetry()
        print("Telemetry manager shutdown, data saved")

# Create a global instance
telemetry_manager = TelemetryManager()