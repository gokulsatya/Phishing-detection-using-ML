/**
 * API Client for PhishGuard Extension
 * Handles communication with the phishing detection API
 * Modified to bypass authentication requirements
 */
// Add this near the top of api-client.js
if (typeof PhishGuardError === 'undefined') {
  // Create a simple fallback error class if the real one isn't loaded
  class PhishGuardError extends Error {
    constructor(code, message) {
      super(message || 'An error occurred');
      this.code = code;
      this.name = 'PhishGuardError';
    }
    
    static authFailed(message) {
      return new PhishGuardError(2002, message || 'Authentication failed');
    }
    
    static unknown(message) {
      return new PhishGuardError(9999, message || 'Unknown error occurred');
    }
  }
  
  // Make it globally available
  window.PhishGuardError = PhishGuardError;
}
class PhishGuardAPI {
    constructor() {
      // Base URL for the API - will be configurable in settings
      this.baseUrl = 'http://127.0.0.1:5000/v1';
      
      // Default request timeout (ms)
      this.timeout = 5000;
      // JWT Token storage - automatically set to a dummy value
      this.token = "dummy-token-auth-bypass";
      // Initialize with stored configuration if available
      this.loadConfig();
      
      // Store dummy token in storage
      chrome.storage.local.set({ authToken: this.token });
      console.log("PhishGuard API initialized in auth-bypass mode");
    }
    
    /**
     * Load API configuration from storage
     */
    async loadConfig() {
      try {
        const result = await chrome.storage.local.get(['phishguardConfig']);
        if (result.phishguardConfig) {
          this.baseUrl = result.phishguardConfig.apiUrl || this.baseUrl;
          this.timeout = result.phishguardConfig.timeout || this.timeout;
        }
        // Always set token regardless of stored value
        this.token = "dummy-token-auth-bypass";
      } catch (error) {
        console.error('Failed to load API config:', error);
      }
    }
    
    /**
     * Save API configuration to storage
     */
    async saveConfig(config) {
      try {
        await chrome.storage.local.set({ 
          phishguardConfig: {
            apiUrl: config.apiUrl || this.baseUrl,
            timeout: config.timeout || this.timeout
          }
        });
        
        // Update current instance
        this.baseUrl = config.apiUrl || this.baseUrl;
        this.timeout = config.timeout || this.timeout;
        
        return true;
      } catch (error) {
        console.error('Failed to save API config:', error);
        return false;
      }
    }

    /**
     * Always succeeds without contacting API
     * Bypasses real login for testing
     */
    async login(email, password) {
      console.log("Login bypassed for testing");
      // Save dummy token to storage
      await chrome.storage.local.set({ authToken: this.token });
      
      return {
        success: true,
        userId: "test-user-123",
        expiresIn: 9999999
      };
    }

    /**
     * Always returns true to bypass authentication check
     */
    isAuthenticated() {
      return true;
    }

    /**
     * Create headers without authentication
     */
    getAuthHeaders() {
      return {
        'Content-Type': 'application/json'
      };
    }
    
    /**
     * Check API health/availability
     */
    async checkHealth() {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(`${this.baseUrl}/health`, {
          method: 'GET',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          const data = await response.json();
          return {
            status: 'online',
            version: data.version || 'unknown',
            message: 'API is available'
          };
        } else {
          return {
            status: 'error',
            message: `API returned status ${response.status}`
          };
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          return {
            status: 'timeout',
            message: 'API request timed out'
          };
        }
        
        return {
          status: 'offline',
          message: error.message || 'Could not connect to API'
        };
      }
    }
    
    /**
     * Analyze URL for phishing indicators
     */
    async analyzeUrl(url) {
      // Add URL validation here if you have validators available
      if (window.validators && !window.validators.isValidUrl(url)) {
        throw PhishGuardError.invalidUrl();
      }

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(`${this.baseUrl}/predict`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            url: url,
            scan_type: 'REALTIME'
          }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          return await response.json();
        } else {
          // Simplified error handling
          const errorData = await response.json().catch(() => ({}));
          throw PhishGuardError.unknown(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw PhishGuardError.apiTimeout();
        }
        // If it's already a PhishGuardError, rethrow it
        if (error instanceof PhishGuardError) {
          throw error;
        }
        // Otherwise, wrap in a PhishGuardError
        throw PhishGuardError.networkFailure(error.message);
      }
    }
    
    /**
     * Analyze email content for phishing indicators
     */
    async analyzeEmail(content) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(`${this.baseUrl}/predict`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            email_content: content,
            scan_type: 'REALTIME'
          }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          return await response.json();
        } else {
          // Simplified error handling
          const errorData = await response.json().catch(() => ({}));
          throw PhishGuardError.unknown(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw PhishGuardError.apiTimeout();
        }
        // If it's already a PhishGuardError, rethrow it
        if (error instanceof PhishGuardError) {
          throw error;
        }
  
        // Otherwise, wrap in a PhishGuardError
        throw PhishGuardError.networkFailure(error.message);
      }
    }
    
    /**
     * Submit user feedback about a detection result
     */
    async submitFeedback(scanId, isCorrect, userComment = '') {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        
        const response = await fetch(`${this.baseUrl}/feedback`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            scan_id: scanId,
            is_correct: isCorrect,
            comment: userComment
          }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          return await response.json();
        } else {
          // Simplified error handling
          const errorData = await response.json().catch(() => ({}));
          throw PhishGuardError.unknown(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw PhishGuardError.apiTimeout();
        }
        // If it's already a PhishGuardError, rethrow it
        if (error instanceof PhishGuardError) {
          throw error;
        }
  
        // Otherwise, wrap in a PhishGuardError
        throw PhishGuardError.networkFailure(error.message);
      }
    }
  }
  
  // Create global instance for use throughout the extension
  window.phishGuardAPI = new PhishGuardAPI();