/**
 * API Client for PhishGuard Extension
 * Handles communication with the phishing detection API
 */

class PhishGuardAPI {
    constructor() {
      // Base URL for the API - will be configurable in settings
      this.baseUrl = 'https://api.phishguard.example.com/v1';
      
      // Default request timeout (ms)
      this.timeout = 5000;
      // JWT Token storage
      this.token = null;
      // Initialize with stored configuration if available
      this.loadConfig();
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
        // Load auth token if available
        if (result.authToken) {
          this.token = result.authToken;
        }  
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
     * Log in to the API and get a token
     */
    async login(email, password) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    
        const response = await fetch(`${this.baseUrl}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            email,
            password
          }),
          signal: controller.signal
        });
    
        clearTimeout(timeoutId);
    
        if (response.ok) {
          const data = await response.json();
          this.token = data.token;
      
         // Save token to storage
          await chrome.storage.local.set({ authToken: data.token });
      
          return {
            success: true,
            userId: data.user_id,
            expiresIn: data.expires_in
          };
        } else {
          const errorData = await response.json().catch(() => ({}));
          if (response.status === 401) {
            throw PhishGuardError.authFailed(errorData.error?.message || 'Invalid credentials');
          } else {
            throw PhishGuardError.unknown(errorData.error?.message || `Login failed: ${response.status}`);
          }
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw PhishGuardError.apiTimeout('Login request timed out');
        }

        // If it's already a PhishGuardError, rethrow it
        if (error instanceof PhishGuardError) {
        throw error;
      }

      // Otherwise, wrap in a PhishGuardError
      throw PhishGuardError.unknown(error.message);
    } }

    /**
     * Check if we have a valid authentication token
     */
    isAuthenticated() {
      return Boolean(this.token);
    }

    /**
     * Create headers with authentication token
    */
    getAuthHeaders() {
      const headers = {
        'Content-Type': 'application/json'
      };
  
      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }
  
      return headers;
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
       // Check authentication
       if (!this.isAuthenticated()) {
        throw PhishGuardError.authRequired();
      }
      
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
           // Handle authentication errors
           if (response.status === 401) {
             // Clear invalid token
             this.token = null;
             await chrome.storage.local.remove('authToken');
             throw PhishGuardError.tokenExpired();
            }
          
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
    } }
    
    /**
     * Analyze email content for phishing indicators
     */
    async analyzeEmail(content) {
      // Check authentication
      if (!this.isAuthenticated()) {
        throw PhishGuardError.authRequired();
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
            email_content: content,
            scan_type: 'REALTIME'
          }),
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          return await response.json();
        } else {
          // Handle authentication errors
          if (response.status === 401) {
            // Clear invalid token
            this.token = null;
            await chrome.storage.local.remove('authToken');
            throw PhishGuardError.tokenExpired();
          }

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
      // Check authentication
      if (!this.isAuthenticated()) {
        throw PhishGuardError.authRequired();
      }

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
          // Handle authentication errors
          if (response.status === 401) {
             // Clear invalid token
            this.token = null;
            await chrome.storage.local.remove('authToken');
            throw PhishGuardError.tokenExpired();
          }

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