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
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error('API request timed out');
        }
        throw error;
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
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error('API request timed out');
        }
        throw error;
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
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error?.message || `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          throw new Error('API request timed out');
        }
        throw error;
      }
    }
  }
  
  // Create global instance for use throughout the extension
  window.phishGuardAPI = new PhishGuardAPI();