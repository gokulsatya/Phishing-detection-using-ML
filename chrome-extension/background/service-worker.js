// Background service worker for PhishGuard extension

// Initialize extension state
let state = {
    enabled: true,
    lastScan: null,
    detectionCount: 0,
    apiEndpoint: 'https://api.phishguard.example.com/v1' // Will be configured properly later
  };
  
  // Load state from storage
  chrome.storage.local.get(['phishguardState'], (result) => {
    if (result.phishguardState) {
      state = { ...state, ...result.phishguardState };
    }
    
    // Save initial state if not present
    if (!result.phishguardState) {
      chrome.storage.local.set({ phishguardState: state });
    }
  });
  
  // Listen for navigation events to scan new pages
  chrome.webNavigation.onCompleted.addListener((details) => {
    // Only inject content scripts if extension is enabled
    if (state.enabled && details.frameId === 0) { // Main frame only
      chrome.scripting.executeScript({
        target: { tabId: details.tabId },
        files: ['content-scripts/dom-scanner.js']
      }).catch(error => {
        console.error('Failed to inject content script:', error);
      });
      
      // Update badge to show scanning
      chrome.action.setBadgeText({ 
        text: 'SCAN',
        tabId: details.tabId 
      });
      
      chrome.action.setBadgeBackgroundColor({ 
        color: '#4285F4',
        tabId: details.tabId 
      });
      
      // Reset badge after 3 seconds
      setTimeout(() => {
        chrome.action.setBadgeText({ 
          text: '',
          tabId: details.tabId 
        });
      }, 3000);
    }
  });
  
  // Listen for messages from content scripts
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SCAN_URL') {
      scanUrl(message.url, sender.tab.id)
        .then(result => {
          sendResponse(result);
          updateBadgeWithResult(result, sender.tab.id);
        })
        .catch(error => {
          console.error('Scan failed:', error);
          sendResponse({ error: 'Scan failed' });
        });
      
      // Keep the message channel open for the async response
      return true;
    }
    
    if (message.type === 'SCAN_EMAIL') {
      scanEmail(message.content, sender.tab.id)
        .then(result => {
          sendResponse(result);
          updateBadgeWithResult(result, sender.tab.id);
        })
        .catch(error => {
          console.error('Email scan failed:', error);
          sendResponse({ error: 'Email scan failed' });
        });
      
      // Keep the message channel open for the async response
      return true;
    }
  });
  
  // Function to scan a URL
  async function scanUrl(url, tabId) {
    // In a real implementation, this would call our Flask API
    // For now, we'll use a simple placeholder
    console.log(`Scanning URL: ${url}`);
    
    try {
      // This will be replaced with actual API call
      // const response = await fetch(`${state.apiEndpoint}/predict`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ url, scan_type: 'REALTIME' })
      // });
      // const result = await response.json();
      
      // Placeholder result
      const result = {
        prediction: Math.random() > 0.8 ? 'phishing' : 'legitimate',
        confidence: 0.85 + (Math.random() * 0.1),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
      
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });
      
      return result;
    } catch (error) {
      console.error('Error scanning URL:', error);
      throw error;
    }
  }
  
  // Function to scan email content
  async function scanEmail(content, tabId) {
    console.log(`Scanning email content (length: ${content.length})`);
    
    try {
      // This will be replaced with actual API call
      // const response = await fetch(`${state.apiEndpoint}/predict`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ email_content: content, scan_type: 'REALTIME' })
      // });
      // const result = await response.json();
      
      // Placeholder result
      const result = {
        prediction: Math.random() > 0.7 ? 'phishing' : 'legitimate',
        confidence: 0.80 + (Math.random() * 0.15),
        scan_id: `scan-${Date.now()}`,
        scan_time: new Date().toISOString()
      };
      
      // Update last scan timestamp
      state.lastScan = new Date().toISOString();
      
      // Update counter if phishing detected
      if (result.prediction === 'phishing') {
        state.detectionCount++;
      }
      
      // Save state
      chrome.storage.local.set({ phishguardState: state });
      
      return result;
    } catch (error) {
      console.error('Error scanning email:', error);
      throw error;
    }
  }
  
  // Update badge based on scan result
  function updateBadgeWithResult(result, tabId) {
    if (result.prediction === 'phishing') {
      chrome.action.setBadgeText({ 
        text: '!',
        tabId: tabId 
      });
      
      chrome.action.setBadgeBackgroundColor({ 
        color: '#EA4335', // Red for phishing
        tabId: tabId 
      });
    } else {
      // Clear any previous warning for legitimate content
      setTimeout(() => {
        chrome.action.setBadgeText({ 
          text: '',
          tabId: tabId 
        });
      }, 3000);
    }
  }
  
  // Reset warning badges when navigating away
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
      chrome.action.setBadgeText({ 
        text: '',
        tabId: tabId 
      });
    }
  });