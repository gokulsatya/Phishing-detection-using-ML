/**
 * PhishGuard Extension Popup UI
 * Controls the UI interactions for the extension popup
 */

// DOM Elements
const enableToggle = document.getElementById('enable-toggle');
const extensionStatus = document.getElementById('extension-status');
const phishingCount = document.getElementById('phishing-count');
const lastScan = document.getElementById('last-scan');
const scanPageButton = document.getElementById('scan-page');
const viewSettingsButton = document.getElementById('view-settings');
const scanResults = document.getElementById('scan-results');
const scanVerdict = document.getElementById('scan-verdict');
const scanConfidence = document.getElementById('scan-confidence');
const scanFeatures = document.getElementById('scan-features');

// DOM elements for statistics
const statsDashboard = document.getElementById('stats-dashboard');
const totalScans = document.getElementById('total-scans');
const totalPhishing = document.getElementById('total-phishing');
const detectionRate = document.getElementById('detection-rate');
const daysActive = document.getElementById('days-active');
const viewResultsButton = document.getElementById('view-results');
const viewStatsButton = document.getElementById('view-stats');

// DOM elements for feedback
const thumbsUpButton = document.getElementById('thumbs-up');
const thumbsDownButton = document.getElementById('thumbs-down');
const feedbackMessage = document.getElementById('feedback-message');
const feedbackPanel = document.getElementById('feedback-panel');


// Extension state
let extensionState = {
  enabled: true,
  lastScan: null,
  detectionCount: 0
};

// Initialize the popup
document.addEventListener('DOMContentLoaded', async () => {
  // Check if authenticated
  const isAuthenticated = await window.phishGuardAPI.isAuthenticated();
  
  if (!isAuthenticated) {
    // Redirect to login page
    window.location.href = 'login.html';
    return;
  }
  // Load state from storage
  await loadState();
  updateUI();
  
  // Set up event listeners
  enableToggle.addEventListener('change', toggleExtension);
  scanPageButton.addEventListener('click', scanCurrentPage);
  viewSettingsButton.addEventListener('click', openSettings);
  // Set up additional event listeners
  viewResultsButton.addEventListener('click', showScanResults);
  viewStatsButton.addEventListener('click', showStatsDashboard);

  // Add event listeners for feedback buttons
  thumbsUpButton.addEventListener('click', () => submitUserFeedback(true));
  thumbsDownButton.addEventListener('click', () => submitUserFeedback(false));

  // Last scan result reference
  let lastScanResult = null;

  
  // Load statistics
  loadStatistics();
  // Check API health
  checkAPIHealth();
});

/**
 * Load extension state from storage
 */
async function loadState() {
  try {
    const result = await chrome.storage.local.get(['phishguardState']);
    if (result.phishguardState) {
      extensionState = result.phishguardState;
    }
  } catch (error) {
    console.error('Failed to load state:', error);
  }
}

/**
 * Save extension state to storage
 */
async function saveState() {
  try {
    await chrome.storage.local.set({ phishguardState: extensionState });
  } catch (error) {
    console.error('Failed to save state:', error);
  }
}

/**
 * Update UI elements based on current state
 */
function updateUI() {
  // Update toggle and status
  enableToggle.checked = extensionState.enabled;
  extensionStatus.textContent = extensionState.enabled ? 'Active' : 'Inactive';
  extensionStatus.className = extensionState.enabled ? 'status-value active' : 'status-value inactive';
  
  // Update stats
  phishingCount.textContent = extensionState.detectionCount || 0;
  
  if (extensionState.lastScan) {
    // Format date nicely
    const scanDate = new Date(extensionState.lastScan);
    const now = new Date();
    const diffMs = now - scanDate;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) {
      lastScan.textContent = 'Just now';
    } else if (diffMins < 60) {
      lastScan.textContent = `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
    } else {
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) {
        lastScan.textContent = `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
      } else {
        lastScan.textContent = scanDate.toLocaleDateString();
      }
    }
  } else {
    lastScan.textContent = 'Never';
  }
  
  // Enable/disable buttons based on extension state
  scanPageButton.disabled = !extensionState.enabled;
}

/**
 * Toggle extension enabled/disabled state
 */
async function toggleExtension(event) {
  extensionState.enabled = event.target.checked;
  await saveState();
  updateUI();
}

/**
 * Check API health and update UI accordingly
 */
async function checkAPIHealth() {
  try {
    const healthResult = await window.phishGuardAPI.checkHealth();
    
    if (healthResult.status === 'online') {
      console.log('API is online:', healthResult);
    } else {
      console.warn('API health check failed:', healthResult);
      // You could update UI to show API status here
    }
  } catch (error) {
    console.error('API health check error:', error);
  }
}

/**
 * Scan the current page for phishing indicators
 */
async function scanCurrentPage() {
  // Show loading state
  scanPageButton.textContent = 'Scanning...';
  scanPageButton.disabled = true;
  scanResults.classList.add('hidden');
  
  try {
    // Get current tab URL
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentTab = tabs[0];
    const url = currentTab.url;
    
    // Only scan http/https URLs
    if (!url.startsWith('http')) {
      throw new Error('Can only scan web pages');
    }
    
    // Send message to content script to get page content
    chrome.tabs.sendMessage(currentTab.id, { action: 'getPageContent' }, async (response) => {
      if (chrome.runtime.lastError) {
        // Content script not ready, inject it
        await chrome.scripting.executeScript({
          target: { tabId: currentTab.id },
          files: ['content-scripts/dom-scanner.js']
        });
        
        // Perform URL-only scan
        const result = await window.phishGuardAPI.analyzeUrl(url);
        displayResults(result);
      } else if (response && response.content) {
        // We have page content, analyze it
        const result = await window.phishGuardAPI.analyzeEmail(response.content);
        displayResults(result);
      } else {
        // Fallback to URL-only scan
        const result = await window.phishGuardAPI.analyzeUrl(url);
        displayResults(result);
      }
    });
  } catch (error) {
    console.error('Scan failed:', error);
    displayError(error.message);
  }
}

/**
 * Display scan results in the UI
 */
function displayResults(result) {
  // Update state
  extensionState.lastScan = new Date().toISOString();
  if (result.prediction === 'phishing') {
    extensionState.detectionCount++;
  }
  saveState();
  
  // Update UI
  scanPageButton.textContent = 'Scan Current Page';
  scanPageButton.disabled = false;
  
  // Show results
  scanResults.classList.remove('hidden');

  // Store scan result for feedback
  lastScanResult = result;

  // Show feedback panel
  feedbackPanel.classList.remove('hidden');
  feedbackMessage.classList.add('hidden');
  
  if (result.prediction === 'phishing') {
    scanVerdict.textContent = 'Likely Phishing';
    scanVerdict.className = 'result-value verdict-phishing';
  } else {
    scanVerdict.textContent = 'Likely Safe';
    scanVerdict.className = 'result-value verdict-safe';
  }
  
  // Format confidence as percentage
  const confidence = Math.round(result.confidence * 100);
  scanConfidence.textContent = `${confidence}%`;
  
  // Display analyzed features
  if (result.features_analyzed && result.features_analyzed.length > 0) {
    scanFeatures.textContent = result.features_analyzed.join(', ');
  } else {
    scanFeatures.textContent = 'Basic URL analysis';
  }
  
  updateUI();
}

/**
 * Display error message
 */
function displayError(message) {
  scanPageButton.textContent = 'Scan Current Page';
  scanPageButton.disabled = false;
  
  // Show error in results panel
  scanResults.classList.remove('hidden');
  scanVerdict.textContent = 'Error';
  scanVerdict.className = 'result-value verdict-phishing';
  scanConfidence.textContent = 'N/A';
  scanFeatures.textContent = message || 'Unknown error';
  
  updateUI();
}

/**
 * Open settings page
 */
function openSettings() {
  // For now, we'll just create a new tab with a placeholder
  // In a real implementation, this would open the extension's options page
  chrome.tabs.create({ url: 'options.html' });
}

// Function to show scan results panel
function showScanResults() {
  scanResults.classList.remove('hidden');
  statsDashboard.classList.add('hidden');
  viewResultsButton.disabled = true;
  viewStatsButton.disabled = false;
}

// Function to show statistics dashboard
function showStatsDashboard() {
  scanResults.classList.add('hidden');
  statsDashboard.classList.remove('hidden');
  viewResultsButton.disabled = false;
  viewStatsButton.disabled = true;
}

// Function to load and display statistics
async function loadStatistics() {
  try {
    // Get statistics from storage
    const result = await chrome.storage.local.get(['phishguardState', 'phishguardStats']);
    const state = result.phishguardState || {};
    const stats = result.phishguardStats || {};
    
    // Display statistics
    totalScans.textContent = stats.scansPerformed || 0;
    totalPhishing.textContent = stats.phishingDetected || 0;
    
    // Calculate detection rate
    if (stats.scansPerformed && stats.scansPerformed > 0) {
      const rate = (stats.phishingDetected / stats.scansPerformed * 100).toFixed(1);
      detectionRate.textContent = `${rate}%`;
    } else {
      detectionRate.textContent = 'N/A';
    }
    
    // Calculate days active
    if (stats.timeInstalled) {
      const installDate = new Date(stats.timeInstalled);
      const now = new Date();
      const diffTime = Math.abs(now - installDate);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      daysActive.textContent = diffDays;
    } else {
      daysActive.textContent = 'Unknown';
    }
    
    // If API is available, try to get server-side statistics
    if (window.phishGuardAPI && window.phishGuardAPI.isAuthenticated()) {
      fetchAPIStatistics();
    }
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

// Function to fetch API statistics
async function fetchAPIStatistics() {
  try {
    // Get auth token
    const result = await chrome.storage.local.get(['authToken']);
    const authToken = result.authToken;
    
    if (!authToken) {
      console.warn('No auth token available');
      return;
    }
    
    // Fetch statistics from API
    const apiEndpoint = (await chrome.storage.local.get(['phishguardConfig'])).phishguardConfig?.apiUrl || 'https://api.phishguard.example.com/v1';
    
    const response = await fetch(`${apiEndpoint}/stats`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (response.ok) {
      const apiStats = await response.json();
      console.log('API statistics:', apiStats);
      
      // Could display global statistics here if desired
    }
  } catch (error) {
    console.error('Error fetching API statistics:', error);
  }
}

// Function to submit user feedback
async function submitUserFeedback(isCorrect) {
  try {
    if (!lastScanResult || !lastScanResult.scan_id) {
      console.error('No scan result to submit feedback for');
      return;
    }
    
    // Disable buttons during submission
    thumbsUpButton.disabled = true;
    thumbsDownButton.disabled = true;
    
    // Submit feedback
    await window.phishGuardAPI.submitFeedback(
      lastScanResult.scan_id,
      isCorrect
    );
    
    // Show thank you message
    feedbackMessage.textContent = 'Thank you for your feedback!';
    feedbackMessage.classList.remove('hidden');
    
    // Re-enable buttons
    thumbsUpButton.disabled = false;
    thumbsDownButton.disabled = false;
    
    console.log('Feedback submitted successfully');
  } catch (error) {
    console.error('Error submitting feedback:', error);
    
    // Show error message
    feedbackMessage.textContent = 'Error submitting feedback. Please try again.';
    feedbackMessage.classList.remove('hidden');
    
    // Re-enable buttons
    thumbsUpButton.disabled = false;
    thumbsDownButton.disabled = false;
  }
}