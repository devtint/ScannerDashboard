/**
 * Security Scanner Platform - Main JavaScript
 * Handles all client-side logic for the security scanning dashboard
 */

/**
 * Main Alpine.js component for the security scanner
 * @returns {Object} Alpine.js component
 */
function securityScanner() {
    return {
        // Data properties
        scanUrl: '',
        selectedScanners: [],
        availableScanners: [],
        recentScans: [],
        stats: {
            total_scans: 0,
            scans_today: 0,
            average_security_score: 0
        },
        scanning: false,
        scanProgress: { completed: 0, total: 0 },
        scanMessages: [],
        showModal: false,
        selectedScan: null,
        ws: null,

        /**
         * Initialize the component
         * Called when Alpine.js initializes the component
         */
        async init() {
            await this.loadScanners();
            await this.loadRecentScans();
            await this.loadStatistics();
            this.connectWebSocket();
        },

        /**
         * Load available scanners from the API
         */
        async loadScanners() {
            try {
                const response = await fetch('/api/scanners');
                const data = await response.json();
                this.availableScanners = data.scanners;
            } catch (error) {
                console.error('Failed to load scanners:', error);
                this.showNotification('Failed to load scanners', 'error');
            }
        },

        /**
         * Select all available scanners
         */
        selectAllScanners() {
            this.selectedScanners = this.availableScanners.map(s => s.id);
        },

        /**
         * Start a new security scan
         */
        async startScan() {
            // Validation
            if (!this.scanUrl) {
                alert('Please enter a URL');
                return;
            }

            if (this.selectedScanners.length === 0) {
                alert('Please select at least one scanner');
                return;
            }

            // Initialize scanning state
            this.scanning = true;
            this.scanProgress = { completed: 0, total: this.selectedScanners.length };
            this.scanMessages = ['Initiating scan...'];

            try {
                // Prepare form data
                const formData = new FormData();
                formData.append('url', this.scanUrl);
                formData.append('scanner_names', this.selectedScanners.join(','));

                // Send scan request
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    this.scanMessages.push('Scan started successfully');
                } else {
                    const error = await response.json();
                    throw new Error(error.detail || 'Scan request failed');
                }
            } catch (error) {
                console.error('Scan failed:', error);
                alert(`Failed to start scan: ${error.message}`);
                this.scanning = false;
            }
        },

        /**
         * Load recent scans from the API
         * @param {number} limit - Maximum number of scans to load
         */
        async loadRecentScans(limit = 20) {
            try {
                const response = await fetch(`/api/scans/recent?limit=${limit}`);
                const data = await response.json();
                this.recentScans = data.scans;
            } catch (error) {
                console.error('Failed to load scans:', error);
            }
        },

        /**
         * Load platform statistics
         */
        async loadStatistics() {
            try {
                const response = await fetch('/api/statistics');
                const data = await response.json();
                this.stats = data;
            } catch (error) {
                console.error('Failed to load statistics:', error);
            }
        },

        /**
         * View detailed results for a specific scan
         * @param {number} scanId - ID of the scan to view
         */
        async viewScanDetails(scanId) {
            try {
                const response = await fetch(`/api/scans/${scanId}`);
                
                if (!response.ok) {
                    throw new Error('Failed to load scan details');
                }
                
                this.selectedScan = await response.json();
                this.showModal = true;
            } catch (error) {
                console.error('Failed to load scan details:', error);
                alert('Failed to load scan details');
            }
        },

        /**
         * Connect to WebSocket for real-time updates
         */
        connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            
            try {
                this.ws = new WebSocket(wsUrl);

                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                };

                this.ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };

                this.ws.onclose = () => {
                    console.log('WebSocket disconnected, reconnecting in 3s...');
                    setTimeout(() => this.connectWebSocket(), 3000);
                };
            } catch (error) {
                console.error('Failed to connect WebSocket:', error);
            }
        },

        /**
         * Handle incoming WebSocket messages
         * @param {Object} data - Message data
         */
        handleWebSocketMessage(data) {
            if (data.type === 'scan_completed') {
                this.scanProgress.completed++;
                this.scanMessages.push(`✓ ${data.scanner} completed`);
                
                // Check if all scans are complete
                if (this.scanProgress.completed === this.scanProgress.total) {
                    this.scanning = false;
                    this.scanMessages.push('All scans completed!');
                    this.loadRecentScans();
                    this.loadStatistics();
                    this.showNotification('All scans completed successfully!', 'success');
                }
            } else if (data.type === 'scan_failed') {
                this.scanProgress.completed++;
                this.scanMessages.push(`✗ ${data.scanner} failed: ${data.error || 'Unknown error'}`);
                
                // Check if all scans are complete (including failures)
                if (this.scanProgress.completed === this.scanProgress.total) {
                    this.scanning = false;
                    this.loadRecentScans();
                    this.loadStatistics();
                }
            } else if (data.type === 'scan_progress') {
                this.scanMessages.push(data.message);
            }
        },

        /**
         * Format date string to localized format
         * @param {string} dateString - ISO date string
         * @returns {string} Formatted date string
         */
        formatDate(dateString) {
            if (!dateString) return 'N/A';
            
            const date = new Date(dateString);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },

        /**
         * Get color class based on security score
         * @param {number} score - Security score (0-100)
         * @returns {string} Tailwind CSS color class
         */
        getScoreColor(score) {
            if (score >= 80) return 'text-green-600';
            if (score >= 60) return 'text-yellow-600';
            if (score >= 40) return 'text-orange-600';
            return 'text-red-600';
        },

        /**
         * Get background color class based on security score
         * @param {number} score - Security score (0-100)
         * @returns {string} Tailwind CSS background color class
         */
        getScoreBgColor(score) {
            if (score >= 80) return 'bg-green-100';
            if (score >= 60) return 'bg-yellow-100';
            if (score >= 40) return 'bg-orange-100';
            return 'bg-red-100';
        },

        /**
         * Show notification (for future toast implementation)
         * @param {string} message - Notification message
         * @param {string} type - Notification type (success, error, warning, info)
         */
        showNotification(message, type = 'info') {
            // Placeholder for future toast notification system
            console.log(`[${type.toUpperCase()}] ${message}`);
        },

        /**
         * Export scan results (for future implementation)
         * @param {number} scanId - ID of the scan to export
         * @param {string} format - Export format (json, csv, pdf)
         */
        async exportScan(scanId, format = 'json') {
            try {
                const response = await fetch(`/api/scans/${scanId}/export?format=${format}`);
                
                if (!response.ok) {
                    throw new Error('Export failed');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan-${scanId}.${format}`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Export failed:', error);
                alert('Failed to export scan results');
            }
        },

        /**
         * Delete a scan record
         * @param {number} scanId - ID of the scan to delete
         */
        async deleteScan(scanId) {
            if (!confirm('Are you sure you want to delete this scan?')) {
                return;
            }
            
            try {
                const response = await fetch(`/api/scans/${scanId}`, {
                    method: 'DELETE'
                });
                
                if (!response.ok) {
                    throw new Error('Failed to delete scan');
                }
                
                // Close modal if open
                if (this.showModal && this.selectedScan?.id === scanId) {
                    this.closeModal();
                }
                
                // Reload scans
                await this.loadRecentScans();
                await this.loadStatistics();
                
                this.showNotification('Scan deleted successfully', 'success');
            } catch (error) {
                console.error('Failed to delete scan:', error);
                alert('Failed to delete scan');
            }
        },

        /**
         * Re-run the exact same scan
         * @param {number} scanId - ID of the scan to re-run
         */
        async rescan(scanId) {
            try {
                const response = await fetch(`/api/scans/${scanId}/rescan`, {
                    method: 'POST'
                });
                
                if (!response.ok) {
                    throw new Error('Failed to start rescan');
                }
                
                const data = await response.json();
                
                // Update UI to show scanning state
                this.scanning = true;
                this.scanProgress = { completed: 0, total: 1 };
                this.scanMessages = [`Re-scanning ${data.url} with ${data.scanner}...`];
                
                // Close modal
                this.closeModal();
                
                this.showNotification('Rescan started successfully', 'success');
            } catch (error) {
                console.error('Failed to start rescan:', error);
                alert('Failed to start rescan');
            }
        },

        /**
         * Close modal
         */
        closeModal() {
            this.showModal = false;
            this.selectedScan = null;
        }
    };
}

/**
 * Utility functions
 */

// Format duration in seconds to human-readable format
function formatDuration(seconds) {
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
    if (seconds < 60) return `${seconds.toFixed(2)}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = (seconds % 60).toFixed(0);
    return `${minutes}m ${remainingSeconds}s`;
}

// Copy text to clipboard
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        return false;
    }
}

// Download text as file
function downloadTextFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Validate URL format
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Export utilities for use in HTML
window.scannerUtils = {
    formatDuration,
    copyToClipboard,
    downloadTextFile,
    isValidUrl,
    debounce
};
