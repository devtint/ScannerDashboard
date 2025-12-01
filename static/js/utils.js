/**
 * Security Scanner Platform - Utility Functions
 * Additional helper functions and constants
 */

// API Configuration
const API_CONFIG = {
    BASE_URL: '/api',
    ENDPOINTS: {
        SCANNERS: '/api/scanners',
        SCAN: '/api/scan',
        RECENT_SCANS: '/api/scans/recent',
        SCAN_DETAILS: '/api/scans',
        STATISTICS: '/api/statistics'
    },
    WEBSOCKET_URL: () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        return `${protocol}//${window.location.host}/ws`;
    }
};

// Severity levels and colors
const SEVERITY = {
    CRITICAL: {
        level: 'critical',
        color: '#dc2626',
        bgColor: '#fee2e2',
        label: 'Critical'
    },
    HIGH: {
        level: 'high',
        color: '#ef4444',
        bgColor: '#fef3c7',
        label: 'High'
    },
    MEDIUM: {
        level: 'medium',
        color: '#f59e0b',
        bgColor: '#fef3c7',
        label: 'Medium'
    },
    LOW: {
        level: 'low',
        color: '#3b82f6',
        bgColor: '#dbeafe',
        label: 'Low'
    },
    INFO: {
        level: 'info',
        color: '#10b981',
        bgColor: '#d1fae5',
        label: 'Info'
    }
};

// Format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Format number with commas
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// Calculate time ago
function timeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = {
        year: 31536000,
        month: 2592000,
        week: 604800,
        day: 86400,
        hour: 3600,
        minute: 60,
        second: 1
    };
    
    for (const [unit, secondsInUnit] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / secondsInUnit);
        if (interval >= 1) {
            return `${interval} ${unit}${interval > 1 ? 's' : ''} ago`;
        }
    }
    
    return 'just now';
}

// Sanitize URL
function sanitizeUrl(url) {
    if (!url) return '';
    
    // Add protocol if missing
    if (!url.match(/^https?:\/\//i)) {
        url = 'https://' + url;
    }
    
    try {
        const urlObj = new URL(url);
        return urlObj.href;
    } catch {
        return url;
    }
}

// Extract domain from URL
function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch {
        return url;
    }
}

// Color scale for security scores
function getSecurityScoreColor(score) {
    if (score >= 90) return { color: '#10b981', label: 'Excellent' };
    if (score >= 80) return { color: '#22c55e', label: 'Good' };
    if (score >= 70) return { color: '#84cc16', label: 'Fair' };
    if (score >= 60) return { color: '#eab308', label: 'Average' };
    if (score >= 50) return { color: '#f59e0b', label: 'Below Average' };
    if (score >= 40) return { color: '#f97316', label: 'Poor' };
    if (score >= 30) return { color: '#ef4444', label: 'Very Poor' };
    return { color: '#dc2626', label: 'Critical' };
}

// Group findings by severity
function groupBySeverity(findings) {
    return findings.reduce((acc, finding) => {
        const severity = finding.severity || 'info';
        if (!acc[severity]) {
            acc[severity] = [];
        }
        acc[severity].push(finding);
        return acc;
    }, {});
}

// Calculate severity score
function calculateSeverityScore(summary) {
    const weights = {
        critical: 10,
        high: 5,
        medium: 2,
        low: 1,
        info: 0
    };
    
    let totalWeight = 0;
    let totalIssues = 0;
    
    for (const [severity, count] of Object.entries(summary)) {
        if (weights[severity] !== undefined) {
            totalWeight += count * weights[severity];
            totalIssues += count;
        }
    }
    
    if (totalIssues === 0) return 100;
    
    // Calculate score (0-100, where 100 is best)
    const maxPossibleScore = totalIssues * weights.critical;
    const score = Math.max(0, 100 - (totalWeight / maxPossibleScore * 100));
    
    return Math.round(score);
}

// Local storage helpers
const storage = {
    set: (key, value) => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error('Failed to save to localStorage:', error);
            return false;
        }
    },
    
    get: (key, defaultValue = null) => {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('Failed to read from localStorage:', error);
            return defaultValue;
        }
    },
    
    remove: (key) => {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.error('Failed to remove from localStorage:', error);
            return false;
        }
    },
    
    clear: () => {
        try {
            localStorage.clear();
            return true;
        } catch (error) {
            console.error('Failed to clear localStorage:', error);
            return false;
        }
    }
};

// Export configuration for CSV
function exportToCSV(data, filename) {
    if (!data || data.length === 0) {
        console.error('No data to export');
        return;
    }
    
    // Get headers
    const headers = Object.keys(data[0]);
    
    // Create CSV content
    let csv = headers.join(',') + '\n';
    
    data.forEach(row => {
        const values = headers.map(header => {
            const value = row[header];
            // Escape commas and quotes
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                return `"${value.replace(/"/g, '""')}"`;
            }
            return value;
        });
        csv += values.join(',') + '\n';
    });
    
    // Download
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

// Generate report summary
function generateReportSummary(scan) {
    const summary = scan.summary || {};
    const totalIssues = Object.values(summary).reduce((a, b) => a + b, 0);
    
    return {
        target: scan.target_url,
        scanner: scan.scanner_name,
        date: new Date(scan.scan_date).toLocaleString(),
        duration: `${scan.duration.toFixed(2)}s`,
        score: scan.security_score,
        totalIssues,
        breakdown: summary
    };
}

// Keyboard shortcuts handler
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + K: Focus search/URL input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const urlInput = document.querySelector('input[type="url"]');
            if (urlInput) urlInput.focus();
        }
        
        // Escape: Close modal
        if (e.key === 'Escape') {
            const event = new CustomEvent('close-modal');
            window.dispatchEvent(event);
        }
        
        // Ctrl/Cmd + R: Refresh scans
        if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
            e.preventDefault();
            const event = new CustomEvent('refresh-scans');
            window.dispatchEvent(event);
        }
    });
}

// Initialize utilities on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initKeyboardShortcuts);
} else {
    initKeyboardShortcuts();
}

// Export all utilities
window.scannerUtilities = {
    API_CONFIG,
    SEVERITY,
    formatBytes,
    formatNumber,
    timeAgo,
    sanitizeUrl,
    extractDomain,
    getSecurityScoreColor,
    groupBySeverity,
    calculateSeverityScore,
    storage,
    exportToCSV,
    generateReportSummary
};
