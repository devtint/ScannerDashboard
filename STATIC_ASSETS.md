# Static Assets Documentation

This document describes all static assets (CSS, JavaScript, images) used in the Security Scanner Platform.

## Directory Structure

```
static/
├── css/
│   └── style.css          # Custom styles and utilities
├── js/
│   ├── scanner.js         # Main Alpine.js component
│   └── utils.js           # Utility functions and helpers
└── images/
    └── logo.svg           # Platform logo
```

## CSS Files

### style.css

Custom stylesheet providing:
- **Severity color classes**: `.severity-critical`, `.severity-high`, `.severity-medium`, `.severity-low`, `.severity-info`
- **Alpine.js cloak utility**: `[x-cloak]` to prevent flash of unstyled content
- **Custom scrollbar styling**: For modal content
- **Animations**: Pulse animation for scanning status
- **Card hover effects**: Interactive card animations
- **Loading spinner**: `.spinner` class for loading states
- **Badge styles**: Pre-styled severity badges
- **Toast notifications**: Ready for future implementation
- **Responsive utilities**: Mobile-first design helpers
- **Dark mode support**: Optional dark theme (`.dark-mode`)
- **Print styles**: Optimized for printing reports

**Usage:**
```html
<link rel="stylesheet" href="/static/css/style.css">
```

## JavaScript Files

### scanner.js

Main Alpine.js component that powers the dashboard interface.

**Key Functions:**

- `securityScanner()` - Main Alpine.js component
  - `init()` - Initialize component and load data
  - `loadScanners()` - Fetch available scanners
  - `selectAllScanners()` - Select all scanner checkboxes
  - `startScan()` - Initiate a new security scan
  - `loadRecentScans(limit)` - Load scan history
  - `loadStatistics()` - Fetch platform statistics
  - `viewScanDetails(scanId)` - Display detailed scan results
  - `connectWebSocket()` - Establish WebSocket connection
  - `handleWebSocketMessage(data)` - Process real-time updates
  - `formatDate(dateString)` - Format timestamps
  - `getScoreColor(score)` - Get color class for security score
  - `showNotification(message, type)` - Display notifications
  - `exportScan(scanId, format)` - Export scan results
  - `closeModal()` - Close detail modal

**Global Utilities (window.scannerUtils):**
- `formatDuration(seconds)` - Convert seconds to readable format
- `copyToClipboard(text)` - Copy text to clipboard
- `downloadTextFile(content, filename)` - Download text as file
- `isValidUrl(string)` - Validate URL format
- `debounce(func, wait)` - Debounce function calls

**Usage:**
```html
<script src="/static/js/scanner.js"></script>
<div x-data="securityScanner()" x-init="init()">
  <!-- Your Alpine.js component -->
</div>
```

### utils.js

Additional utility functions and configuration.

**Constants:**

- `API_CONFIG` - API endpoints and configuration
  - `BASE_URL`: '/api'
  - `ENDPOINTS`: Object with all API endpoints
  - `WEBSOCKET_URL()`: Function returning WebSocket URL

- `SEVERITY` - Severity level definitions
  - Each level includes: level, color, bgColor, label
  - Levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

**Utility Functions:**

- `formatBytes(bytes, decimals)` - Convert bytes to human-readable format
- `formatNumber(num)` - Add thousand separators
- `timeAgo(dateString)` - Calculate relative time (e.g., "2 hours ago")
- `sanitizeUrl(url)` - Clean and validate URLs
- `extractDomain(url)` - Extract hostname from URL
- `getSecurityScoreColor(score)` - Get color and label for score
- `groupBySeverity(findings)` - Group scan results by severity
- `calculateSeverityScore(summary)` - Calculate weighted security score
- `storage` - LocalStorage wrapper with error handling
  - `set(key, value)` - Save to localStorage
  - `get(key, defaultValue)` - Retrieve from localStorage
  - `remove(key)` - Delete from localStorage
  - `clear()` - Clear all localStorage
- `exportToCSV(data, filename)` - Export data to CSV file
- `generateReportSummary(scan)` - Create report summary object

**Keyboard Shortcuts:**
- `Ctrl/Cmd + K` - Focus URL input
- `Escape` - Close modal
- `Ctrl/Cmd + R` - Refresh scans

**Usage:**
```html
<script src="/static/js/utils.js"></script>
<script>
  // Access utilities
  const config = window.scannerUtilities.API_CONFIG;
  const score = window.scannerUtilities.calculateSeverityScore(summary);
</script>
```

## Images

### logo.svg

SVG logo for the Security Scanner Platform.

**Features:**
- Shield design with checkmark
- Blue gradient color scheme (#2563eb to #3b82f6)
- Scanner line effects
- Scalable vector format (200x200 base size)
- Optimized for use as favicon and branding

**Usage:**
```html
<!-- As favicon -->
<link rel="icon" type="image/svg+xml" href="/static/images/logo.svg">

<!-- As image -->
<img src="/static/images/logo.svg" alt="Security Scanner Logo" width="48" height="48">

<!-- As background -->
<div style="background-image: url('/static/images/logo.svg')"></div>
```

## CDN Dependencies

The platform uses the following CDN-hosted libraries:

### TailwindCSS
```html
<script src="https://cdn.tailwindcss.com"></script>
```
**Purpose:** Utility-first CSS framework for rapid UI development
**Version:** Latest (CDN always serves current version)

### Chart.js
```html
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
```
**Purpose:** Charts and data visualization (for future dashboard enhancements)
**Version:** Latest stable

### Alpine.js
```html
<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
```
**Purpose:** Lightweight reactive framework for interactivity
**Version:** 3.x.x

## Best Practices

### Performance
- CSS and JS files are minified for production
- Static files are cached by the browser
- CDN libraries are loaded from fast global networks
- Images use SVG format for scalability without quality loss

### Maintenance
- Custom CSS is separated from inline styles
- JavaScript is modular with clear separation of concerns
- Utility functions are reusable across the application
- Comments explain complex logic

### Accessibility
- Color contrast meets WCAG standards
- Keyboard shortcuts for common actions
- Semantic HTML with proper ARIA labels
- Focus states for interactive elements

### Security
- No inline JavaScript (CSP-friendly)
- User input is sanitized
- URLs are validated before use
- XSS protection through proper escaping

## Future Enhancements

Planned additions to static assets:

1. **Chart configurations** (chart-config.js)
   - Pre-configured Chart.js settings
   - Custom chart types for security metrics

2. **Theme switcher** (theme.js)
   - Light/dark mode toggle
   - User preference persistence

3. **Export templates** (export-templates.js)
   - PDF generation templates
   - Custom report formats

4. **Animation library** (animations.css)
   - Page transition effects
   - Loading animations
   - Success/error feedback

5. **Icon set** (icons/)
   - Custom SVG icons
   - Scanner-specific icons
   - Status indicators

6. **Internationalization** (i18n/)
   - Multi-language support
   - Localized date/time formats

## Testing

To verify static assets are loading correctly:

1. **Open browser developer tools** (F12)
2. **Go to Network tab**
3. **Reload the page**
4. **Check for:**
   - All CSS files loaded (status 200)
   - All JS files loaded (status 200)
   - No 404 errors
   - Proper MIME types (text/css, application/javascript)

**Console checks:**
```javascript
// Verify utilities loaded
console.log(typeof window.scannerUtils);        // should be 'object'
console.log(typeof window.scannerUtilities);    // should be 'object'

// Verify Alpine.js loaded
console.log(typeof Alpine);                      // should be 'object'

// Verify Chart.js loaded
console.log(typeof Chart);                       // should be 'function'
```

## Troubleshooting

**CSS not loading:**
- Check FastAPI static file mount in `main.py`
- Verify file path is correct: `/static/css/style.css`
- Clear browser cache (Ctrl+Shift+R)

**JavaScript errors:**
- Check browser console for error messages
- Ensure scripts are loaded in correct order (utils.js before scanner.js)
- Verify CDN libraries are accessible

**Images not displaying:**
- Check file permissions
- Verify MIME type for SVG files
- Test direct URL access: `http://localhost:8000/static/images/logo.svg`

## License

All static assets are part of the Security Scanner Platform and are licensed under the MIT License.
