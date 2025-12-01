# New Features: Delete and Rescan

## ✨ Features Added

### 1. Delete Scan Results
Users can now delete individual scan results from the dashboard.

**API Endpoint:**
```http
DELETE /api/scans/{scan_id}
```

**Features:**
- ✅ Confirmation dialog before deletion
- ✅ Automatic cleanup of related records (cascade delete)
- ✅ Audit logging for deletion actions
- ✅ Real-time UI update after deletion
- ✅ Updates statistics automatically

**UI Locations:**
- 🗑️ Delete button in scan list (hover to see)
- 🗑️ Delete button in scan details modal

### 2. Rescan with Same Configuration
Re-run any previous scan with the exact same settings.

**API Endpoint:**
```http
POST /api/scans/{scan_id}/rescan
```

**Features:**
- ✅ Automatically uses original URL and scanner
- ✅ Creates new scan record (preserves history)
- ✅ Real-time progress updates via WebSocket
- ✅ Audit logging for rescan actions
- ✅ Background task execution

**UI Locations:**
- 🔄 Rescan button in scan list (hover to see)
- 🔄 Rescan button in scan details modal

## 🎯 Use Cases

### Delete Scenarios
- Remove test scans
- Clean up duplicate scans
- Delete outdated scan results
- Free up database space
- Maintain clean scan history

### Rescan Scenarios
- Verify if security issues were fixed
- Track security improvements over time
- Regular security monitoring
- Compare current vs. previous results
- Automated periodic rescanning

## 💻 Implementation Details

### Backend Changes (main.py)

**New Endpoint: DELETE /api/scans/{scan_id}**
```python
@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession):
    - Validates scan exists (404 if not found)
    - Deletes scan record and related data
    - Logs deletion in audit_logs table
    - Returns success response
```

**New Endpoint: POST /api/scans/{scan_id}/rescan**
```python
@app.post("/api/scans/{scan_id}/rescan")
async def rescan(scan_id: int, background_tasks: BackgroundTasks, db: AsyncSession):
    - Retrieves original scan configuration
    - Creates new scan with same URL and scanner
    - Executes scan in background
    - Logs rescan action in audit_logs
    - Returns immediate response with new scan ID
```

### Frontend Changes

**JavaScript Functions (scanner.js)**
```javascript
async deleteScan(scanId) {
    - Shows confirmation dialog
    - Calls DELETE endpoint
    - Closes modal if currently viewing deleted scan
    - Refreshes scan list and statistics
    - Shows success notification
}

async rescan(scanId) {
    - Calls POST rescan endpoint
    - Updates UI to show scanning state
    - Sets progress indicators
    - Closes modal
    - Shows success notification
}
```

**UI Updates (index.html)**
- Added action buttons to scan list items
- Added action buttons to modal header
- Improved click handling (prevent event bubbling)
- Better visual feedback on hover

## 🔒 Security Considerations

### Delete Protection
- ✅ Confirmation dialog prevents accidental deletion
- ✅ Audit logging tracks all deletions
- ✅ Cascade delete ensures data integrity
- ✅ 404 error for non-existent scans

### Rescan Safety
- ✅ Validates original scan exists
- ✅ URL validation before rescan
- ✅ Scanner validation before execution
- ✅ Background task prevents blocking
- ✅ Audit trail for all rescans

## 📊 Database Impact

### Audit Logs
All actions are logged in `audit_logs` table:

**Delete Action:**
```json
{
    "action": "scan_deleted",
    "target_url": "https://example.com",
    "scanner_name": "security_headers",
    "details": {"scan_id": 123}
}
```

**Rescan Action:**
```json
{
    "action": "scan_rerun",
    "target_url": "https://example.com",
    "scanner_name": "security_headers",
    "details": {
        "original_scan_id": 123,
        "new_scan_id": "2025-12-01T..."
    }
}
```

### Cascade Deletion
When a scan is deleted:
- ✅ `scan_records` row deleted
- ✅ Related `scan_history` entries deleted (cascade)
- ✅ Audit log entry created (preserved)

## 🎨 UI/UX Improvements

### Visual Design
- **Delete Button**: Red color (🗑️) for destructive action
- **Rescan Button**: Blue color (🔄) for positive action
- **Hover States**: Background highlights on hover
- **Button Placement**: 
  - Quick actions in scan list (always visible)
  - Prominent buttons in modal (top-right)

### User Feedback
- ✅ Confirmation before deletion
- ✅ Success notifications after actions
- ✅ Error alerts for failures
- ✅ Real-time progress for rescans
- ✅ Automatic list refresh

## 📝 API Documentation

### Delete Scan
```http
DELETE /api/scans/{scan_id}

Response 200:
{
    "status": "success",
    "message": "Scan 123 deleted successfully"
}

Response 404:
{
    "detail": "Scan not found"
}
```

### Rescan
```http
POST /api/scans/{scan_id}/rescan

Response 200:
{
    "status": "started",
    "message": "Re-scanning https://example.com with security_headers",
    "original_scan_id": 123,
    "new_scan_id": "2025-12-01T16:35:00",
    "url": "https://example.com",
    "scanner": "security_headers"
}

Response 404:
{
    "detail": "Scan not found"
}
```

## 🧪 Testing

### Manual Testing Steps

**Test Delete:**
1. Open dashboard at http://localhost:8000
2. View any scan in the list
3. Click 🗑️ delete button
4. Confirm deletion
5. Verify scan removed from list
6. Verify statistics updated

**Test Rescan:**
1. Open dashboard
2. View any scan in the list
3. Click 🔄 rescan button
4. Observe progress indicators
5. Wait for completion
6. Verify new scan appears in list
7. Compare results with original

**Test Modal Actions:**
1. Click on any scan to open modal
2. Test 🔄 Rescan button in modal
3. Test 🗑️ Delete button in modal
4. Verify modal closes after actions

## 🚀 Future Enhancements

Potential improvements:
- [ ] Bulk delete (select multiple scans)
- [ ] Undo delete (soft delete with restore)
- [ ] Schedule automatic rescans
- [ ] Compare scan results side-by-side
- [ ] Export before delete option
- [ ] Delete all scans for a URL
- [ ] Keyboard shortcuts (Del key)
- [ ] Drag to delete gesture (mobile)

## ✅ Status

- ✅ Backend implementation complete
- ✅ Frontend implementation complete
- ✅ UI/UX design implemented
- ✅ Error handling added
- ✅ Audit logging functional
- ✅ Server tested and running
- 🟢 **READY FOR USE**

## 📦 Files Modified

1. **main.py**: Added 2 new endpoints (DELETE, POST rescan)
2. **static/js/scanner.js**: Added 2 new functions
3. **templates/index.html**: Updated UI with action buttons

## 🎉 Summary

Users can now:
- 🗑️ **Delete unwanted scans** with confirmation
- 🔄 **Re-run any scan** with one click
- 📊 **Keep scan history clean** and organized
- 🔍 **Track security changes** over time
- ⚡ **Quick actions** directly from scan list

All features are production-ready and include proper error handling, audit logging, and user feedback!
