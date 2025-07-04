# Threading and Error Handling Improvements

## Summary of Changes

### 1. Centralized Error Handling
- **Created**: `app/core/error_handler.py`
- **Features**:
  - Global exception handler that catches unhandled exceptions
  - User-friendly error dialogs instead of crashes
  - Automatic error logging
  - Setup function integrated into main.py

### 2. Consistent QThreadPool/QRunnable Usage
- **Created**: `app/core/base_worker.py`
- **Features**:
  - `BaseWorker` class for consistent threading patterns
  - `CommandWorker` class for subprocess execution
  - Standard signal interface (output, error, finished, progress)
  - Built-in timeout protection (5 minutes)
  - Proper error handling and logging

### 3. Updated All Pages
**Replaced `threading.Thread` with `QThreadPool/QRunnable` in:**
- `enumeration_page.py` - All port scanning, SMB, SMTP, SNMP, HTTP, API, and DB enumeration tools
- `cracking_page.py` - All password cracking tools
- `vuln_scanning_page.py` - All NSE vulnerability scanning tools
- `web_exploits_page.py` - All web exploitation tools
- `db_attacks_page.py` - All database attack tools
- `os_exploits_page.py` - All OS exploitation tools

### 4. Benefits Achieved
- **Consistent Threading**: All tools now use the same QThreadPool/QRunnable pattern
- **Better Resource Management**: QThreadPool automatically manages thread lifecycle
- **Improved Error Handling**: Centralized exception handling prevents crashes
- **Timeout Protection**: Commands automatically timeout after 5 minutes
- **Cleaner Code**: Reduced code duplication across pages
- **Better UI Responsiveness**: Proper Qt threading prevents GUI freezing

### 5. Files Modified
- `main.py` - Added global error handler setup
- `app/core/error_handler.py` - New centralized error handling
- `app/core/base_worker.py` - New base worker classes
- All page files in `app/pages/` - Updated to use new threading approach

### 6. Key Features
- **Global Exception Handler**: Catches any unhandled exceptions and shows user-friendly dialogs
- **Consistent Worker Pattern**: All background tasks use the same base worker class
- **Automatic Timeout**: Commands timeout after 5 minutes to prevent hanging
- **Proper Signal Handling**: Standard signals for output, errors, and completion
- **Resource Cleanup**: QThreadPool automatically manages thread resources

The application is now more robust and consistent in its threading approach, with centralized error handling that prevents unexpected crashes.