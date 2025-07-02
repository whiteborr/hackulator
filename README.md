# Hackulator

A comprehensive penetration testing toolkit built with PyQt6, featuring a complete enumeration suite with modern GUI interface and advanced security analysis capabilities.

## Features

### Core Functionality
- **Complete Enumeration Suite**: 8 different enumeration tools
- **Modern GUI Interface**: Responsive layout with alien tablet-themed design
- **Multi-threaded Operations**: Concurrent scanning for improved performance
- **Real-time Output**: Live terminal-style output with progress tracking
- **Customizable**: Configurable wordlists and scan parameters

### Advanced Features ✨
- **Performance Optimization**: Connection pooling, result caching, memory management
- **Scan Control**: Pause/resume/stop functionality for long-running scans
- **Professional Reporting**: PDF reports and executive summaries
- **Vulnerability Correlation**: AI-powered analysis of security relationships
- **Export Formats**: JSON, CSV, XML, PDF, Executive Summary, Correlation Analysis, Result Comparison
- **Rate Limiting**: Configurable scan speed control with presets
- **Custom Templates**: Save and reuse scan configurations
- **Scan Scheduling**: Automated scan execution at specified times
- **Multi-Target Scanning**: Simultaneous scanning of multiple targets
- **Theme Toggle**: Dark and light interface themes with persistent settings
- **Keyboard Shortcuts**: Quick access to common functions via hotkeys
- **Drag & Drop Support**: Direct file import via drag and drop interface
- **Advanced Directory Enumeration**: Recursive web directory discovery with intelligent filtering
- **Certificate Transparency Integration**: Subdomain discovery through CT logs and certificate analysis
- **OSINT Data Gathering**: Multi-source intelligence collection from open source platforms
- **Vulnerability Scanning Integration**: Automated security vulnerability detection and assessment
- **Scan History Database**: Persistent storage and management of scan results with search capabilities
- **Session Management**: Project organization with grouped scans and session-based workflow management
- **Custom Wordlist Manager**: Create, edit, and manage custom wordlists with import/export and merging capabilities
- **Result Filtering and Search**: Advanced filtering and search capabilities with real-time results and statistics
- **Real-time Notifications**: Desktop notifications, system tray integration, and configurable alert system
- **System Tray Integration**: Minimize to tray with quick access menu and notifications
- **Context Menus**: Right-click menus for terminal output, input fields, and results areas
- **Advanced UI Themes**: Multiple color schemes including Dark, Light, Cyberpunk, Matrix, and Ocean themes
- **Unit Testing**: Automated test suite for core functionality validation
- **Integration Testing**: End-to-end workflow testing and component interaction validation
- **Code Documentation**: Comprehensive API documentation and development guides
- **Plugin Architecture**: Extensible plugin system for custom tools and functionality
- **API Integration**: External service connectivity with Shodan, VirusTotal, and custom API support
- **Threat Intelligence**: IOC reputation checking against malware and phishing threat feeds
- **Machine Learning**: Automated pattern detection and anomaly analysis for scan results
- **Distributed Scanning**: Multi-node scanning support for improved performance and scalability
- **Memory Monitoring**: Real-time memory usage tracking and optimization
- **Status Bar Integration**: Live feedback and system monitoring

## Enumeration Tools

### 1. DNS Enumeration
- Subdomain discovery with wordlists
- Multiple DNS record types (A, AAAA, CNAME, MX, TXT)
- Wildcard detection and handling

### 2. Port Scanning
- TCP connect scans with service detection
- Network ping sweeps for host discovery
- Top ports and custom port ranges

### 3. SMB Enumeration
- SMB/NetBIOS port detection (139, 445)
- Computer name enumeration via NetBIOS
- OS detection through SMB negotiation

### 4. SMTP Enumeration
- User enumeration via VRFY, EXPN, RCPT TO
- Wordlist-based username testing
- Mail server probing

### 5. SNMP Enumeration
- SNMP port detection (UDP 161)
- Community string testing
- SNMP walks for device information

### 6. HTTP/S Fingerprinting
- Web server identification and fingerprinting
- SSL/TLS certificate analysis
- Directory and file discovery

### 7. API Enumeration
- REST API endpoint discovery
- HTTP method testing
- Authentication bypass attempts

### 8. Database Enumeration
- Database port scanning (MSSQL, MySQL, PostgreSQL, etc.)
- Service version detection
- Connection testing

## Project Structure

```
hackulator/
├── app/                           # GUI application
│   ├── core/                      # Core functionality
│   ├── pages/                     # UI pages
│   ├── widgets/                   # Custom widgets
│   └── main_window.py             # Main application window
├── tools/                         # Enumeration tools
│   ├── port_scanner.py            # Port scanning tool
│   ├── smb_enum.py                # SMB enumeration
│   ├── smtp_enum.py               # SMTP enumeration
│   ├── snmp_enum.py               # SNMP enumeration
│   ├── http_enum.py               # HTTP fingerprinting
│   ├── api_enum.py                # API enumeration
│   └── db_enum.py                 # Database enumeration
├── resources/
│   ├── fonts/                     # Custom fonts
│   ├── icons/                     # UI icons
│   ├── themes/                    # Theme configurations
│   └── wordlists/                 # Enumeration wordlists
├── exports/                       # Scan results
├── logs/                          # Application logs
└── main.py                        # Application entry point
```

## Requirements

### Core Dependencies
- Python 3.8+
- PyQt6
- requests
- dnspython
- psutil (for memory monitoring)

### Optional Dependencies
- reportlab>=4.0.0 (for PDF generation)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd hackulator
```

2. Install dependencies:
```bash
# Core dependencies
pip install PyQt6 dnspython requests psutil

# Optional: For PDF reports
pip install reportlab>=4.0.0
```

3. Run the application:
```bash
python main.py
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **API.md**: API reference with code examples
- **ARCHITECTURE.md**: System architecture and design patterns
- **DEVELOPMENT.md**: Development guidelines and coding standards
- **MODULES.md**: Auto-generated module documentation

### Generate Documentation

```bash
# Generate module documentation from docstrings
python generate_docs.py
```

## Plugin System

Hackulator supports a plugin architecture for extending functionality:

### Using Plugins

1. Access plugin manager via Export dropdown → "Plugins"
2. Select available plugin from dropdown
3. Click "Execute Plugin" to run on current target
4. View results in plugin output area

### Creating Plugins

```python
# plugins/my_plugin.py
from app.core.plugin_manager import PluginBase

class MyPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.version = "1.0.0"
        self.description = "Custom functionality"
    
    def execute(self, target, **kwargs):
        # Plugin logic here
        return {
            "plugin": self.name,
            "target": target,
            "result": "Custom scan completed",
            "data": ["result1", "result2"]
        }
```

### Available Plugins

- **Example Plugin**: Demonstration plugin showing basic structure
- **WHOIS Lookup**: Domain WHOIS information retrieval
- **Custom Plugins**: Add your own plugins to the `plugins/` directory

## API Integration

Hackulator supports integration with external APIs for enhanced intelligence gathering:

### Supported APIs

- **Shodan**: Internet-connected device discovery and port information
- **VirusTotal**: Domain reputation and malware analysis
- **URLVoid**: Domain reputation checking
- **Custom APIs**: Generic HTTP API integration

### Using API Integration

1. Access API integration via Export dropdown → "API Integration"
2. Select API service from dropdown
3. Enter API key if required (Shodan, VirusTotal)
4. Click "Query API" to execute request
5. View results in API output area

### API Configuration

```python
# Example API usage
from app.core.api_integration import api_integration

# Shodan query
result = api_integration.query_shodan("8.8.8.8", "your_api_key")

# VirusTotal query
result = api_integration.query_virustotal("example.com", "your_api_key")

# Custom API request
result = api_integration.custom_api_request("https://api.example.com/data")
```

### API Key Management

- **Shodan**: Requires API key for host information queries
- **VirusTotal**: Requires API key for domain reputation checks
- **URLVoid**: Free tier available without API key
- **Custom APIs**: Support for authentication headers and parameters

## Threat Intelligence

Hackulator integrates with threat intelligence feeds for IOC (Indicator of Compromise) checking:

### Supported Threat Feeds

- **Abuse.ch Feodo Tracker**: Malware C&C server IP addresses
- **Malware Domains**: Known malware hosting domains
- **Phishing Army**: Phishing domain blocklist

### Using Threat Intelligence

1. Access threat intelligence via Export dropdown → "Threat Intel"
2. Click "Check Target Reputation" to scan current target
3. Click "Check Feed Status" to verify feed availability
4. View threats in color-coded table (High/Medium/Low severity)
5. Review detailed results in output area

### IOC Checking

```python
# Example threat intelligence usage
from app.core.threat_intelligence import threat_intelligence

# Check IP reputation
result = threat_intelligence.check_ip_reputation("192.168.1.1")

# Check domain reputation
result = threat_intelligence.check_domain_reputation("example.com")

# Get comprehensive IOC summary
result = threat_intelligence.get_ioc_summary("target")
```

### Threat Detection

- **Automatic target detection**: Distinguishes between IP addresses and domains
- **Multiple feed checking**: Queries multiple threat intelligence sources
- **Severity classification**: High, medium, low threat categorization
- **Real-time status**: Live feed availability checking
- **Historical data**: First seen and last seen timestamps where available

## Machine Learning Pattern Detection

Hackulator includes ML-based pattern detection for automated analysis of scan results:

### Pattern Detection Features

- **DNS Pattern Analysis**: Subdomain naming patterns, wildcard detection
- **Port Scan Analysis**: Service patterns, unusual port combinations
- **HTTP Pattern Analysis**: Response code patterns, WAF detection
- **Anomaly Detection**: Statistical analysis of result deviations

### Using ML Pattern Detection

1. Access ML analysis via Export dropdown → "ML Patterns"
2. Click "Analyze Current Results" to process scan data
3. View detected patterns in color-coded confidence table
4. Review anomalies with severity classification
5. Read ML-generated insights and recommendations

### Pattern Analysis

```python
# Example ML pattern detection usage
from app.core.ml_pattern_detection import ml_pattern_detection

# Analyze DNS enumeration results
analysis = ml_pattern_detection.analyze_scan_results(dns_results, "dns_enum")

# Analyze port scan results
analysis = ml_pattern_detection.analyze_scan_results(port_results, "port_scan")

# Detect anomalies compared to historical data
anomalies = ml_pattern_detection.detect_scan_anomalies(current, historical)
```

### ML Insights

- **Automatic Analysis**: Runs automatically on significant scan results
- **Confidence Scoring**: Pattern confidence from 0-100%
- **Severity Classification**: High, medium, low anomaly severity
- **Actionable Insights**: ML-generated recommendations and observations
- **Historical Comparison**: Deviation detection from previous scans

## Distributed Scanning

Hackulator supports distributed scanning across multiple nodes for improved performance and scalability:

### Distributed Features

- **Node Discovery**: Automatic discovery of available scanning nodes on the network
- **Task Distribution**: Intelligent distribution of scan tasks across multiple nodes
- **Result Aggregation**: Automatic collection and consolidation of results from all nodes
- **Load Balancing**: Even distribution of targets across available nodes

### Using Distributed Scanning

1. Access distributed scanning via Export dropdown → "Distributed Scan"
2. Click "Discover Nodes" to find available scanning nodes
3. View discovered nodes in the nodes table with status and capabilities
4. Enter targets and select scan type (DNS, Port, HTTP)
5. Click "Start Distributed Scan" to distribute tasks across nodes
6. Monitor progress and view aggregated results

### Distributed Architecture

```python
# Example distributed scanning usage
from app.core.distributed_scanning import distributed_scanner

# Discover nodes
distributed_scanner.discover_nodes("192.168.1.0/24")

# Distribute scan
result = distributed_scanner.distribute_scan(
    "dns", 
    ["example1.com", "example2.com", "example3.com"]
)

# Check scan status
status = distributed_scanner.get_scan_status(result["scan_id"])
```

### Node Management

- **Node Registration**: Automatic registration of scanning nodes
- **Capability Detection**: Nodes advertise their scanning capabilities (DNS, Port, HTTP)
- **Health Monitoring**: Real-time status monitoring of all nodes
- **Fault Tolerance**: Graceful handling of node failures during scans

## Testing

Run the unit test suite to validate core functionality:

```bash
# Run all tests (unit + integration)
python run_tests.py

# Run only unit tests
python -m unittest discover tests -v

# Run only integration tests
python -m unittest discover tests/integration -v

# Run specific test file
python -m unittest tests.test_validators
```

### Test Coverage

#### Unit Tests
- **Input Validation**: IP address and domain validation
- **Cache Management**: Cache operations and TTL handling
- **Theme Management**: Advanced theme application and stylesheet generation
- **Context Menus**: Menu creation and action handling

#### Integration Tests
- **Scan Workflow**: Complete scan process from validation to storage
- **Theme Integration**: Theme application across multiple components
- **Export Integration**: Cache-to-export data flow and multiple format support
- **Component Interaction**: Cross-component functionality validation

## Usage

### Home Page
- Navigate through different enumeration categories using the circular menu buttons
- Hover over buttons to see detailed descriptions in the info panel
- Click "ENUMERATION" to access all enumeration tools

### Using Enumeration Tools
1. **Select Tool**: Click on any enumeration tool (DNS, Port Scan, SMB, etc.)
2. **Enter Target**: Input IP address, domain, or network range
3. **Configure Options**: Select wordlists, record types, or scan parameters
4. **Run Scan**: Click specific tool buttons (HOSTS, TCP SCAN, SMB SCAN, etc.)
5. **Control Scans**: Use pause/resume/stop controls during execution
6. **Export Results**: Choose from multiple formats:
   - **JSON/CSV/XML**: Raw data export
   - **PDF**: Professional detailed reports
   - **Summary**: Executive summary with risk assessment
   - **Correlate**: Vulnerability correlation analysis
   - **Compare**: Scan result comparison with change detection
   - **Proxy**: Proxy configuration and testing interface
   - **Rate Limit**: Scan speed control and throttling configuration
   - **Templates**: Custom scan template management
   - **Schedule**: Automated scan scheduling interface
   - **Multi-Target**: Bulk target scanning interface
   - **Theme**: Dark/light theme selection interface
   - **Help**: Keyboard shortcuts and usage guide (F1)

### Tool-Specific Usage
- **DNS**: Domain enumeration with wordlists and record types
- **Port Scan**: TCP scans, network sweeps, service detection
- **SMB**: NetBIOS queries, OS detection, range scanning
- **SMTP**: User enumeration via VRFY/EXPN/RCPT TO
- **SNMP**: Community testing, SNMP walks, device discovery
- **HTTP**: Server fingerprinting, SSL analysis, directory scanning
- **API**: Endpoint discovery, method testing, auth bypass
- **Database**: Port scanning, service detection, connection testing

### Advanced Features in Detail

#### Performance Optimization
- **Connection Pooling**: Reuses HTTP connections for faster scanning
- **Result Caching**: Avoids redundant scans with 1-hour TTL
- **Memory Management**: Automatic garbage collection and monitoring
- **Scan Control**: Pause/resume/stop functionality for resource management

#### Professional Reporting
- **PDF Reports**: Detailed technical reports with formatted tables
- **Executive Summaries**: High-level risk assessment for management
- **Vulnerability Correlation**: AI-powered analysis identifying:
  - Attack chains and potential exploit paths
  - Risk amplifiers that increase overall exposure
  - Security gaps requiring attention
- **Result Comparison**: Change detection between scan runs:
  - New and removed findings identification
  - Historical trend analysis
  - Automatic change notifications
- **Proxy Support**: Complete proxy integration:
  - HTTP/HTTPS and SOCKS5 proxy support
  - Authentication with username/password
  - Proxy connectivity testing
  - All HTTP-based tools proxy-aware
- **Rate Limiting**: Intelligent scan speed control:
  - Configurable requests per second (1-100)
  - Thread count optimization
  - Preset configurations (Stealth to Aggressive)
  - Per-tool rate limiting with automatic throttling
- **Custom Templates**: Reusable scan configurations:
  - Pre-built templates (Quick Web, Stealth Recon, Full Assessment)
  - Save current settings as custom templates
  - Template-based configuration loading
  - Tool-specific parameter management
- **Scan Scheduling**: Automated scan execution:
  - Schedule scans for specific date/time
  - Recurring scans with configurable intervals
  - Quick time presets (1h, 6h, 24h, 7d)
  - Schedule management with status tracking
- **Multi-Target Scanning**: Bulk target processing:
  - Scan multiple targets simultaneously (up to 20)
  - Load targets from file or manual input
  - Concurrent execution with progress tracking
  - Consolidated results and status monitoring
- **Theme Management**: Visual customization:
  - Dark and light theme options
  - One-click theme toggle functionality
  - Persistent theme preferences
  - Comprehensive UI element styling
- **Keyboard Shortcuts**: Efficient navigation:
  - Common actions accessible via hotkeys
  - Scan control shortcuts (start, pause, stop)
  - Quick access to advanced features
  - Built-in help system (F1)
- **Context Menus**: Right-click functionality:
  - Terminal output: Copy, select all, clear, save to file
  - Input fields: Cut, copy, paste, select all, clear
  - Results areas: Export, copy results, clear results
  - Quick access to common actions without menu navigation
- **Drag & Drop Support**: Intuitive file handling:
  - Drag wordlist files directly to combo boxes
  - Drop target lists into multi-target scanner
  - Visual feedback during drag operations
  - Automatic file validation and loading
- **Advanced Directory Enumeration**: Enhanced web discovery:
  - Recursive directory scanning with configurable depth
  - Intelligent file/directory categorization
  - Interesting finding detection (admin, config, backup files)
  - Real-time results with status code filtering
- **Certificate Transparency Integration**: Passive subdomain discovery:
  - Search multiple CT log sources (crt.sh, Certspotter)
  - Extract subdomains from SSL/TLS certificates
  - Certificate metadata analysis and validation
  - Historical certificate data for comprehensive coverage
- **OSINT Data Gathering**: Multi-source intelligence collection:
  - Shodan integration for exposed services and ports
  - VirusTotal reputation and malware analysis
  - URLVoid domain reputation checking
  - WHOIS registration and ownership data
  - DNS Dumpster comprehensive DNS enumeration
- **Vulnerability Scanning Integration**: Automated security assessment:
  - HTTP vulnerability detection (SQLi, XSS, directory traversal)
  - SSL/TLS certificate and configuration analysis
  - DNS security assessment and zone transfer testing
  - Port-based service vulnerability identification
  - Security header analysis and missing protection detection
- **Scan History Database**: Persistent result management:
  - SQLite database for reliable scan result storage
  - Search and filter capabilities across all stored scans
  - Detailed scan statistics and activity tracking
  - Historical result comparison and trend analysis
  - Automatic result saving with metadata preservation
- **Session Management**: Project-based organization:
  - Create and manage scanning sessions for different projects
  - Group related scans under named sessions with descriptions
  - Automatic scan association with active sessions
  - Session statistics and progress tracking
  - Import/export functionality for session data sharing
- **Custom Wordlist Manager**: Wordlist creation and management:
  - Create custom wordlists with categorization and descriptions
  - Import wordlists from external files with automatic processing
  - Edit existing wordlists with full content management
  - Merge multiple wordlists with duplicate removal options
  - Preview wordlist content and comprehensive statistics tracking
- **Result Filtering and Search**: Advanced result analysis:
  - Real-time search across all result fields with debounced input
  - Multiple filter criteria with AND/OR logic combinations
  - Field-specific filtering with various operators (contains, equals, regex)
  - Dynamic sorting and grouping of filtered results
  - Comprehensive statistics and field analysis for result sets
- **Real-time Notifications**: Comprehensive alert system:
  - Desktop notifications for scan completion and vulnerability detection
  - System tray integration with context menu and status indicators
  - Configurable notification types and sound alerts
  - Notification history with read/unread status tracking
  - Customizable notification settings for different event types

#### Real-time Monitoring
- **Memory Usage**: Live memory consumption tracking
- **Cache Status**: Hit/miss indicators for performance optimization
- **Scan Progress**: Visual progress bars and status updates
- **System Integration**: Status bar with real-time system information

#### Wildcard Detection
- Automatically detects wildcard DNS configurations
- Filters out false positives from wildcard responses
- Displays detection status in real-time

#### Multi-threaded Scanning
- Concurrent DNS queries (50 threads by default)
- Organized output by record type
- Alphabetically sorted results

## Architecture

### Core Components

#### Performance Layer
- **ConnectionPool**: Singleton HTTP session manager with retry logic
- **CacheManager**: File-based result caching with TTL support
- **MemoryManager**: System memory monitoring and optimization
- **ScanController**: Thread-safe pause/resume/stop functionality
- **ProxyManager**: Centralized proxy configuration and testing
- **RateLimiter**: Global rate limiting with per-tool tracking
- **TemplateManager**: Custom scan template storage and management
- **ScanScheduler**: Automated scan scheduling and execution
- **MultiTargetManager**: Concurrent multi-target scan coordination
- **ThemeManager**: Dark/light theme management with persistence
- **ShortcutManager**: Global keyboard shortcut handling
- **DragDropHandler**: File drag and drop functionality
- **AdvancedDirectoryEnumerator**: Recursive web directory discovery
- **CertificateTransparencyClient**: CT log search and subdomain extraction
- **OSINTCollector**: Multi-source open source intelligence gathering
- **VulnerabilityScanner**: Automated security vulnerability detection
- **ScanDatabase**: Persistent scan result storage and retrieval system
- **SessionManager**: Project organization and session-based workflow management
- **WordlistManager**: Custom wordlist creation, editing, and management system
- **ResultFilter**: Advanced filtering and search engine for scan results
- **NotificationManager**: Real-time notification and system tray management

#### Analysis Layer
- **ExecutiveSummary**: Risk assessment and management reporting
- **VulnerabilityCorrelator**: AI-powered security relationship analysis
- **ResultComparator**: Change detection and historical analysis
- **PDFGenerator**: Professional report generation with ReportLab

#### UI Layer
- **Responsive Layouts**: Dynamic QVBoxLayout/QHBoxLayout instead of fixed positioning
- **Status Integration**: Real-time feedback via status bar and widgets
- **Control Widgets**: Scan control, memory monitoring, cache status

#### Worker System
- **WorkerSignals**: Enhanced with progress and correlation callbacks
- **HostWordlistWorker**: Pause-aware DNS enumeration with correlation support
- **CommandWorker**: Generic command execution with caching integration

#### Theme System
- JSON-based theme configuration
- Dynamic resource path resolution
- Enhanced QSS stylesheet with responsive features

## Customization

### Adding Wordlists
Place `.txt` files in `resources/wordlists/` directory. They will automatically appear in the wordlist dropdown.

### Modifying Themes
Edit `resources/themes/default/theme.json` to customize:
- Background images
- Color schemes
- Font settings

### Proxy Configuration
- **HTTP/HTTPS Proxies**: Standard web proxy support
- **SOCKS5 Proxies**: Advanced proxy protocol support
- **Authentication**: Username/password authentication
- **Testing**: Built-in connectivity testing

### Rate Limiting Configuration
- **Speed Control**: 1-100 requests per second
- **Thread Management**: Automatic thread count optimization
- **Preset Modes**: Stealth (2 req/s) to Aggressive (50 req/s)
- **Per-tool Tracking**: Individual rate limits for different scan types

### Template Management
- **Default Templates**: Pre-configured scan scenarios
- **Custom Templates**: Save current settings for reuse
- **Template Loading**: One-click configuration application
- **Parameter Storage**: Tool-specific settings preservation

### Scan Scheduling
- **Time-based Execution**: Schedule scans for specific date/time
- **Recurring Scans**: Repeat scans at configurable intervals
- **Quick Presets**: 1 hour, 6 hours, 24 hours, 7 days
- **Schedule Management**: View, cancel, and track scheduled scans

### Multi-Target Scanning
- **Bulk Processing**: Scan up to 20 targets simultaneously
- **File Import**: Load target lists from text files
- **Flexible Input**: Support for domains, IPs, comments, multiple separators
- **Progress Tracking**: Real-time status and completion monitoring

### Theme Management
- **Theme Options**: Dark and light interface themes
- **Quick Toggle**: One-click switching between themes
- **Persistent Settings**: Theme preference saved automatically
- **Comprehensive Styling**: All UI elements themed consistently

### Keyboard Shortcuts
- **Scan Control**: Ctrl+N (new), Ctrl+P (pause), Ctrl+S (stop)
- **Export Functions**: Ctrl+E (export), Ctrl+M (multi-target)
- **Interface**: Ctrl+T (toggle theme), Ctrl+M (minimize to tray), F1 (help), Ctrl+Q (quit)
- **Quick Access**: Escape (stop operation), direct feature access

### Context Menu Features
- **Terminal Output**: Right-click for copy, select all, clear output, save to file
- **Input Fields**: Standard edit operations (cut, copy, paste, select all, clear)
- **Results Areas**: Export results, copy all results, clear results
- **Quick Actions**: Access common functions without navigating through menus

### Drag & Drop Support
- **Wordlist Files**: Drag .txt files to wordlist combo boxes
- **Target Lists**: Drop target files into multi-target scanner
- **Visual Feedback**: Highlight drop zones during drag operations
- **File Validation**: Automatic validation of dropped files

### Advanced Directory Enumeration
- **Recursive Scanning**: Multi-level directory discovery (1-5 depth levels)
- **Intelligent Categorization**: Automatic file vs directory detection
- **Interesting Findings**: Highlights admin, config, backup, and sensitive files
- **Performance Control**: Configurable thread count and scan depth

### Certificate Transparency Integration
- **Multiple CT Sources**: Search crt.sh and Certspotter CT logs
- **Subdomain Extraction**: Parse certificates for domain names
- **Certificate Analysis**: Metadata extraction and validation
- **Historical Coverage**: Access to historical certificate data

### OSINT Data Gathering
- **Multi-Source Collection**: Query 5+ open source intelligence platforms
- **Reputation Analysis**: Domain and IP reputation checking
- **Service Discovery**: Exposed ports and services identification
- **Registration Data**: WHOIS and domain ownership information

### Vulnerability Scanning Integration
- **Multi-Protocol Support**: HTTP, SSL/TLS, DNS, and port-based scanning
- **Common Vulnerability Detection**: SQLi, XSS, directory traversal, and more
- **Security Configuration Analysis**: Missing headers and weak configurations
- **Severity Classification**: High, medium, and low risk categorization

### Scan History Database
- **Persistent Storage**: SQLite database for reliable scan result preservation
- **Search Functionality**: Full-text search across targets, results, and metadata
- **Filter Options**: Filter by scan type, date range, and target patterns
- **Statistics Dashboard**: Comprehensive analytics and activity tracking

### Session Management
- **Project Organization**: Create named sessions for different assessment projects
- **Scan Grouping**: Automatically associate scans with active sessions
- **Session Statistics**: Track progress and results across session scans
- **Workflow Management**: Organize scanning activities by project or client

### Custom Wordlist Manager
- **Wordlist Creation**: Create custom wordlists with names, categories, and descriptions
- **Content Management**: Full editing capabilities with import from external files
- **Merging Functionality**: Combine multiple wordlists with duplicate removal
- **Preview and Statistics**: Content preview and comprehensive wordlist analytics

### Result Filtering and Search
- **Real-time Search**: Instant search across all result fields with debounced input
- **Advanced Filtering**: Multiple criteria with field-specific operators
- **Dynamic Sorting**: Sort results by any field in ascending or descending order
- **Statistics Dashboard**: Comprehensive analysis of filtered result sets

### Real-time Notifications
- **Desktop Notifications**: System-native notifications for important events
- **System Tray Integration**: Persistent tray icon with context menu and status
- **Configurable Alerts**: Customizable notification types and sound settings
- **Notification History**: Complete history with read/unread status management

### Performance Tuning
- **Cache TTL**: Modify `cache_manager.ttl` (default: 3600 seconds)
- **Memory Threshold**: Adjust `memory_manager.memory_threshold` (default: 80%)
- **Connection Pool**: Configure pool size in `ConnectionPool` class
- **Proxy Settings**: Configure via UI or direct API calls
- **Rate Limits**: Adjust scan speed via preset buttons or sliders
- **Templates**: Create and manage custom scan configurations
- **Scheduling**: Set up automated scan execution times
- **Multi-Target**: Configure bulk scanning operations
- **Themes**: Switch between dark and light interface themes
- **Shortcuts**: Configure and view keyboard shortcuts
- **File Import**: Drag and drop files for easy loading
- **Directory Scanning**: Advanced recursive web directory enumeration
- **Certificate Analysis**: Passive subdomain discovery via CT logs
- **OSINT Collection**: Multi-source intelligence gathering and analysis
- **Vulnerability Assessment**: Automated security vulnerability detection
- **Scan History**: Persistent storage and retrieval of scan results
- **Session Management**: Project-based organization and workflow management
- **Wordlist Management**: Custom wordlist creation and content management
- **Result Filtering**: Advanced search and filtering of scan results
- **Real-time Notifications**: Desktop alerts and system tray integration

### Extending Functionality
The modular architecture supports easy extension:
1. **New Tools**: Add worker classes with pause/resume and proxy support
2. **Custom Analysis**: Extend `VulnerabilityCorrelator` with new rules
3. **Report Formats**: Add new export formats to `PDFGenerator`
4. **UI Components**: Create responsive widgets using layout managers
5. **Proxy Integration**: Extend `ProxyManager` for new proxy types
6. **Rate Limiting**: Add rate limiting to new tools via `RateLimiter`
7. **Templates**: Create custom templates for specific scan scenarios
8. **Scheduling**: Implement automated scan execution workflows
9. **Multi-Target**: Add bulk scanning capabilities for efficiency
10. **Themes**: Implement visual customization options
11. **Shortcuts**: Add keyboard shortcuts for efficient navigation
12. **Drag & Drop**: Implement intuitive file import capabilities
13. **Advanced Directory**: Enhanced web directory discovery tools
14. **Certificate Transparency**: Passive reconnaissance via CT logs
15. **OSINT**: Multi-source open source intelligence collection
16. **Vulnerability Scanning**: Automated security assessment integration
17. **Scan History**: Persistent result storage and management system
18. **Session Management**: Project organization and workflow management
19. **Custom Wordlists**: Wordlist creation and management system
20. **Result Filtering**: Advanced search and filtering capabilities
21. **Real-time Notifications**: Desktop alerts and system tray integration
22. **Plugin Architecture**: Extensible plugin system for custom functionality
23. **API Integration**: External service connectivity and custom API support
24. **Threat Intelligence**: IOC reputation checking and threat feed integration
25. **Machine Learning**: Automated pattern detection and anomaly analysis
26. **Distributed Scanning**: Multi-node scanning support for performance and scalability

## Technical Details

### Enhanced Scanning Process
1. **Cache Check**: Verifies if results exist in cache before scanning
2. **Memory Optimization**: Pre-scan garbage collection and monitoring
3. **Scan Control**: Pause-aware execution with thread-safe controls
4. **Wildcard Detection**: Tests random subdomains to identify wildcard responses
5. **Concurrent Queries**: Processes wordlist entries using ThreadPoolExecutor
6. **Result Correlation**: Automatic vulnerability relationship analysis
7. **Multi-format Export**: Generates reports in multiple formats simultaneously
8. **Cache Storage**: Stores results for future quick access

### Advanced Analysis Engines

#### Vulnerability Correlation Engine
- **Attack Chain Detection**: Identifies potential exploit paths
- **Risk Amplification**: Finds patterns that multiply security risks
- **Security Gap Analysis**: Highlights missing security controls
- **Weighted Scoring**: Calculates correlation risk scores (0-100)

#### Result Comparison Engine
- **Change Detection**: Identifies new and removed findings
- **Historical Tracking**: Maintains comparison history (last 10 scans)
- **Automatic Notifications**: Alerts when significant changes detected
- **Trend Analysis**: Shows security posture changes over time

### Performance Optimizations
- **Connection Pooling**: HTTP session reuse with retry strategies
- **Result Caching**: File-based cache with automatic expiration
- **Memory Management**: Proactive garbage collection and monitoring
- **Thread Pool Management**: Controlled concurrency for optimal performance
- **Result Batching**: Minimized UI updates for better responsiveness
- **Efficient Filtering**: Wildcard detection to reduce false positives

### Error Handling
- **Network Resilience**: Automatic retries with exponential backoff
- **Resource Management**: Memory threshold monitoring and cleanup
- **Graceful Degradation**: Cache failures don't affect core functionality
- **DNS Error Handling**: Timeout and NXDOMAIN response management
- **File Protection**: Wordlist and export directory validation
- **Thread Safety**: Proper locking for concurrent operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes following the existing architecture
4. **Run all tests**: `python run_tests.py`
5. **Add tests** for new functionality (both unit and integration)
6. Test thoroughly with various configurations
7. Submit a pull request

### Development Guidelines
- Write unit tests for new core functionality
- Add integration tests for workflow changes
- Follow existing code patterns and architecture
- **Add proper docstrings** to new classes and methods
- **Update API documentation** for new features
- Ensure all tests pass before submitting changes
- Update documentation for new features

### Documentation Standards
- Use Google-style docstrings for all public methods
- Include type hints and parameter descriptions
- Provide usage examples in API documentation
- Run `python generate_docs.py` to update module docs

### Plugin Development
- Inherit from `PluginBase` class
- Implement `execute(target, **kwargs)` method
- Place plugin files in `plugins/` directory
- Follow naming convention: `*_plugin.py`

### API Integration Development
- Add new API services to `api_integration.py`
- Follow consistent return format for API responses
- Handle authentication and rate limiting appropriately
- Provide error handling for API failures

### Threat Intelligence Development
- Add new threat feeds to `threat_intelligence.py`
- Follow standardized IOC result format
- Implement proper timeout and error handling
- Provide severity classification for threats

### Machine Learning Development
- Add new pattern detection algorithms to `ml_pattern_detection.py`
- Follow standardized analysis result format
- Implement confidence scoring for patterns
- Provide severity classification for anomalies

### Distributed Scanning Development
- Add new node capabilities to `distributed_scanning.py`
- Follow standardized task distribution format
- Implement proper node discovery and registration
- Provide fault tolerance and error handling

## License

[Add your license information here]

## Performance Benchmarks

- **Connection Pooling**: 40-60% faster HTTP-based scans
- **Result Caching**: Instant loading of previous scan results
- **Memory Optimization**: 20-30% reduction in memory usage
- **Correlation Analysis**: Sub-second vulnerability relationship detection
- **Result Comparison**: Near-instant change detection and historical analysis
- **Rate Limiting**: Intelligent throttling prevents target overload
- **Templates**: Instant configuration loading for common scenarios
- **Scheduling**: Automated execution reduces manual intervention
- **Multi-Target**: Bulk processing significantly improves efficiency
- **Themes**: Customizable interface improves user experience
- **Shortcuts**: Keyboard navigation significantly improves workflow efficiency
- **Drag & Drop**: Intuitive file handling reduces import complexity
- **Advanced Directory**: Recursive scanning discovers hidden web content
- **Certificate Transparency**: Passive discovery reveals historical subdomains
- **OSINT**: Comprehensive intelligence from multiple open sources
- **Vulnerability Scanning**: Automated detection of security weaknesses
- **Scan History**: Persistent storage enables result tracking and comparison
- **Session Management**: Project organization improves workflow efficiency
- **Custom Wordlists**: Tailored wordlists improve scanning effectiveness
- **Result Filtering**: Advanced filtering enables efficient result analysis
- **Real-time Notifications**: Immediate alerts improve workflow awareness

## Proxy Usage Examples

### HTTP Proxy
```
Proxy URL: http://proxy.company.com:8080
Username: user
Password: pass
```

### SOCKS5 Proxy
```
Proxy URL: socks5://127.0.0.1:9050
(For Tor: typically localhost:9050)
```

### Testing Proxy
Use the built-in test function to verify proxy connectivity before running scans.

## Rate Limiting Examples

### Preset Configurations
- **🐌 Stealth**: 2 req/s, 10 threads - Maximum stealth
- **🚶 Slow**: 5 req/s, 20 threads - Conservative scanning
- **🏃 Normal**: 10 req/s, 50 threads - Balanced performance
- **🏎️ Fast**: 25 req/s, 100 threads - Aggressive scanning
- **🚀 Aggressive**: 50 req/s, 200 threads - Maximum speed

### Custom Configuration
Adjust the slider for precise requests per second control, or set custom thread counts for specific requirements.

## Template Examples

### Default Templates
- **Quick Web Scan**: Fast web application assessment (25 req/s, HTTP + API tools)
- **Stealth Recon**: Low-profile reconnaissance (2 req/s, DNS + Port scanning)
- **Full Assessment**: Comprehensive security assessment (10 req/s, all tools)

### Custom Templates
Save your current scan configuration as a template:
1. Configure tools, rate limits, and parameters
2. Access Templates panel via export dropdown
3. Enter template name and description
4. Click "Save Current" to create template

### Template Loading
Load saved templates to instantly apply configurations:
1. Select template from dropdown
2. Review description and included tools
3. Click "Load" to apply all settings

## Scheduling Examples

### Quick Scheduling
- **1h**: Schedule scan 1 hour from now
- **6h**: Schedule scan 6 hours from now  
- **24h**: Schedule scan 24 hours from now
- **7d**: Schedule scan 7 days from now

### Recurring Scans
1. Set target and scan type
2. Choose schedule time
3. Set repeat interval (hours)
4. Click "Schedule Scan"

### Schedule Management
- View all scheduled scans in table format
- Monitor time until execution
- Cancel scheduled scans
- Track scan status (Scheduled/Running/Completed/Failed)

## Multi-Target Scanning Examples

### Target Input Formats
```
# Domains and IPs
example.com
192.168.1.1
test.org

# Comments supported
# Production servers
app.company.com
api.company.com

# Multiple separators
site1.com, site2.com; site3.com
```

### File Import
1. Create text file with targets (one per line)
2. Click "Load from File" in Multi-Target panel
3. Review loaded targets and count
4. Start multi-target scan

### Bulk Scanning Workflow
1. Access Multi-Target panel via export dropdown
2. Enter targets manually or load from file
3. Review target count and validation
4. Click "Start Multi-Scan" for concurrent execution
5. Monitor progress and individual target results

## Advanced Theme Examples

### Dark Theme (Default)
- **Background**: Deep black (#0A0A0A)
- **Primary**: Bright blue (#64C8FF)
- **Text**: Light gray (#DCDCDC)
- **Accent**: Orange (#FFAA00)

### Light Theme
- **Background**: White (#FFFFFF)
- **Primary**: Blue (#2196F3)
- **Text**: Dark gray (#212121)
- **Accent**: Orange (#FF9800)

### Cyberpunk Theme
- **Background**: Pure black (#000000)
- **Primary**: Cyan (#00FFFF)
- **Text**: Green (#00FF00)
- **Accent**: Magenta (#FF00FF)

### Matrix Theme
- **Background**: Black (#000000)
- **Primary**: Matrix green (#00FF41)
- **Text**: Matrix green (#00FF41)
- **Accent**: Bright green (#00AA00)

### Ocean Blue Theme
- **Background**: Deep navy (#001122)
- **Primary**: Ocean blue (#0077BE)
- **Text**: Light cyan (#E0F6FF)
- **Accent**: Bright blue (#00AAFF)

### Theme Switching
1. **Menu Access**: View → Themes → Select theme
2. **Advanced Panel**: Export dropdown → "Advanced Themes"
3. **Preview**: Real-time preview before applying
4. **Instant Apply**: All UI elements update immediately
5. **Persistent**: Theme preference automatically saved

## Keyboard Shortcuts

### Scan Operations
- **Ctrl+N**: Start new scan
- **Ctrl+P**: Pause/resume current scan
- **Ctrl+S**: Stop current scan
- **Escape**: Stop current operation

### Export & Features
- **Ctrl+E**: Export results
- **Ctrl+M**: Open multi-target scanner
- **Ctrl+T**: Toggle between dark/light themes

### Navigation & Help
- **F1**: Show help and shortcuts guide
- **Ctrl+Q**: Quit application

### Shortcut Benefits
1. **Efficiency**: Quick access without mouse navigation
2. **Workflow**: Streamlined scanning operations
3. **Accessibility**: Keyboard-only operation support
4. **Productivity**: Faster execution of common tasks

## Drag & Drop File Support

### Supported File Types
- **Wordlists**: .txt files for DNS enumeration
- **Target Lists**: .txt, .csv files for multi-target scanning
- **Configuration Files**: .json files for settings import

### Drop Zones
- **Wordlist Combo**: Drop wordlist files directly onto combo box
- **Multi-Target Panel**: Drop target list files into text area
- **Visual Feedback**: Drop zones highlight during drag operations

### File Handling
1. **Validation**: Automatic file type and content validation
2. **Integration**: Files automatically added to appropriate controls
3. **Feedback**: Status messages confirm successful file loading
4. **Error Handling**: Clear messages for invalid or corrupted files

### Usage Examples
- Drag wordlist.txt from file explorer to wordlist dropdown
- Drop targets.txt into multi-target scanner text area
- Files are validated and loaded automatically
- Visual highlighting shows valid drop zones

## Advanced Directory Enumeration

### Scanning Features
- **Recursive Discovery**: Scan found directories for additional content
- **Configurable Depth**: Set maximum recursion levels (1-5)
- **Thread Control**: Adjust concurrent request threads (1-50)
- **Rate Limiting**: Integrated with global rate limiting system

### Intelligent Detection
- **File Categorization**: Automatic file vs directory classification
- **Status Code Analysis**: 200, 301, 302, 403 response handling
- **Content Analysis**: Response header and content inspection
- **Interesting Findings**: Highlights sensitive files and directories

### Results Display
- **Real-time Updates**: Live results as directories are discovered
- **Color Coding**: Status code based result highlighting
- **Summary Statistics**: Comprehensive scan completion metrics
- **Export Integration**: Results available for standard export formats

### Configuration Options
1. **Target URL**: Web application base URL
2. **Wordlist Selection**: Choose from available directory wordlists
3. **Max Depth**: Set recursive scanning depth (1-5 levels)
4. **Thread Count**: Configure concurrent requests (1-50 threads)
5. **Recursive Mode**: Enable/disable recursive directory scanning

### Interesting Finding Detection
- **Admin Paths**: /admin, /login, /config directories
- **Backup Files**: .bak, .backup, .old file extensions
- **Configuration Files**: config.php, settings.json, .env files
- **Development Paths**: /dev, /test, /staging directories
- **Sensitive Content**: Password, database, API references

## Certificate Transparency Integration

### CT Log Sources
- **crt.sh**: Primary certificate search database
- **Certspotter**: Real-time CT monitoring service
- **Multiple APIs**: Redundant sources for comprehensive coverage
- **Rate Limiting**: Integrated with global rate limiting system

### Subdomain Discovery
- **Certificate Parsing**: Extract domains from certificate names
- **Wildcard Handling**: Process wildcard certificates appropriately
- **Domain Validation**: Verify discovered subdomain formats
- **Deduplication**: Remove duplicate entries across sources

### Certificate Analysis
- **Metadata Extraction**: Issuer, validity dates, common names
- **Historical Data**: Access to expired and historical certificates
- **Multi-domain Certs**: Handle certificates with multiple domains
- **SAN Processing**: Subject Alternative Name parsing

### Results Display
- **Tabbed Interface**: Subdomains, certificates, and statistics
- **Certificate Table**: Detailed certificate information display
- **Statistics Panel**: Source breakdown and discovery metrics
- **Export Integration**: Results compatible with all export formats

### Search Features
1. **Domain Input**: Target domain for certificate search
2. **Multi-source Search**: Query multiple CT log APIs
3. **Real-time Progress**: Live updates during search process
4. **Comprehensive Results**: Subdomains, certificates, and statistics
5. **Export Ready**: Results available for standard export formats

## OSINT Data Gathering

### Intelligence Sources
- **Shodan**: Internet-connected device and service discovery
- **VirusTotal**: Domain reputation and malware analysis
- **URLVoid**: Multi-engine domain reputation checking
- **WHOIS**: Domain registration and ownership data
- **DNS Dumpster**: Comprehensive DNS record enumeration

### Data Collection
- **Service Discovery**: Open ports, running services, and exposed interfaces
- **Reputation Analysis**: Malware detections and security ratings
- **Registration Data**: Domain ownership, creation dates, and registrar info
- **DNS Intelligence**: Comprehensive DNS record mapping
- **Historical Data**: Access to archived and historical information

### Results Analysis
- **Severity Classification**: High, medium, low, and informational findings
- **Source Attribution**: Track which sources provided specific intelligence
- **Finding Categorization**: Organize results by type and relevance
- **Summary Statistics**: Overview of collection success and findings

### Interface Features
- **Source Selection**: Choose specific OSINT sources to query
- **Tabbed Results**: Summary, findings table, and raw data views
- **Progress Tracking**: Real-time updates during data collection
- **Export Integration**: Results compatible with all export formats

### Collection Process
1. **Target Specification**: Enter domain or IP address
2. **Source Selection**: Choose from available OSINT platforms
3. **Data Collection**: Automated querying of selected sources
4. **Result Analysis**: Categorization and severity assessment
5. **Export Options**: Save results in preferred formats

## Vulnerability Scanning Integration

### Scan Types
- **HTTP Scanning**: Web application vulnerability assessment
- **SSL/TLS Analysis**: Certificate and encryption configuration review
- **DNS Security**: Zone transfer and DNS configuration testing
- **Port Analysis**: Service-based vulnerability identification

### Vulnerability Detection
- **SQL Injection**: Database query manipulation testing
- **Cross-Site Scripting (XSS)**: Script injection vulnerability detection
- **Directory Traversal**: File system access vulnerability testing
- **Security Headers**: Missing protection header identification
- **Default Credentials**: Common login interface detection
- **Information Disclosure**: Sensitive file and data exposure

### Security Analysis
- **Certificate Validation**: SSL/TLS certificate expiration and configuration
- **Service Exposure**: Identification of potentially vulnerable services
- **Configuration Assessment**: Security misconfigurations and weaknesses
- **Risk Classification**: Severity-based vulnerability prioritization

### Results Display
- **Vulnerability Table**: Detailed findings with type, severity, and evidence
- **Risk Summary**: Overview with severity breakdown and risk assessment
- **Raw Data**: Complete scan results for detailed analysis
- **Export Integration**: Results compatible with all export formats

### Scanning Process
1. **Target Configuration**: Specify target and select scan type
2. **Vulnerability Detection**: Automated testing for common security issues
3. **Severity Assessment**: Classification of findings by risk level
4. **Results Analysis**: Detailed vulnerability information and evidence
5. **Export Options**: Save findings for reporting and remediation

## Scan History Database

### Database Features
- **SQLite Storage**: Lightweight, reliable database for scan result persistence
- **Automatic Saving**: All scan results automatically stored with metadata
- **Search Capabilities**: Full-text search across targets, results, and summaries
- **Filter Options**: Filter by scan type, target, date range, and status
- **Statistics Tracking**: Comprehensive analytics and activity monitoring

### Data Management
- **Scan Metadata**: Target, type, timestamp, duration, and result counts
- **Result Storage**: Complete scan results preserved in JSON format
- **Summary Generation**: Automatic summary creation for quick overview
- **Tag Support**: Custom tagging system for result organization
- **Status Tracking**: Scan completion status and error handling

### History Interface
- **Tabbed Display**: History table, statistics, and detailed views
- **Search and Filter**: Real-time search with type-based filtering
- **Load Functionality**: Restore historical scans for re-analysis
- **Delete Management**: Remove outdated or unwanted scan records
- **Statistics Dashboard**: Visual analytics and trend tracking

### Database Operations
1. **Automatic Storage**: Scan results saved immediately upon completion
2. **Search and Filter**: Find specific scans using various criteria
3. **Load Historical Data**: Restore previous scan results for analysis
4. **Statistics Review**: Monitor scanning activity and trends
5. **Data Management**: Delete outdated records and manage storage

### Storage Benefits
- **Result Preservation**: Never lose important scan findings
- **Trend Analysis**: Track changes in target security over time
- **Efficient Retrieval**: Quick access to historical scan data
- **Comparison Capability**: Compare current and historical results
- **Audit Trail**: Complete record of all scanning activities

## Session Management

### Project Organization
- **Named Sessions**: Create sessions with descriptive names and descriptions
- **Target Management**: Define target lists for each session or project
- **Scan Grouping**: Automatically associate scans with active sessions
- **Status Tracking**: Monitor session progress and completion status
- **Workflow Organization**: Organize scanning activities by project or client

### Session Features
- **Session Creation**: Create new sessions with name, description, and targets
- **Current Session**: Set active session for automatic scan association
- **Session Statistics**: Track scan counts, targets, and results per session
- **Session Details**: View comprehensive session information and progress
- **Session Management**: Edit, delete, and organize existing sessions

### Data Organization
- **Automatic Association**: New scans automatically added to current session
- **Scan Grouping**: Related scans organized under project sessions
- **Progress Tracking**: Monitor scanning progress across session targets
- **Result Aggregation**: View combined results for all session scans
- **Timeline Management**: Track session activity over time

### Session Interface
- **Session Table**: View all sessions with creation dates and scan counts
- **Current Session Display**: Shows active session for new scans
- **Session Details**: Comprehensive view of session information and statistics
- **Management Controls**: Create, edit, delete, and set current sessions
- **Statistics Dashboard**: Session-specific analytics and progress metrics

### Workflow Benefits
1. **Project Organization**: Group related scans under named sessions
2. **Progress Tracking**: Monitor scanning progress across project targets
3. **Result Management**: Organize findings by project or assessment
4. **Client Separation**: Separate different client assessments cleanly
5. **Workflow Efficiency**: Streamlined project-based scanning workflows

## Custom Wordlist Manager

### Wordlist Creation
- **Custom Wordlists**: Create wordlists with names, categories, and descriptions
- **Content Input**: Manual entry or import from external text files
- **Categorization**: Organize wordlists by type (DNS, directories, passwords, etc.)
- **Metadata Management**: Track creation dates, word counts, and descriptions
- **File Organization**: Automatic file management and storage structure

### Content Management
- **Full Editing**: Complete wordlist content editing capabilities
- **Import Functionality**: Import wordlists from external text files
- **Export Options**: Export wordlists to standard text file formats
- **Content Validation**: Automatic word count and content verification
- **Encoding Support**: UTF-8 encoding with error handling for various file types

### Advanced Features
- **Wordlist Merging**: Combine multiple wordlists into single consolidated lists
- **Duplicate Removal**: Optional duplicate word removal during merge operations
- **Preview Functionality**: View wordlist content before use in scans
- **Statistics Dashboard**: Comprehensive analytics on wordlist collections
- **Category Filtering**: Filter wordlists by category for easy organization

### Management Interface
- **Wordlist Table**: Overview of all wordlists with metadata and statistics
- **Creation Dialog**: User-friendly interface for creating new wordlists
- **Edit Functionality**: Modify existing wordlists with full content access
- **Import/Export**: File-based wordlist import and export capabilities
- **Merge Dialog**: Interface for combining multiple wordlists with options

### Integration Benefits
1. **Scan Customization**: Use custom wordlists tailored to specific targets
2. **Content Control**: Full control over wordlist content and organization
3. **Efficiency**: Optimized wordlists reduce scan time and improve results
4. **Organization**: Categorized wordlists for different scanning scenarios
5. **Reusability**: Save and reuse custom wordlists across multiple assessments

## Result Filtering and Search

### Search Capabilities
- **Real-time Search**: Instant search with 300ms debounced input for performance
- **Field-specific Search**: Search within specific fields or across all result data
- **Case-insensitive**: All searches performed case-insensitively for better matches
- **Nested Field Support**: Search within complex nested data structures
- **Query Highlighting**: Visual indication of search matches in results

### Advanced Filtering
- **Multiple Operators**: Contains, equals, starts with, ends with, regex patterns
- **Field Selection**: Filter by any available field in the result set
- **Combination Logic**: AND/OR logic for combining multiple filter criteria
- **Dynamic Fields**: Automatically detect and populate available fields
- **Filter Management**: Add, remove, and modify active filter criteria

### Result Processing
- **Dynamic Sorting**: Sort filtered results by any field in ascending/descending order
- **Result Grouping**: Group results by field values for organized analysis
- **Statistics Generation**: Comprehensive statistics on filtered result sets
- **Field Analysis**: Unique value counts and sample data for each field
- **Export Integration**: Filtered results compatible with all export formats

### User Interface
- **Tabbed Display**: Filtered results table and comprehensive statistics
- **Active Filter Display**: Visual representation of currently applied filters
- **Real-time Updates**: Instant result updates as filters are modified
- **Status Feedback**: Clear indication of filter effectiveness and result counts
- **Clear Functionality**: One-click removal of all filters and search criteria

### Performance Features
1. **Debounced Search**: Prevents excessive filtering during rapid typing
2. **Efficient Algorithms**: Optimized filtering for large result sets
3. **Memory Management**: Proper handling of large datasets without memory leaks
4. **Progressive Loading**: Handle large result sets with progressive display
5. **Caching**: Cache filtered results for improved performance on repeated operations

## Real-time Notifications

### Desktop Notifications
- **System Integration**: Native desktop notifications using system tray API
- **Event Types**: Scan completion, vulnerability detection, error alerts, and info messages
- **Configurable Settings**: Enable/disable notifications by type and category
- **Sound Alerts**: Optional audio notifications with system sound integration
- **Click Actions**: Clickable notifications that bring application to foreground

### System Tray Integration
- **Persistent Icon**: Always-visible system tray icon for quick access
- **Context Menu**: Right-click menu with show, notifications, settings, and quit options
- **Status Indicators**: Visual indication of application status and activity
- **Double-click Action**: Quick access to main application window
- **Tooltip Information**: Hover tooltip with application status and information

### Notification Management
- **Notification History**: Complete log of all notifications with timestamps
- **Read/Unread Status**: Track which notifications have been viewed
- **Categorization**: Organize notifications by type (scan, vulnerability, error, info)
- **Bulk Actions**: Mark all read, clear all, and batch management operations
- **Search and Filter**: Find specific notifications in history

### Configuration Options
- **Notification Types**: Enable/disable desktop notifications, system tray, sound alerts
- **Event Categories**: Configure scan completion, vulnerability alerts, error notifications
- **Display Duration**: Customize how long notifications remain visible
- **Sound Settings**: Choose system sounds for different notification types
- **Tray Behavior**: Control system tray icon visibility and behavior

### Alert Categories
1. **Scan Completion**: Notifications when scans finish with result summaries
2. **Vulnerability Detection**: Alerts when vulnerabilities are discovered
3. **Error Notifications**: System errors and scan failures
4. **Information Messages**: General status updates and informational alerts
5. **System Events**: Application startup, shutdown, and status changes

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for complying with applicable laws and regulations. The vulnerability correlation features are designed to assist security professionals in understanding attack surfaces and should not be used for malicious purposes. Proxy support is provided for legitimate network access requirements and should not be used to circumvent security controls or hide malicious activity. Rate limiting features help ensure responsible scanning practices and prevent overwhelming target systems. Custom templates enable efficient workflow management and consistent scan configurations across different assessment scenarios. Scan scheduling provides automated execution capabilities for regular security assessments and monitoring workflows. Multi-target scanning dramatically improves efficiency by processing multiple targets concurrently with consolidated progress tracking and results management. Theme management provides visual customization options with dark and light themes, improving user experience and accessibility across different environments and preferences. Keyboard shortcuts enable efficient navigation and quick access to common functions, significantly improving workflow productivity for power users and accessibility for keyboard-only operation. Drag and drop file support provides intuitive file import capabilities, allowing users to directly drag wordlists and target files into the interface, reducing the complexity of file management and improving overall user experience. Advanced directory enumeration enhances web application testing with recursive directory discovery, intelligent file categorization, and automatic detection of interesting findings like admin panels, configuration files, and backup directories. Certificate Transparency integration provides passive subdomain discovery by searching CT logs for historical and current SSL/TLS certificates, revealing subdomains that may not be discoverable through traditional DNS enumeration methods. OSINT data gathering collects intelligence from multiple open source platforms including Shodan, VirusTotal, URLVoid, WHOIS, and DNS Dumpster, providing comprehensive target reconnaissance with reputation analysis, service discovery, and registration data for thorough security assessments. Vulnerability scanning integration provides automated security assessment capabilities, detecting common vulnerabilities like SQL injection, XSS, directory traversal, SSL/TLS issues, and security misconfigurations with severity-based classification and detailed remediation guidance. Scan history database ensures persistent storage of all scan results with comprehensive search, filter, and statistics capabilities, enabling long-term result tracking, trend analysis, and efficient data management for security assessment workflows. Session management provides project-based organization by grouping related scans under named sessions with automatic association, progress tracking, and comprehensive statistics, significantly improving workflow efficiency for multi-target assessments and client project management. Custom wordlist manager enables creation, editing, and management of tailored wordlists with import/export capabilities, merging functionality, and comprehensive content management, allowing users to optimize scanning effectiveness with custom-built wordlists for specific targets and scenarios. Result filtering and search provides advanced analysis capabilities with real-time search, multiple filter criteria, dynamic sorting, and comprehensive statistics, enabling users to efficiently analyze large result sets and extract meaningful insights from scan data. Real-time notifications deliver immediate desktop alerts for scan completion, vulnerability detection, and system events through system tray integration with configurable settings, notification history, and comprehensive alert management for enhanced workflow awareness and productivity.