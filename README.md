# Hackulator

A comprehensive penetration testing toolkit built with PyQt6, featuring a complete enumeration suite with modern GUI interface.

## Features

- **Complete Enumeration Suite**: 8 different enumeration tools
- **Modern GUI Interface**: Alien tablet-themed design with custom animations
- **Multi-threaded Operations**: Concurrent scanning for improved performance
- **Export Functionality**: Results in JSON, CSV, and XML formats
- **Real-time Output**: Live terminal-style output with progress tracking
- **Customizable**: Configurable wordlists and scan parameters

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

- Python 3.8+
- PyQt6
- requests
- dnspython

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd hackulator
```

2. Install dependencies:
```bash
pip install PyQt6 dnspython requests
```

3. Run the application:
```bash
python main.py
```

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
5. **Export Results**: Save results in JSON, CSV, or XML format

### Tool-Specific Usage
- **DNS**: Domain enumeration with wordlists and record types
- **Port Scan**: TCP scans, network sweeps, service detection
- **SMB**: NetBIOS queries, OS detection, range scanning
- **SMTP**: User enumeration via VRFY/EXPN/RCPT TO
- **SNMP**: Community testing, SNMP walks, device discovery
- **HTTP**: Server fingerprinting, SSL analysis, directory scanning
- **API**: Endpoint discovery, method testing, auth bypass
- **Database**: Port scanning, service detection, connection testing

### Features in Detail

#### Wildcard Detection
- Automatically detects wildcard DNS configurations
- Filters out false positives from wildcard responses
- Displays detection status in real-time

#### Multi-threaded Scanning
- Concurrent DNS queries (50 threads by default)
- Organized output by record type
- Alphabetically sorted results

#### Real-time Output
- Color-coded terminal output
- Live status updates
- Scrollable results panel

## Architecture

### Core Components

#### WorkerSignals (custom_scripts.py)
- `output`: Emits formatted scan results
- `status`: Provides operation status updates
- `finished`: Signals completion
- `wildcard_result`: Reports wildcard detection

#### HostWordlistWorker (custom_scripts.py)
- QRunnable-based worker for DNS enumeration
- Implements wildcard detection and filtering
- Handles concurrent DNS queries with proper result aggregation

#### Theme System
- JSON-based theme configuration
- Dynamic resource path resolution
- QSS stylesheet integration

#### Page Navigation
- Animated transitions between pages
- Signal-based navigation system
- Responsive layout scaling

## Customization

### Adding Wordlists
Place `.txt` files in `resources/wordlists/` directory. They will automatically appear in the wordlist dropdown.

### Modifying Themes
Edit `resources/themes/default/theme.json` to customize:
- Background images
- Color schemes
- Font settings

### Extending Functionality
The modular architecture allows easy addition of new enumeration tools by:
1. Adding new worker classes in `core/custom_scripts.py`
2. Creating corresponding UI elements in enumeration pages
3. Implementing signal connections for real-time updates

## Technical Details

### DNS Enumeration Process
1. **Wildcard Detection**: Tests random subdomains to identify wildcard responses
2. **Concurrent Queries**: Processes wordlist entries using ThreadPoolExecutor
3. **Result Aggregation**: Collects and sorts results by record type
4. **Output Formatting**: Generates HTML-formatted output for display

### Performance Optimizations
- Thread pool management for controlled concurrency
- Result batching to minimize UI updates
- Efficient wildcard filtering to reduce false positives

### Error Handling
- Graceful handling of DNS timeouts and NXDOMAIN responses
- File not found protection for wordlists
- Network error recovery

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes following the existing architecture
4. Test thoroughly with various DNS configurations
5. Submit a pull request

## License

[Add your license information here]

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for complying with applicable laws and regulations.