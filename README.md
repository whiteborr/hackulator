# Hackulator

A cybersecurity enumeration toolkit built with PyQt6, featuring a futuristic alien tablet-themed interface for DNS enumeration and reconnaissance tasks.

## Features

- **Modern GUI Interface**: Alien tablet-themed design with custom animations and styling
- **DNS Enumeration**: Comprehensive hostname enumeration with wildcard detection
- **Multi-threaded Operations**: Concurrent DNS queries for improved performance
- **Customizable Record Types**: Support for A, AAAA, CNAME, MX, and TXT records
- **Wordlist Integration**: Built-in wordlist support for subdomain discovery
- **Real-time Output**: Live terminal-style output with color-coded results

## Project Structure

```
hackulator/
├── app/
│   ├── core/
│   │   └── custom_scripts.py      # DNS enumeration worker threads
│   ├── pages/
│   │   ├── home_page.py           # Main navigation page
│   │   └── enumeration_page.py    # DNS enumeration interface
│   ├── widgets/
│   │   └── animated_stacked_widget.py  # Page transition animations
│   ├── main_window.py             # Main application window
│   └── theme_manager.py           # Theme and resource management
├── resources/
│   ├── fonts/
│   │   └── neuropol.otf           # Custom font
│   ├── icons/                     # UI icons (1.png - 1J.png)
│   ├── themes/default/
│   │   ├── *.png                  # Background images
│   │   ├── style.qss              # Qt stylesheets
│   │   └── theme.json             # Theme configuration
│   └── wordlists/
│       └── subdomains-top1000.txt # Default wordlist
└── main.py                        # Application entry point
```

## Requirements

- Python 3.7+
- PyQt6
- dnspython

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd hackulator
```

2. Install dependencies:
```bash
pip install PyQt6 dnspython
```

3. Run the application:
```bash
python main.py
```

## Usage

### Home Page
- Navigate through different enumeration categories using the circular menu buttons
- Hover over buttons to see detailed descriptions in the info panel
- Click "ENUMERATION" to access DNS tools

### DNS Enumeration
- **Target Input**: Enter the domain to enumerate (e.g., example.com)
- **Wordlist Selection**: Choose from available wordlists or add custom ones
- **Record Types**: Select DNS record types to query (A, AAAA, CNAME, MX, TXT)
- **HOSTS Button**: Start hostname enumeration with selected parameters

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