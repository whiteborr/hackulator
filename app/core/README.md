# Hackulator: Advanced Security Assessment and Reconnaissance Framework

Hackulator is a comprehensive security assessment and reconnaissance framework that provides automated scanning, vulnerability detection, and intelligence gathering capabilities. It combines multiple security tools and techniques into a unified, user-friendly interface with advanced result filtering, memory management, and distributed scanning capabilities.

The framework offers powerful features including:
- Multi-threaded scanning with intelligent rate limiting
- Advanced result filtering and pattern detection
- Comprehensive scan history and session management
- Automated vulnerability correlation and risk assessment
- OSINT collection and threat intelligence integration
- Customizable templates and wordlists
- Drag-and-drop file support
- Memory-optimized operations
- Executive summary generation

## Repository Structure
```
app/
└── core/
    ├── advanced_dir_enum.py       # Enhanced directory enumeration with recursive scanning
    ├── api_integration.py         # External API integrations (Shodan, VirusTotal, URLVoid)
    ├── base_worker.py            # Base worker class for command execution
    ├── cache_manager.py          # File-based caching system for scan results
    ├── cert_transparency.py      # Certificate Transparency log searching
    ├── connection_pool.py        # HTTP connection pooling and retry handling
    ├── distributed_scanning.py   # Distributed scanning coordination
    ├── memory_manager.py         # Memory usage monitoring and optimization
    ├── ml_pattern_detection.py   # Machine learning-based pattern detection
    ├── plugin_manager.py         # Plugin system for extensibility
    ├── rate_limiter.py          # Global rate limiting for scanning operations
    ├── result_filter.py         # Advanced result filtering and search
    ├── scan_database.py         # SQLite database for scan history
    ├── scan_controller.py       # Scan process control and management
    ├── template_manager.py      # Scan template management
    ├── threat_intelligence.py   # Threat intelligence feed integration
    └── vulnerability_correlator.py # Vulnerability correlation and analysis
```

## Core Components Documentation

### advanced_dir_enum.py
**Purpose**: Provides enhanced directory enumeration with recursive scanning capabilities.
**Key Features**:
- Recursive directory scanning up to specified depth
- Concurrent request handling
- Integration with proxy and rate limiting
- Progress monitoring and callback support

**Usage**:
```python
from app.core.advanced_dir_enum import AdvancedDirectoryEnumerator

enumerator = AdvancedDirectoryEnumerator()
results = enumerator.enumerate_directories(
    target_url="https://example.com",
    wordlist_path="/path/to/wordlist.txt"
)
```

**Suggested Improvements**:
- Add pattern-based directory filtering
- Implement smart throttling based on server responses
- Add support for custom status code handling

### api_integration.py
**Purpose**: Manages external API integrations with security services.
**Key Features**:
- Shodan API integration
- VirusTotal API integration
- URLVoid API integration
- Custom API request support

**Usage**:
```python
from app.core.api_integration import APIIntegration

api = APIIntegration()
results = api.query_shodan("192.168.1.1", api_key="your_api_key")
```

**Suggested Improvements**:
- Add rate limiting per API service
- Implement API response caching
- Add more security service integrations

### base_worker.py
**Purpose**: Provides base worker class for executing shell commands safely and consistently.
**Key Features**:
- Standard signals for worker threads
- Safe subprocess command execution
- Timeout handling
- Exception management

**Usage**:
```python
from app.core.base_worker import CommandWorker

worker = CommandWorker("nmap -sV example.com", "Port Scan")
worker.run()
```

**Suggested Improvements**:
- Add command validation
- Implement resource usage monitoring
- Add command output filtering

### cache_manager.py
**Purpose**: Implements file-based caching system for scan results.
**Key Features**:
- TTL-based caching
- Thread-safe operations
- Automatic cache cleanup
- JSON-based storage

**Usage**:
```python
from app.core.cache_manager import cache_manager

# Cache scan results
cache_manager.set("port_scan", "example.com", results)

# Retrieve cached results
cached_results = cache_manager.get("port_scan", "example.com")
```

**Suggested Improvements**:
- Add memory-based caching option
- Implement cache compression
- Add cache statistics tracking

### connection_pool.py
**Purpose**: Manages HTTP connection pooling and retry handling.
**Key Features**:
- Connection pooling
- Automatic retry strategy
- Custom headers support
- Session management

**Usage**:
```python
from app.core.connection_pool import connection_pool

session = connection_pool.get_session()
response = session.get("https://example.com")
```

**Suggested Improvements**:
- Add connection monitoring
- Implement connection limits per domain
- Add proxy rotation support

### distributed_scanning.py
**Purpose**: Manages distributed scanning operations across multiple nodes.
**Key Features**:
- Coordinator server for managing scanning nodes
- Node discovery and registration
- Scan distribution based on node capabilities
- Result collection and aggregation

**Usage**:
```python
from app.core.distributed_scanning import DistributedScanner

scanner = DistributedScanner()
scanner.start_coordinator()
scanner.distribute_scan(targets, scan_type="port_scan")
```

**Suggested Improvements**:
- Add node health monitoring
- Implement load balancing
- Add secure node authentication

### memory_manager.py
**Purpose**: Monitors and optimizes application memory usage.
**Key Features**:
- Memory usage monitoring
- Automatic garbage collection
- Memory optimization triggers
- Background monitoring process

**Usage**:
```python
from app.core.memory_manager import MemoryManager

manager = MemoryManager()
manager.start_monitoring()
current_usage = manager.get_memory_usage()
```

**Suggested Improvements**:
- Add memory profiling
- Implement memory leak detection
- Add custom optimization strategies

### ml_pattern_detection.py
**Purpose**: Analyzes scan results using machine learning to detect patterns and anomalies.
**Key Features**:
- Pattern detection in DNS, port, and HTTP results
- Anomaly detection using historical data
- Common prefix and pattern extraction
- Actionable insight generation

**Usage**:
```python
from app.core.ml_pattern_detection import MLPatternDetection

detector = MLPatternDetection()
patterns = detector.analyze_scan_results(results, "dns_enum")
```

**Suggested Improvements**:
- Add more ML algorithms
- Implement pattern classification
- Add custom pattern definitions

### plugin_manager.py
**Purpose**: Manages the loading and execution of custom plugins.
**Key Features**:
- Dynamic plugin loading
- Plugin execution management
- Plugin event signals
- Base plugin class definition

**Usage**:
```python
from app.core.plugin_manager import PluginManager

manager = PluginManager()
manager.load_plugins()
manager.execute_plugin("plugin_name", args)
```

**Suggested Improvements**:
- Add plugin dependencies
- Implement plugin versioning
- Add plugin sandboxing

### rate_limiter.py
**Purpose**: Provides global rate limiting for scanning operations.
**Key Features**:
- Request rate limiting
- Concurrent thread limiting
- Tool-specific rate limits
- Burst control

**Usage**:
```python
from app.core.rate_limiter import rate_limiter

rate_limiter.set_rate_limit(10, concurrent_threads=50)
rate_limiter.wait_if_needed("tool_name")
```

**Suggested Improvements**:
- Add dynamic rate adjustment
- Implement per-domain limits
- Add rate limit persistence

### result_filter.py
**Purpose**: Provides advanced filtering and search capabilities for scan results.
**Key Features**:
- Multiple filter criteria support
- Complex search queries
- Result sorting and grouping
- Statistical analysis

**Usage**:
```python
from app.core.result_filter import ResultFilter

filter = ResultFilter()
filtered_results = filter.apply_filters(results, criteria)
```

**Suggested Improvements**:
- Add regex pattern matching
- Implement result caching
- Add custom filter functions

### scan_controller.py
**Purpose**: Controls scan execution with pause, resume, and stop capabilities.
**Key Features**:
- Scan process control
- State management
- Progress monitoring
- Status notifications

**Usage**:
```python
from app.core.scan_controller import ScanController

controller = ScanController()
controller.start()
controller.pause()
controller.resume()
```

**Suggested Improvements**:
- Add scan queuing
- Implement priority control
- Add scan dependencies

### template_manager.py
**Purpose**: Manages scan templates for different types of assessments.
**Key Features**:
- Template creation and management
- Default template presets
- Template import/export
- Template customization

**Usage**:
```python
from app.core.template_manager import TemplateManager

manager = TemplateManager()
template = manager.load_template("Quick Web Scan")
```

**Suggested Improvements**:
- Add template versioning
- Implement template sharing
- Add template validation

### threat_intelligence.py
**Purpose**: Integrates with threat intelligence feeds to check indicators of compromise.
**Key Features**:
- Multiple feed integration
- IOC checking and validation
- Feed status monitoring
- Comprehensive IOC summary

**Usage**:
```python
from app.core.threat_intelligence import ThreatIntelligence

ti = ThreatIntelligence()
results = ti.check_ioc("example.com")
```

**Suggested Improvements**:
- Add custom feed support
- Implement feed caching
- Add IOC correlation

### vulnerability_correlator.py
**Purpose**: Correlates findings to identify attack chains and security gaps.
**Key Features**:
- Finding correlation analysis
- Attack chain detection
- Risk amplifier identification
- Security gap detection

**Usage**:
```python
from app.core.vulnerability_correlator import VulnerabilityCorrelator

correlator = VulnerabilityCorrelator()
analysis = correlator.correlate_findings(scan_results)
```

**Suggested Improvements**:
- Add custom correlation rules
- Implement risk scoring
- Add mitigation suggestions

### cert_transparency.py
**Purpose**: Provides certificate transparency log searching capabilities.
**Key Features**:
- Multiple CT log source support
- Subdomain extraction
- Certificate details retrieval
- Proxy integration

**Usage**:
```python
from app.core.cert_transparency import CertificateTransparencyClient

client = CertificateTransparencyClient()
results = client.search_certificates("example.com")
```

**Suggested Improvements**:
- Add certificate validation
- Implement result caching
- Add more CT log sources

[Continue with all core components...]

## Usage Instructions
[Previous usage instructions remain unchanged...]

## Data Flow
[Previous data flow section remains unchanged...]