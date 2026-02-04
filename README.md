# Network Port Scanner

A Python-based network port scanning tool similar to Nmap.

## Features
- Single IP and IP range scanning
- TCP port scanning
- Service detection on open ports
- Multi-threaded scanning for speed
- Export results to JSON/CSV

## Installation

```bash
# Clone or download the project
cd port-scanner

# Install dependencies
pip install -r requirements.txt --break-system-packages
```

## Usage

### Basic Scan
```bash
python3 scanner.py -t 192.168.1.1 -p 1-100
```

### Scan Specific Ports
```bash
python3 scanner.py -t 192.168.1.1 -p 22,80,443,8080
```

### Scan with Service Detection
```bash
python3 scanner.py -t 192.168.1.1 -p 1-1000 -s
```

### Export Results
```bash
python3 scanner.py -t 192.168.1.1 -p 1-1000 -o results.json
```

## Project Structure
```
port-scanner/
├── scanner.py          # Main entry point
├── core/
│   ├── __init__.py
│   ├── port_scanner.py # Port scanning logic
│   ├── service_detector.py # Service detection
│   └── utils.py        # Helper functions
├── data/
│   └── services.json   # Common port-service mappings
├── results/            # Output directory
├── requirements.txt
└── README.md
```

## Future Enhancements
- OS fingerprinting
- Vulnerability detection
- Network mapping
- Banner grabbing improvements
- GUI interface