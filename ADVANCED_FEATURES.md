# L0p4Map - Advanced Security Scanning Features

## Recent Enhancements (April 10, 2026)

### 1. **Passive Reconnaissance Module** (`core/scanners/passive_recon.py`)

Performs OSINT without triggering IDS/IPS systems. No packets are sent, only passive information gathering.

#### Features:
- **DNS Lookups**: A, AAAA, MX, TXT, NS, SOA records
- **Reverse DNS**: Hostname resolution from IP addresses
- **WHOIS Lookups**: Domain registration information
- **DNS Zone Transfer**: AXFR attempts (authorized domains only)
- **SSL Certificate Transparency**: Query CT logs for subdomains
- **No IDS/IPS Triggering**: Completely passive

#### Usage:
```python
from core.scanners import passive_recon_report, PassiveReconConfig

config = PassiveReconConfig()
config.dns_lookup = True
config.reverse_dns = True
config.whois_lookup = True

report = passive_recon_report('example.com', config)
```

---

### 2. **IDS/IPS Evasion Module** (`core/scanners/ids_evasion.py`)

Advanced techniques to evade intrusion detection and prevention systems.

#### Detection Methods:
- Response time analysis
- Packet drop detection
- Port filtering detection
- Reset attack detection
- Behavioral analysis

#### Evasion Techniques:
- **Scan Pattern Randomization**
  - Random order scanning
  - Reverse scanning (high to low ports)
  - Grouped scanning with delays
  - Weighted scanning (common ports mixed with rare)

- **Noise Injection**: Send decoy packets with various payloads
- **Adaptive Timing**: Adjust delays based on detected defenses
- **Protocol Switching**: Switch between TCP/UDP/ICMP if blocked
- **Payload Fragmentation**: Fragment payloads in unusual ways
- **Stealth HTTP**: Craft requests that blend with legitimate traffic
- **Honeypot Detection**: Identify potential honeypot systems

#### Usage:
```python
from core.scanners import IDSEvader

evader = IDSEvader()

# Randomize port scan pattern
ports = [80, 443, 22, 23, 445]
pattern = evader.randomize_scan_pattern(ports, pattern='weighted')

# Inject noise packets
noise = evader.inject_noise_packets('192.168.1.100', num_packets=5)

# Get evasion report
report = evader.generate_evasion_report()
```

---

### 3. **Secure Logging Module** (`core/scanners/secure_logger.py`)

Encrypted logging system for sensitive scan data, preventing forensic analysis.

#### Features:
- **Encrypted File Storage**: AES-256 encryption with Fernet
- **In-Memory Logging**: Optional volatile logging
- **Selective Field Encryption**: Choose which fields to encrypt
- **Log Rotation**: Automatic log file management
- **Activity Tracking**: Audit trail for all scans
- **Export Functionality**: Export encrypted log archives

#### Usage:
```python
from core.scanners import SecureLogger, ScanActivity

# Create secure logger
logger = SecureLogger(log_dir='./secure_logs', enable_encryption=True)

# Log scan results
log_id = logger.log_scan(
    scan_type='tcp_connect',
    target='192.168.1.1',
    results={'open_ports': [80, 443]},
    sensitive_fields=['open_ports']
)

# Log IDS detection
logger.log_ids_detection(
    detection_type='port_scan_detected',
    severity='high',
    description='Unusual port scanning activity detected'
)

# Track scan activity
activity = ScanActivity(logger)
activity.start_scan('scan_001', 'tcp_connect', '192.168.1.0/24')
```

---

### 4. **Enhanced Firewall Evasion** (Existing + improvements)

The firewall evasion module now works seamlessly with:
- IDS detection and adaptive responses
- Passive reconnaissance for information gathering
- Secure logging of evasion techniques
- Enhanced timing controls based on detected defenses

#### Configuration:
```python
from core.scanners import FirewallEvasionConfig, FirewallEvader

config = FirewallEvasionConfig()
config.timing_mode = 'sneaky'  # sneaky, polite, normal, aggressive, insane
config.use_decoys = True
config.decoy_count = 5
config.enable_fragmentation = True
config.randomize_source_port = True
config.randomize_ttl = True
config.randomize_packet_size = True

evader = FirewallEvader(config)
report = evader.generate_report()
```

---

## Architecture Overview

```
L0p4Map Core Scanner Modules
├── tcp_connect.py           (Pure Python TCP scanner)
├── http_probe.py            (HTTP(S) endpoint probing)
├── ssl_info.py              (SSL certificate inspection)
├── firewall_evasion.py      (Firewall evasion techniques)
├── tcp_connect_evasion.py   (Evasion-enabled TCP scanner)
├── ids_evasion.py          (IDS/IPS evasion)
├── passive_recon.py        (Passive reconnaissance)
├── secure_logger.py        (Encrypted logging)
└── nmap_adapter.py         (Optional nmap integration)
```

---

## Recommended Workflow

### 1. **Passive Information Gathering** (Stealthy)
```python
# Start with passive reconnaissance
config = PassiveReconConfig()
report = passive_recon_report('target.com', config)

# Log findings securely
logger = SecureLogger()
logger.log_scan('osint', 'target.com', report)
```

### 2. **Adaptive Scanning** (With Evasion)
```python
# Detect potential defenses
evader = IDSEvader()
ids_report = evader.generate_evasion_report()

# Adjust evasion settings based on detection
evasion_config = FirewallEvasionConfig()
evasion_config.use_decoys = ids_report['detection_signals']['active_defense_detected']

# Run scan with evasion
results = tcp_connect_scan_with_evasion(
    '192.168.1.1', 
    ports=[80, 443, 22, 23, 445],
    evasion_config=evasion_config
)

# Log encrypted results
logger.log_scan('tcp_evasion', '192.168.1.1', results, ['open_ports'])
```

### 3. **Advanced Evasion** (Highly Stealthy)
```python
# Use randomized patterns
evader = IDSEvader()
pattern = evader.randomize_scan_pattern(ports, pattern='grouped')

# Inject noise
noise_results = evader.inject_noise_packets(target, num_packets=10)

# Adaptive timing
delay = evader.adaptive_timing(base_delay=2.0)

# Log evasion activity
logger.log_evasion_technique('scan_pattern_randomization', 
                             {'pattern': 'grouped'}, True)
```

---

## Security & Legal Notice

⚠️ **IMPORTANT**: All scanning and evasion techniques are **FOR AUTHORIZED PENETRATION TESTING ONLY**

- Ensure you have explicit written authorization before scanning any systems
- Unauthorized network scanning is illegal in most jurisdictions
- Firewall evasion techniques may violate computer fraud laws
- Always comply with your organization's security policies
- Maintain detailed records of authorized testing activities

---

## Performance & Detection Prevention

### Mitigation Strategies:

| Threat | Mitigation |
|--------|-----------|
| **High-Frequency Scanning** | Use adaptive timing, randomize patterns |
| **Signature Detection** | Inject noise, fragment payloads, stealth HTTP |
| **Behavioral Analysis** | Randomize scan order, vary timing, use decoys |
| **Honeypot Detection** | Check for all ports open, identical responses |
| **Forensic Analysis** | Use encrypted logging, clear in-memory logs |

### Best Practices:

✅ Use passive reconnaissance first
✅ Enable adaptive timing based on network response
✅ Rotate between different evasion techniques
✅ Use encrypted logging for sensitive operations
✅ Clear logs after authorized testing
✅ Document all scanning activities
✅ Respect firewall rules and network policies

---

## Dependencies

### Required:
- `scapy` - Network packet manipulation
- `requests` - HTTP probing
- `dnspython` - DNS operations
- `cryptography` - Encrypted logging

### Optional:
- `python-nmap` - Nmap integration
- `paramiko` - SSH operations
- `pyopenssl` - Enhanced SSL/TLS support

Install all: `pip install -r requirements.txt`

---

## Testing

Run the test suite:
```bash
cd /Users/user/Downloads/L0p4Map
python -m pytest tests/ -v
```

Individual module tests:
```bash
python -c "from core.scanners import IDSEvader; print('✓ IDSEvader loaded')"
python -c "from core.scanners import passive_recon_report; print('✓ Passive recon loaded')"
python -c "from core.scanners import SecureLogger; print('✓ SecureLogger loaded')"
```

---

## Future Enhancements

- [ ] Proxy chain support (SOCKS5/HTTP)
- [ ] Tor integration for anonymized scanning
- [ ] Advanced masquerading techniques
- [ ] Machine learning-based evasion adaptation
- [ ] Real-time IDS/IPS detection and response
- [ ] Stealth exfiltration of scan results
- [ ] Multi-stage scan orchestration
- [ ] Collaborative scanning with distributed agents

---

## Author

**L0p4Map Security Scanner**  
Enhanced with advanced firewall evasion, IDS/IPS avoidance, and secure logging.

*"Authorized security testing only - With great power comes great responsibility"*
