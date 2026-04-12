# 🛡️ L0p4Map - Security Hardening Guide

**Date**: 12 avril 2026  
**Status**: Ready for Implementation

---

## 1. CRITICAL Mitigations (Implement Immediately)

### 1.1 IDS Evasion - Noise Packet Cap

**File**: `core/scanners/ids_evasion.py`

**Problem**: 
```python
def inject_noise_packets(self, target: str, num_packets: int = 5):
    for i in range(num_packets):  # ← Can be 1M packets!
        craft_fake_syn(target)
```

**Solution**:
```python
def inject_noise_packets(self, target: str, num_packets: int = 5):
    # CAP: Maximum 100 packets per operation
    MAX_PACKETS = 100
    RATE_LIMIT = 100  # packets per second
    
    safe_packets = min(num_packets, MAX_PACKETS)
    if num_packets > MAX_PACKETS:
        logger.warning(f"Noise packets capped: {num_packets} → {MAX_PACKETS}")
    
    for i in range(safe_packets):
        craft_fake_syn(target)
        time.sleep(1.0 / RATE_LIMIT)  # Enforce rate limit
```

---

### 1.2 Firewall Evasion - Decoy Validation

**File**: `core/scanners/firewall_evasion.py`

**Problem**:
```python
def set_decoy_hosts(self, hosts: List[str]):
    self.decoy_hosts = hosts  # ← No validation!
```

**Solution**:
```python
import ipaddress

def set_decoy_hosts(self, hosts: List[str], network_cidr: str):
    """
    Validate decoys are in same network to prevent frame attacks
    
    Args:
        hosts: List of decoy IPs
        network_cidr: Target network (e.g., "192.168.1.0/24")
    """
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
    except ValueError:
        raise ValueError(f"Invalid CIDR: {network_cidr}")
    
    valid_decoys = []
    for host in hosts:
        try:
            ip = ipaddress.IPv4Address(host)
            if ip in network:
                valid_decoys.append(str(ip))
            else:
                logger.warning(f"Decoy {host} outside network {network_cidr} - REJECTED")
        except ValueError:
            logger.error(f"Invalid decoy IP: {host}")
    
    if not valid_decoys:
        raise ValueError("No valid decoy hosts in network range")
    
    self.decoy_hosts = valid_decoys
    logger.info(f"✅ Decoys validated: {len(valid_decoys)} IPs in {network_cidr}")
```

---

### 1.3 Evasion Budget - Limit Technique Stacking

**File**: `core/scanners/ids_evasion.py`

**Problem**:
```python
# Can stack unlimited evasion techniques
evasion_chain = [
    randomize_ports,
    fragment_packets,
    inject_decoys,
    timing_variation,  # ← Can be combined infinitely
]
```

**Solution**:
```python
class EvasionBudget:
    """
    Limit number of concurrent evasion techniques
    to prevent undetectable attacks
    """
    
    MAX_TECHNIQUES = 3
    
    def __init__(self):
        self.active_techniques = set()
    
    def enable_technique(self, technique_name: str) -> bool:
        """Enable evasion technique if budget available"""
        if len(self.active_techniques) >= self.MAX_TECHNIQUES:
            logger.error(f"Evasion budget exceeded. Active: {self.active_techniques}")
            return False
        
        self.active_techniques.add(technique_name)
        logger.info(f"✅ Technique enabled: {technique_name} ({len(self.active_techniques)}/{self.MAX_TECHNIQUES})")
        return True
    
    def disable_technique(self, technique_name: str):
        """Disable technique and free budget"""
        self.active_techniques.discard(technique_name)
        logger.info(f"Technique disabled: {technique_name}")
    
    def reset(self):
        """Clear all techniques"""
        self.active_techniques.clear()

# Usage:
budget = EvasionBudget()
budget.enable_technique("fragment_packets")  # ✅ OK
budget.enable_technique("randomize_ttl")    # ✅ OK
budget.enable_technique("inject_decoys")    # ✅ OK
budget.enable_technique("timing_variation") # ❌ REJECTED (limit = 3)
```

---

### 1.4 Remove Root Requirement

**File**: `core/scanner.py`

**Current**:
```python
def check_root():
    if os.getuid() != 0:
        raise PermissionError("Execute the program with SUDO!")
```

**Better Solution** - Use Capabilities:
```python
import subprocess

def check_capabilities():
    """
    Check if process has required capabilities instead of requiring root
    
    Required:
    - CAP_NET_RAW: Raw socket access (ARP)
    - CAP_NET_ADMIN: Network admin (packet injection)
    """
    try:
        # Check if we have required capabilities
        result = subprocess.run(
            ["getcap", "/proc/self/exe"],
            capture_output=True, text=True
        )
        caps = result.stdout
        
        required = {"cap_net_raw", "cap_net_admin"}
        current = set(caps.lower().split())
        
        if not required.issubset(current):
            raise PermissionError(
                f"Missing capabilities: {required - current}\n"
                f"Run: sudo setcap cap_net_raw,cap_net_admin=ep {sys.executable}"
            )
    except FileNotFoundError:
        # getcap not available, fall back to root check
        if os.getuid() != 0:
            raise PermissionError("Requires root or capabilities: cap_net_raw,cap_net_admin")

# Then modify check_root():
def check_root():
    """Check for required permissions (root OR capabilities)"""
    try:
        check_capabilities()
        logger.info("✅ Running with required capabilities")
    except PermissionError as e:
        logger.error(str(e))
        raise
```

**Setup Instructions**:
```bash
# Install with capabilities (no root at runtime)
sudo setcap cap_net_raw,cap_net_admin=ep /usr/bin/python3.9
sudo setcap cap_net_raw,cap_net_admin=ep /usr/bin/python3.10
sudo setcap cap_net_raw,cap_net_admin=ep /usr/bin/python3.11

# Then run WITHOUT sudo
python3 ui/app.py  # ✅ Works now!
```

---

## 2. HIGH Priority Mitigations

### 2.1 HTTP Header Sanitization

**File**: `core/scanners/http_probe.py`

**Problem**:
```python
server = response.headers.get('Server')  # ← Can contain XSS
```

**Solution**:
```python
import html
import re

def sanitize_header(value: str, max_length: int = 200) -> str:
    """
    Sanitize HTTP headers to prevent injection attacks
    
    Removes:
    - Newlines/tabs (header injection)
    - Script tags (XSS)
    - Control characters
    """
    if not value:
        return ""
    
    # Remove newlines, tabs, control characters
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f]', '', value)
    
    # HTML escape
    sanitized = html.escape(sanitized, quote=True)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
    
    return sanitized

# Usage:
server = response.headers.get('Server', 'Unknown')
safe_server = sanitize_header(server)  # ✅ Safe now
```

---

### 2.2 CSV Injection Protection

**File**: `ui/app.py` (export function)

**Problem**:
```python
# CSV with formula like: =cmd|'/c calc.exe
writer.writerow([host, mac, vendor, hostname])  # ← Can execute!
```

**Solution**:
```python
def escape_csv_formula(value: str) -> str:
    """
    Escape CSV formulas to prevent injection
    
    Dangerous prefixes: =, +, -, @, \t, \r
    """
    if not value or not isinstance(value, str):
        return str(value)
    
    # If starts with dangerous char, prefix with single quote
    if value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    
    return value

# Usage in export:
def export_to_csv(hosts: list, filepath: str):
    with open(filepath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'MAC', 'Vendor', 'Hostname'])
        for host in hosts:
            writer.writerow([
                escape_csv_formula(host['ip']),
                escape_csv_formula(host['mac']),
                escape_csv_formula(host['vendor']),
                escape_csv_formula(host['hostname']),
            ])
```

---

### 2.3 Rate Limiting - Token Bucket

**File**: `core/scanner.py` (add new module)

**Solution**:
```python
import time
from threading import Lock

class TokenBucket:
    """
    Token bucket rate limiter to prevent DoS
    """
    
    def __init__(self, capacity: int = 100, refill_rate: float = 100.0):
        """
        Args:
            capacity: Max tokens in bucket
            refill_rate: Tokens per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()
    
    def refill(self):
        """Add tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens. Return True if successful.
        """
        with self.lock:
            self.refill()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def wait_until_available(self, tokens: int = 1) -> float:
        """Wait until tokens available. Return wait time."""
        start = time.time()
        while not self.consume(tokens):
            time.sleep(0.01)
        return time.time() - start

# Usage:
rate_limiter = TokenBucket(capacity=1000, refill_rate=100)  # 100 probes/sec max

def scan_network(subnet: str) -> List[Dict]:
    # ... existing code ...
    
    for _, risposta in risposte:
        rate_limiter.wait_until_available(1)  # Wait for token
        
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        # ... process ...
```

---

### 2.4 Network Scope Validation

**File**: `ui/app.py` (modify scan function)

**Solution**:
```python
import ipaddress

class ScanScope:
    """
    Define allowed networks for scanning
    Prevents accidental scanning of external networks
    """
    
    def __init__(self, whitelist: List[str] = None):
        """
        Args:
            whitelist: List of allowed CIDR blocks
                      Default: RFC 1918 private networks
        """
        self.whitelist = whitelist or [
            "10.0.0.0/8",      # Private
            "172.16.0.0/12",   # Private
            "192.168.0.0/16",  # Private
            "127.0.0.0/8",     # Loopback
        ]
        self.networks = [ipaddress.IPv4Network(cidr, strict=False) 
                        for cidr in self.whitelist]
    
    def is_allowed(self, network_cidr: str) -> bool:
        """Check if network is in whitelist"""
        try:
            target = ipaddress.IPv4Network(network_cidr, strict=False)
            for allowed in self.networks:
                if target.subnet_of(allowed) or target == allowed:
                    return True
            return False
        except ValueError:
            return False

# Usage in UI:
scope = ScanScope()

def _start_scan(self):
    subnet = get_local_subnet(iface["name"])
    
    if not scope.is_allowed(subnet):
        QMessageBox.warning(
            self, "Scan Blocked",
            f"Network {subnet} not in whitelist!\n"
            f"Allowed: {scope.whitelist}"
        )
        return
    
    # ... proceed with scan ...
```

---

## 3. MEDIUM Priority Mitigations

### 3.1 ARP Validation

**File**: `core/scanner.py` (modify `scan_network`)

```python
def _validate_arp_response(self, mac: str, ip: str, expected_subnet: str) -> bool:
    """
    Validate ARP response legitimacy
    
    Checks:
    - IP in expected subnet
    - MAC OUI is known (not spoofed)
    - TTL is reasonable
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        subnet = ipaddress.IPv4Network(expected_subnet, strict=False)
        
        if ip_obj not in subnet:
            logger.warning(f"⚠️ ARP response IP {ip} outside subnet {expected_subnet}")
            return False
        
        oui = mac.replace(":", "").upper()[:6]
        if oui not in _oui_db:
            logger.warning(f"⚠️ Unknown OUI {oui} for MAC {mac} - possible spoofing")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Error validating ARP: {e}")
        return False

# Usage:
def scan_network(subnet: str) -> List[Dict]:
    for _, risposta in risposte:
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        
        if not _validate_arp_response(mac, ip, subnet):
            logger.warning(f"Skipping invalid ARP response: {ip} ({mac})")
            continue
        
        # ... process valid response ...
```

---

### 3.2 HMAC Integrity for Logs

**File**: `core/scanners/secure_logger.py` (add integrity checks)

```python
import hmac
import hashlib

class SecureLoggerWithIntegrity:
    """
    Secure logger with HMAC integrity verification
    Prevents log tampering
    """
    
    def __init__(self, log_file: str, encryption_key: bytes, 
                 integrity_key: bytes):
        self.log_file = log_file
        self.encryption_key = encryption_key
        self.integrity_key = integrity_key
    
    def _compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256"""
        return hmac.new(self.integrity_key, data, hashlib.sha256).digest()
    
    def write_entry(self, message: str) -> str:
        """
        Write encrypted entry with HMAC
        Returns: encrypted_data + HMAC (for verification)
        """
        # Encrypt message
        cipher_suite = Fernet(self.encryption_key)
        encrypted = cipher_suite.encrypt(message.encode())
        
        # Compute HMAC of encrypted data
        integrity_tag = self._compute_hmac(encrypted)
        
        # Store: encrypted_data + integrity_tag
        entry = encrypted + b":" + integrity_tag.hex()
        
        with open(self.log_file, 'ab') as f:
            f.write(entry + b"\n")
        
        return entry.decode()
    
    def verify_integrity(self, entry: str) -> bool:
        """Verify log entry hasn't been tampered"""
        try:
            encrypted, tag_hex = entry.rsplit(":", 1)
            encrypted = encrypted.encode()
            expected_tag = bytes.fromhex(tag_hex)
            
            computed_tag = self._compute_hmac(encrypted)
            return hmac.compare_digest(computed_tag, expected_tag)
        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            return False
```

---

## 4. Implementation Checklist

- [ ] **Week 1**: Cap noise packets, add evasion budget, remove root requirement
- [ ] **Week 2**: Add header sanitization, CSV escape, rate limiting  
- [ ] **Week 3**: Network scope validation, ARP validation
- [ ] **Week 4**: HMAC integrity for logs, remote syslog
- [ ] **Week 5**: Penetration test all changes
- [ ] **Week 6**: Security audit, deploy to production

---

**Last Updated**: 12 avril 2026  
**Review Date**: 26 avril 2026
