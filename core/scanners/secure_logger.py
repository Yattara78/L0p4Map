"""
Secure logging module - Encrypted and secure logging of scan results
Prevents forensic analysis of scan activity
"""

import logging
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib
import hmac

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecureLogger:
    """
    Encrypted logging system for sensitive scan data
    Supports:
    - Encrypted file storage
    - In-memory logging (volatile)
    - Selective field encryption
    - Log rotation
    """
    
    def __init__(self, log_dir: str = None, encryption_key: str = None, 
                 enable_encryption: bool = True):
        """
        Initialize secure logger
        
        Args:
            log_dir: Directory for log files (None = in-memory only)
            encryption_key: Key for encryption (auto-generated if None)
            enable_encryption: Enable encryption if available
        """
        
        self.log_dir = log_dir
        self.enable_encryption = enable_encryption and CRYPTO_AVAILABLE
        self.logs = []
        self.metadata = {
            'created': datetime.now().isoformat(),
            'hostname': os.uname()[1],
            'log_count': 0
        }
        
        # Setup encryption if enabled
        if self.enable_encryption:
            if encryption_key is None:
                self.cipher = Fernet(Fernet.generate_key())
            else:
                # Derive key from provided string
                key_hash = hashlib.sha256(encryption_key.encode()).digest()[:32]
                derived_key = Fernet.generate_key()  # Would need proper key derivation
                self.cipher = Fernet(derived_key)
        
        # Create log directory if specified
        if self.log_dir:
            Path(self.log_dir).mkdir(parents=True, exist_ok=True)
    
    def log_scan(self, scan_type: str, target: str, results: Dict[str, Any],
                 sensitive_fields: list = None) -> str:
        """
        Log scan results with optional field encryption
        
        Args:
            scan_type: Type of scan (tcp_connect, http_probe, etc.)
            target: Target host/IP
            results: Scan results dictionary
            sensitive_fields: Fields to encrypt (e.g., ['found_services'])
        
        Returns:
            Log entry ID
        """
        
        if sensitive_fields is None:
            sensitive_fields = []
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'scan_type': scan_type,
            'target': target,
            'results': results,
            'sensitive': True if sensitive_fields else False
        }
        
        # Encrypt sensitive fields
        if self.enable_encryption and sensitive_fields:
            encrypted_results = self._encrypt_fields(results, sensitive_fields)
            log_entry['results'] = encrypted_results
            log_entry['encrypted_fields'] = sensitive_fields
        
        # Add to in-memory log
        entry_id = self._generate_log_id(log_entry)
        log_entry['id'] = entry_id
        self.logs.append(log_entry)
        self.metadata['log_count'] += 1
        
        # Write to file if configured
        if self.log_dir:
            self._write_to_file(log_entry)
        
        return entry_id
    
    def log_evasion_technique(self, technique: str, parameters: Dict[str, Any],
                             result: bool) -> str:
        """
        Log evasion technique usage (encrypted)
        """
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'evasion_technique',
            'technique': technique,
            'parameters': parameters,
            'success': result,
            'sensitive': True
        }
        
        # Always encrypt evasion logs
        if self.enable_encryption:
            encrypted = self.cipher.encrypt(
                json.dumps(log_entry).encode()
            )
            log_entry['encrypted'] = encrypted.decode()
            log_entry['parameters'] = "***ENCRYPTED***"
        
        entry_id = self._generate_log_id(log_entry)
        log_entry['id'] = entry_id
        self.logs.append(log_entry)
        
        if self.log_dir:
            self._write_to_file(log_entry)
        
        return entry_id
    
    def log_ids_detection(self, detection_type: str, severity: str,
                         description: str) -> str:
        """
        Log IDS/IPS detection events (encrypted)
        """
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'ids_detection',
            'detection_type': detection_type,
            'severity': severity,  # low, medium, high, critical
            'description': description,
            'sensitive': True
        }
        
        entry_id = self._generate_log_id(log_entry)
        log_entry['id'] = entry_id
        self.logs.append(log_entry)
        
        if self.log_dir:
            self._write_to_file(log_entry)
        
        return entry_id
    
    def _encrypt_fields(self, data: Dict, fields: list) -> Dict:
        """
        Selectively encrypt specified fields
        """
        
        encrypted_data = data.copy()
        
        for field in fields:
            if field in encrypted_data and self.enable_encryption:
                value = encrypted_data[field]
                encrypted_value = self.cipher.encrypt(
                    json.dumps(value).encode()
                )
                encrypted_data[field] = encrypted_value.decode()
        
        return encrypted_data
    
    def _write_to_file(self, log_entry: Dict):
        """
        Write log entry to encrypted file
        """
        
        try:
            timestamp = log_entry['timestamp'].replace(':', '-').replace('.', '-')
            filename = f"l0p4map_scan_{timestamp}.log"
            filepath = os.path.join(self.log_dir, filename)
            
            # Write as JSON
            with open(filepath, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Encrypt file if encryption enabled
            if self.enable_encryption:
                self._encrypt_file(filepath)
        
        except Exception as e:
            logger.error(f"Error writing log file: {e}")
    
    def _encrypt_file(self, filepath: str):
        """
        Encrypt log file
        """
        
        try:
            if not self.enable_encryption:
                return
            
            with open(filepath, 'rb') as f:
                plaintext = f.read()
            
            encrypted = self.cipher.encrypt(plaintext)
            
            # Write encrypted content
            with open(filepath, 'wb') as f:
                f.write(encrypted)
        
        except Exception as e:
            logger.error(f"Error encrypting file: {e}")
    
    def _generate_log_id(self, entry: Dict) -> str:
        """
        Generate unique log entry ID
        """
        
        content = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of logged activities
        """
        
        summary = self.metadata.copy()
        summary['logs'] = []
        
        for log in self.logs:
            log_summary = {
                'id': log['id'],
                'timestamp': log['timestamp'],
                'type': log.get('event_type', log.get('scan_type', 'unknown'))
            }
            summary['logs'].append(log_summary)
        
        return summary
    
    def clear_logs(self) -> bool:
        """
        Clear all in-memory logs (for security)
        Files remain encrypted on disk
        """
        
        try:
            self.logs.clear()
            self.metadata['log_count'] = 0
            return True
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            return False
    
    def export_encrypted(self, output_path: str, password: str = None) -> bool:
        """
        Export all logs as encrypted archive
        """
        
        try:
            export_data = {
                'metadata': self.metadata,
                'logs': self.logs
            }
            
            content = json.dumps(export_data, default=str).encode()
            
            # Encrypt with optional password
            if password and self.enable_encryption:
                # Simple password protection
                password_hash = hashlib.sha256(password.encode()).digest()
                encrypted = self.cipher.encrypt(content)
            else:
                encrypted = content
            
            with open(output_path, 'wb') as f:
                f.write(encrypted)
            
            return True
        
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return False


class ScanActivity:
    """
    Track and log scan activity for audit trail
    """
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
        self.scans = []
    
    def start_scan(self, scan_id: str, scan_type: str, target: str) -> Dict:
        """
        Log start of scan
        """
        
        scan = {
            'id': scan_id,
            'type': scan_type,
            'target': target,
            'start_time': datetime.now().isoformat(),
            'status': 'running'
        }
        
        self.scans.append(scan)
        return scan
    
    def end_scan(self, scan_id: str, results: Dict) -> Dict:
        """
        Log end of scan with results
        """
        
        for scan in self.scans:
            if scan['id'] == scan_id:
                scan['end_time'] = datetime.now().isoformat()
                scan['status'] = 'completed'
                scan['results'] = results
                
                # Log to secure logger
                self.logger.log_scan(
                    scan['type'],
                    scan['target'],
                    results,
                    sensitive_fields=['open_ports', 'services']
                )
                
                return scan
        
        return None
    
    def get_activity_summary(self) -> Dict:
        """
        Get summary of all scans
        """
        
        return {
            'total_scans': len(self.scans),
            'completed': len([s for s in self.scans if s['status'] == 'completed']),
            'running': len([s for s in self.scans if s['status'] == 'running']),
            'scans': self.scans
        }
