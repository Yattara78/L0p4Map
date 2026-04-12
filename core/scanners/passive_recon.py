"""
Passive reconnaissance module - OSINT without triggering IDS/IPS
No packets sent, purely information gathering via public APIs and DNS
"""

import socket
import dns.resolver
import dns.zone
import dns.query
import subprocess
import json
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class PassiveReconConfig:
    """Configuration for passive reconnaissance options"""
    
    def __init__(self):
        self.dns_lookup = True
        self.reverse_dns = True
        self.whois_lookup = True
        self.dns_zone_transfer = False  # Only on authorized domains
        self.ssl_cert_transparency = True
        self.subdomains = True
        
    def to_dict(self):
        return {
            'dns_lookup': self.dns_lookup,
            'reverse_dns': self.reverse_dns,
            'whois_lookup': self.whois_lookup,
            'dns_zone_transfer': self.dns_zone_transfer,
            'ssl_cert_transparency': self.ssl_cert_transparency,
            'subdomains': self.subdomains,
        }


def dns_lookup(hostname: str) -> Dict[str, List[str]]:
    """
    Perform DNS lookups (A, AAAA, MX, TXT, NS records)
    No network impact, completely passive
    """
    results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'TXT': [],
        'NS': [],
        'SOA': []
    }
    
    try:
        # A records (IPv4)
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            results['A'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"A record lookup failed: {e}")
        
        # AAAA records (IPv6)
        try:
            answers = dns.resolver.resolve(hostname, 'AAAA')
            results['AAAA'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"AAAA record lookup failed: {e}")
        
        # MX records (Mail servers)
        try:
            answers = dns.resolver.resolve(hostname, 'MX')
            results['MX'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"MX record lookup failed: {e}")
        
        # TXT records
        try:
            answers = dns.resolver.resolve(hostname, 'TXT')
            results['TXT'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"TXT record lookup failed: {e}")
        
        # NS records (Nameservers)
        try:
            answers = dns.resolver.resolve(hostname, 'NS')
            results['NS'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"NS record lookup failed: {e}")
        
        # SOA record
        try:
            answers = dns.resolver.resolve(hostname, 'SOA')
            results['SOA'] = [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"SOA record lookup failed: {e}")
            
    except Exception as e:
        logger.error(f"DNS lookup error for {hostname}: {e}")
    
    return results


def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """
    Perform reverse DNS lookup
    Completely passive - uses only standard DNS resolution
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except Exception as e:
        logger.debug(f"Reverse DNS lookup failed for {ip_address}: {e}")
        return None


def whois_lookup(domain: str) -> Dict[str, str]:
    """
    Perform WHOIS lookup using system whois command
    Passive information gathering
    """
    results = {}
    
    try:
        # Try to run whois command (available on most systems)
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Parse common WHOIS fields
            for line in output.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    # Store important fields
                    important_keys = [
                        'registrant', 'registrar', 'created', 'expires',
                        'updated', 'name server', 'tech', 'admin'
                    ]
                    
                    if any(imp_key in key for imp_key in important_keys):
                        results[key] = value
        else:
            logger.warning(f"WHOIS lookup failed for {domain}")
            
    except subprocess.TimeoutExpired:
        logger.warning(f"WHOIS lookup timeout for {domain}")
    except FileNotFoundError:
        logger.warning("whois command not found on system")
    except Exception as e:
        logger.error(f"WHOIS lookup error for {domain}: {e}")
    
    return results


def dns_zone_transfer(domain: str, nameserver: str = None) -> Dict[str, List[str]]:
    """
    Attempt DNS zone transfer (AXFR)
    Should only be used on authorized domains!
    LEGAL NOTICE: Only perform on domains you own or have authorization
    """
    results = {}
    
    try:
        if not nameserver:
            # Get NS records first
            answers = dns.resolver.resolve(domain, 'NS')
            nameserver = str(answers[0]).rstrip('.')
        
        # Attempt zone transfer
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        
        # Extract all records
        for name, node in zone.items():
            for rdataset in node:
                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                if record_type not in results:
                    results[record_type] = []
                
                for rdata in rdataset:
                    results[record_type].append(str(rdata))
    
    except Exception as e:
        logger.warning(f"DNS zone transfer failed for {domain}: {e}")
    
    return results


def ssl_cert_transparency(domain: str) -> List[Dict[str, str]]:
    """
    Query Certificate Transparency logs (public, no network impact)
    Returns list of subdomains found in CT logs
    """
    results = []
    
    try:
        # Use crt.sh API (public service)
        import urllib.request
        import json as json_lib
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json_lib.loads(response.read().decode())
                
                seen = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    
                    # Extract unique subdomains
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and subdomain not in seen:
                            seen.add(subdomain)
                            results.append({
                                'subdomain': subdomain,
                                'source': 'crt.sh'
                            })
        except Exception as e:
            logger.debug(f"crt.sh API error: {e}")
    
    except Exception as e:
        logger.error(f"SSL CT lookup error for {domain}: {e}")
    
    return results


def passive_recon_report(hostname: str, config: PassiveReconConfig = None) -> Dict:
    """
    Generate comprehensive passive reconnaissance report
    No IDS/IPS triggering - completely passive information gathering
    """
    if config is None:
        config = PassiveReconConfig()
    
    report = {
        'hostname': hostname,
        'methods_used': [],
        'data': {}
    }
    
    # DNS Lookup
    if config.dns_lookup:
        report['methods_used'].append('DNS Lookup')
        report['data']['dns_records'] = dns_lookup(hostname)
    
    # Reverse DNS (for IP addresses)
    if config.reverse_dns:
        try:
            # Check if it's an IP address
            import ipaddress
            ipaddress.ip_address(hostname)
            report['methods_used'].append('Reverse DNS')
            result = reverse_dns_lookup(hostname)
            if result:
                report['data']['reverse_dns'] = result
        except ValueError:
            # Not an IP, try for A records
            pass
    
    # WHOIS
    if config.whois_lookup:
        report['methods_used'].append('WHOIS')
        report['data']['whois'] = whois_lookup(hostname)
    
    # DNS Zone Transfer (only if explicitly enabled and authorized!)
    if config.dns_zone_transfer:
        report['methods_used'].append('DNS Zone Transfer')
        report['data']['zone_transfer'] = dns_zone_transfer(hostname)
    
    # SSL Certificate Transparency
    if config.ssl_cert_transparency:
        report['methods_used'].append('SSL CT Logs')
        report['data']['ct_subdomains'] = ssl_cert_transparency(hostname)
    
    return report
