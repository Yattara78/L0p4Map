"""
IDS/IPS evasion and detection module
Techniques to avoid detection and detect when defenses are active
"""

import time
import random
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class IDS_Detection_Method(Enum):
    """Methods to detect IDS/IPS presence"""
    RESPONSE_TIME = "response_time"
    PACKET_DROPS = "packet_drops"
    PORT_FILTERING = "port_filtering"
    RESET_ATTACKS = "reset_attacks"
    BEHAVIORAL = "behavioral"


@dataclass
class IDSDetectionSignals:
    """Signals indicating possible IDS/IPS presence"""
    
    excessive_timeouts: int = 0
    unexpected_resets: int = 0
    dropped_packets: int = 0
    port_unreachable: int = 0
    suspicious_latency: int = 0
    blocked_protocols: List[str] = field(default_factory=list)
    
    def has_active_defense(self) -> bool:
        """Check if there are signs of active defense"""
        score = (
            self.excessive_timeouts * 2 +
            self.unexpected_resets * 3 +
            self.dropped_packets * 2 +
            self.port_unreachable +
            self.suspicious_latency +
            len(self.blocked_protocols)
        )
        return score >= 5


class IDSEvader:
    """
    Techniques to evade IDS/IPS detection
    """
    
    def __init__(self):
        self.detection_signals = IDSDetectionSignals()
        self.technique_effectiveness = {}
    
    def randomize_scan_pattern(self, ports: List[int], pattern: str = "random") -> List[int]:
        """
        Randomize port scan pattern to avoid detection signatures
        Patterns:
        - random: completely random order
        - reverse: backwards from highest to lowest
        - grouped: scan in groups separated by delays
        - weighted: focus on common ports with intermixed rare ports
        """
        
        if pattern == "random":
            shuffled = ports.copy()
            random.shuffle(shuffled)
            return shuffled
        
        elif pattern == "reverse":
            return sorted(ports, reverse=True)
        
        elif pattern == "grouped":
            # Group ports in chunks of 5-10
            shuffled = ports.copy()
            random.shuffle(shuffled)
            
            grouped = []
            chunk_size = random.randint(5, 10)
            
            for i in range(0, len(shuffled), chunk_size):
                chunk = shuffled[i:i + chunk_size]
                grouped.extend(chunk)
            
            return grouped
        
        elif pattern == "weighted":
            # Common ports first, then others randomly
            common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995]
            target_common = [p for p in common_ports if p in ports]
            target_rare = [p for p in ports if p not in common_ports]
            
            random.shuffle(target_rare)
            result = target_common + target_rare
            
            return result
        
        else:
            return ports
    
    def inject_noise_packets(self, target_host: str, num_packets: int = 5) -> Dict:
        """
        Send decoy/noise packets to confuse IDS signature matching
        Different packet types and payloads
        """
        
        noise_results = {
            'packets_sent': 0,
            'packet_types': [],
            'effectiveness': 0.0
        }
        
        try:
            from scapy.all import IP, TCP, UDP, ICMP, Raw, send
            
            payload_types = [
                ("HTTP-like", b"GET / HTTP/1.1\r\nHost: test\r\n"),
                ("FTP-like", b"220 FTP Server\r\n"),
                ("DNS-like", bytes([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])),
                ("SSL-like", b"\x16\x03\x01\x00\x4a"),
                ("Random", bytes([random.randint(0, 255) for _ in range(20)]))
            ]
            
            for _ in range(num_packets):
                ptype, payload = random.choice(payload_types)
                random_port = random.randint(1024, 65535)
                
                try:
                    packet = IP(dst=target_host) / TCP(dport=random_port, flags="S") / Raw(load=payload)
                    send(packet, verbose=False)
                    
                    noise_results['packets_sent'] += 1
                    noise_results['packet_types'].append(ptype)
                except Exception as e:
                    logger.debug(f"Could not send noise packet: {e}")
            
            # Estimate effectiveness (25% per packet sent)
            noise_results['effectiveness'] = min(100, noise_results['packets_sent'] * 25)
        
        except ImportError:
            logger.warning("Scapy not available for noise injection")
        
        return noise_results
    
    def adaptive_timing(self, base_delay: float = 1.0) -> float:
        """
        Calculate adaptive delay based on detected defense systems
        If IDS detected, increase delay; if not, maintain speed
        """
        
        if self.detection_signals.has_active_defense():
            # Increase delay if defense detected
            multiplier = 1.5 + random.uniform(0.5, 1.5)
            return base_delay * multiplier
        else:
            # Slightly variable but faster
            return base_delay * random.uniform(0.8, 1.2)
    
    def protocol_switching(self, primary_protocol: str = "TCP") -> str:
        """
        Suggest protocol switching if primary protocol seems blocked
        """
        
        if "TCP" in self.detection_signals.blocked_protocols:
            return "UDP"
        elif "UDP" in self.detection_signals.blocked_protocols:
            return "ICMP"
        elif "ICMP" in self.detection_signals.blocked_protocols:
            return "TCP"
        
        return primary_protocol
    
    def fragment_payloads(self, payload: bytes, max_fragment_size: int = None) -> List[bytes]:
        """
        Fragment payloads in unusual ways to bypass IDS inspection
        """
        
        if max_fragment_size is None:
            max_fragment_size = random.randint(8, 64)
        
        fragments = []
        offset = 0
        
        while offset < len(payload):
            fragment_size = random.randint(1, max_fragment_size)
            fragments.append(payload[offset:offset + fragment_size])
            offset += fragment_size
        
        return fragments
    
    def stealth_http_request(self, target_host: str, port: int = 80) -> Dict:
        """
        Craft stealthy HTTP requests that blend with legitimate traffic
        Uses unusual headers and behaviors
        """
        
        headers = {
            'User-Agent': self._generate_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US', 'fr-FR', 'de-DE', 'ja-JP']),
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Randomly add headers to look more legitimate
        if random.random() > 0.5:
            headers['Referer'] = random.choice([
                'https://www.google.com/search?q=test',
                'https://www.github.com/',
                'https://stackoverflow.com/'
            ])
        
        request_info = {
            'headers': headers,
            'looks_legitimate': True,
            'blends_with_traffic': True
        }
        
        return request_info
    
    def _generate_random_user_agent(self) -> str:
        """Generate realistic random user agent"""
        
        browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15'
        ]
        
        return random.choice(browsers)
    
    def detect_honeypots(self, target_host: str, test_ports: List[int] = None) -> Dict:
        """
        Detect potential honeypots by analyzing response patterns
        Honeypots often have suspicious characteristics
        """
        
        if test_ports is None:
            test_ports = [1, 10, 100, 23, 135, 445, 999]
        
        honeypot_indicators = {
            'all_ports_open': False,
            'identical_responses': False,
            'suspicious_banners': [],
            'unlikely_service_combination': False,
            'honeypot_probability': 0.0
        }
        
        # Would need actual network interaction to implement fully
        # This is a template for honeypot detection logic
        
        return honeypot_indicators
    
    def generate_evasion_report(self) -> Dict:
        """Generate report on detected defenses and evasion applied"""
        
        report = {
            'detection_signals': {
                'excessive_timeouts': self.detection_signals.excessive_timeouts,
                'unexpected_resets': self.detection_signals.unexpected_resets,
                'dropped_packets': self.detection_signals.dropped_packets,
                'port_unreachable': self.detection_signals.port_unreachable,
                'suspicious_latency': self.detection_signals.suspicious_latency,
                'blocked_protocols': self.detection_signals.blocked_protocols,
                'active_defense_detected': self.detection_signals.has_active_defense()
            },
            'evasion_techniques_recommended': [
                'randomize_scan_pattern' if self.detection_signals.has_active_defense() else None,
                'adaptive_timing' if self.detection_signals.suspicious_latency > 2 else None,
                'inject_noise_packets' if self.detection_signals.excessive_timeouts > 3 else None,
                'protocol_switching' if len(self.detection_signals.blocked_protocols) > 0 else None,
            ],
            'effectiveness_score': self._calculate_effectiveness()
        }
        
        return {k: v for k, v in report.items() if v}
    
    def _calculate_effectiveness(self) -> float:
        """Calculate overall evasion effectiveness score (0-100)"""
        
        if not self.detection_signals.has_active_defense():
            return 85.0
        
        score = 100.0
        score -= self.detection_signals.excessive_timeouts * 5
        score -= self.detection_signals.unexpected_resets * 8
        score -= self.detection_signals.dropped_packets * 6
        
        return max(0, score)
