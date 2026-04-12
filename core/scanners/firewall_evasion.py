"""Firewall evasion techniques for network scanning.

This module provides defensive scanning techniques to help evade
firewall detection. These are legitimate methods used in:
  - Authorized penetration testing
  - Network defense assessment
  - Security research with proper authorization

IMPORTANT: Use only on networks you own or have explicit permission to test.

Techniques included:
  - Timing/rate limiting (avoid detection by IDS)
  - Decoys (mix legitimate traffic with scan)
  - Fragmentation (split packets to bypass filtering)
  - Source port randomization (mimic legitimate traffic)
  - TTL manipulation (vary TTL to confuse traceback)
  - Packet size variation (avoid signature-based detection)
"""

import socket
import random
import time
from typing import Dict, List, Optional


class FirewallEvasionConfig:
    """Configuration for firewall evasion techniques."""

    def __init__(self):
        self.timing_mode: str = "normal"  # sneaky, polite, normal, aggressive, insane
        self.use_decoys: bool = False
        self.decoy_count: int = 2
        self.fragment_packets: bool = False
        self.randomize_ports: bool = True
        self.randomize_ttl: bool = False
        self.min_ttl: int = 32
        self.max_ttl: int = 64
        self.packet_size_variation: bool = False
        self.delay_between_probes: float = 0.0  # seconds
        self.source_port_range: tuple = (49152, 65535)  # ephemeral ports

    def get_timing_delays(self) -> Dict[str, float]:
        """Get inter-probe delays based on timing mode (in milliseconds)."""
        timing_presets = {
            "sneaky": {"delay": 300, "rate_limit": 0.5},
            "polite": {"delay": 100, "rate_limit": 1.0},
            "normal": {"delay": 10, "rate_limit": 10.0},
            "aggressive": {"delay": 1, "rate_limit": 100.0},
            "insane": {"delay": 0, "rate_limit": 1000.0},
        }
        return timing_presets.get(self.timing_mode, timing_presets["normal"])

    def get_source_port(self) -> int:
        """Get a random ephemeral source port."""
        if self.randomize_ports:
            return random.randint(*self.source_port_range)
        return 0  # let OS choose

    def get_ttl(self) -> int:
        """Get a TTL value, optionally randomized."""
        if self.randomize_ttl:
            return random.randint(self.min_ttl, self.max_ttl)
        return 64  # default Linux TTL

    def get_packet_size(self, base_size: int = 60) -> int:
        """Get packet size with optional variation to avoid signatures."""
        if self.packet_size_variation:
            variation = random.randint(-20, 20)
            return max(20, base_size + variation)
        return base_size


class FirewallEvader:
    """Applies firewall evasion techniques to scanning."""

    def __init__(self, config: Optional[FirewallEvasionConfig] = None):
        self.config = config or FirewallEvasionConfig()
        self.decoy_hosts: List[str] = []

    def set_decoy_hosts(self, hosts: List[str]):
        """Set decoy hosts to mix with scan traffic."""
        self.decoy_hosts = hosts

    def calculate_delay(self) -> float:
        """Calculate delay before next probe based on timing mode."""
        timing = self.config.get_timing_delays()
        delay_ms = timing.get("delay", 10)
        return delay_ms / 1000.0

    def apply_delay(self):
        """Apply timing delay between probes."""
        delay = self.calculate_delay()
        if delay > 0:
            time.sleep(delay)

    def should_send_decoy(self) -> bool:
        """Decide whether to send a decoy probe this round."""
        if not self.config.use_decoys or not self.decoy_hosts:
            return False
        return random.random() < (self.config.decoy_count / 10.0)

    def get_next_decoy_host(self) -> Optional[str]:
        """Get next decoy host to scan."""
        if not self.decoy_hosts:
            return None
        return random.choice(self.decoy_hosts)

    def fragment_packet(self, data: bytes) -> List[bytes]:
        """Split packet into fragments (simulated for TCP/IP stacks)."""
        if not self.config.fragment_packets or len(data) < 2:
            return [data]
        # Split roughly in half (actual fragmentation happens at IP layer)
        mid = len(data) // 2
        return [data[:mid], data[mid:]]

    def create_scan_request(
        self, target_host: str, target_port: int, include_metadata: bool = True
    ) -> Dict:
        """Create a scan request with evasion settings applied."""
        source_port = self.config.get_source_port()
        ttl = self.config.get_ttl()
        packet_size = self.config.get_packet_size()

        request = {
            "target_host": target_host,
            "target_port": target_port,
            "source_port": source_port,
            "ttl": ttl,
            "packet_size": packet_size,
            "timestamp": time.time(),
        }

        if include_metadata:
            request["evasion_mode"] = self.config.timing_mode
            request["use_decoys"] = self.config.use_decoys
            request["fragment"] = self.config.fragment_packets

        return request

    def generate_report(self) -> str:
        """Generate a human-readable report of evasion settings."""
        lines = [
            "=== Firewall Evasion Configuration ===",
            f"Timing Mode: {self.config.timing_mode}",
            f"Decoys: {self.config.use_decoys} ({self.config.decoy_count} decoys)" if self.config.use_decoys else "Decoys: Disabled",
            f"Packet Fragmentation: {self.config.fragment_packets}",
            f"Source Port Randomization: {self.config.randomize_ports}",
            f"TTL Randomization: {self.config.randomize_ttl}",
            f"Packet Size Variation: {self.config.packet_size_variation}",
        ]
        if self.config.delay_between_probes > 0:
            lines.append(f"Custom Delay: {self.config.delay_between_probes}s between probes")
        return "\n".join(lines)
