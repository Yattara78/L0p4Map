"""TCP connect scanner with firewall evasion support.

Extends the basic TCP connect scanner with optional firewall evasion
techniques like timing control, decoys, and packet manipulation.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
from typing import Dict, Iterable, List, Optional

from .firewall_evasion import FirewallEvader, FirewallEvasionConfig


def tcp_connect_scan_with_evasion(
    host: str,
    ports: Iterable[int],
    workers: int = 100,
    timeout: float = 0.5,
    evasion_config: Optional[FirewallEvasionConfig] = None,
) -> Dict:
    """TCP connect scan with optional firewall evasion.

    Args:
        host: Target hostname or IP
        ports: Iterable of port numbers
        workers: Number of concurrent threads
        timeout: Socket timeout in seconds
        evasion_config: FirewallEvasionConfig or None for defaults

    Returns:
        Dictionary with results and evasion info.
    """
    if evasion_config is None:
        evasion_config = FirewallEvasionConfig()

    evader = FirewallEvader(evasion_config)
    open_ports: List[int] = []
    probes_sent = 0
    decoys_sent = 0

    def check_port_with_evasion(port: int) -> bool:
        nonlocal probes_sent, decoys_sent
        probes_sent += 1

        # Apply timing evasion
        evader.apply_delay()

        # Send decoy probe if configured
        if evader.should_send_decoy():
            decoy_host = evader.get_next_decoy_host()
            if decoy_host:
                decoys_sent += 1
                try:
                    sock = socket.create_connection((decoy_host, port), timeout=timeout)
                    sock.close()
                except Exception:
                    pass

        # Perform actual scan
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_port_with_evasion, p): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                if fut.result():
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()

    return {
        "target": host,
        "open_ports": open_ports,
        "probes_sent": probes_sent,
        "decoys_sent": decoys_sent,
        "evasion_config": evasion_config.__dict__,
        "evasion_report": evader.generate_report(),
    }
