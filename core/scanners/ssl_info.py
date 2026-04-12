"""SSL/TLS certificate inspection helper.

Returns basic certificate fields for a host:port.
"""
import socket
import ssl
from typing import Dict, Optional


def get_ssl_info(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    result = {"subject": None, "issuer": None, "notAfter": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = cert.get("subject")
                issuer = cert.get("issuer")
                notAfter = cert.get("notAfter")
                # Simplify subject and issuer to readable strings
                if subject:
                    result["subject"] = ", ".join("=".join(x) for part in subject for x in part)
                if issuer:
                    result["issuer"] = ", ".join("=".join(x) for part in issuer for x in part)
                result["notAfter"] = notAfter
    except Exception as e:
        result["error"] = str(e)
    return result
