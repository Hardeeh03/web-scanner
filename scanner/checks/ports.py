import socket
from urllib.parse import urlparse

COMMON_PORTS = [21, 22, 80, 443, 3306, 6379, 8080]


def scan_ports(base_url):
    findings = []
    host = urlparse(base_url).netloc.split(":")[0]

    for port in COMMON_PORTS:
        try:
            sock = socket.create_connection((host, port), timeout=1.5)
            sock.close()
            findings.append({"type": "Open Port", "port": port, "host": host})
        except Exception:
            continue

    return findings
