import requests

COMMON_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
]


def scan_misconfig(base_url):
    findings = []
    headers = {"User-Agent": "BasicSecurityScanner/0.1"}

    try:
        r = requests.get(base_url, headers=headers, timeout=8)
        for h in COMMON_HEADERS:
            if h not in r.headers:
                findings.append(
                    {"type": "Missing Security Header", "header": h, "url": base_url}
                )
    except Exception:
        pass

    return findings
