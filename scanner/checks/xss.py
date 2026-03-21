import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOAD = "<xss-test>"


def scan_xss(pages):
    findings = []
    headers = {"User-Agent": "BasicSecurityScanner/0.1"}

    for url, _ in pages:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param in qs:
            test_qs = qs.copy()
            test_qs[param] = PAYLOAD
            new_query = urlencode(test_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, headers=headers, timeout=8)
                if PAYLOAD in r.text:
                    findings.append(
                        {
                            "type": "Reflected XSS (Heuristic)",
                            "url": test_url,
                            "param": param,
                            "summary": "The page reflected input back into the response, which can allow script injection (XSS).",
                        }
                    )
            except Exception:
                continue
    return findings
