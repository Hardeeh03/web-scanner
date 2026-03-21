import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQL_ERRORS = [
    "syntax error",
    "mysql",
    "sql",
    "postgres",
    "sqlite",
    "odbc",
    "unterminated",
]


def scan_sql(pages):
    findings = []
    headers = {"User-Agent": "BasicSecurityScanner/0.1"}

    for url, _ in pages:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            continue

        for param in qs:
            test_qs = qs.copy()
            test_qs[param] = "'"
            new_query = urlencode(test_qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, headers=headers, timeout=8)
                body = r.text.lower()
                if any(err in body for err in SQL_ERRORS):
                    findings.append(
                        {
                            "type": "SQL Injection (Heuristic)",
                            "url": test_url,
                            "param": param,
                            "summary": "The page showed a database error when we tested input, which can indicate SQL injection risk.",
                        }
                    )
            except Exception:
                continue
    return findings
