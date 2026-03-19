import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def crawl(base_url, max_pages=50, delay_s=0.25):
    visited = set()
    to_visit = [base_url]
    pages = []

    base_domain = urlparse(base_url).netloc
    headers = {"User-Agent": "BasicSecurityScanner/0.1"}

    while to_visit and len(pages) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)

        try:
            r = requests.get(url, headers=headers, timeout=8)
            pages.append((url, r.text))

            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                abs_url = urljoin(url, link["href"])
                if urlparse(abs_url).netloc == base_domain:
                    if abs_url not in visited:
                        to_visit.append(abs_url)
        except Exception:
            continue

        if delay_s:
            time.sleep(delay_s)

    return pages
