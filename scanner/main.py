from .crawler import crawl
from .checks.sql_injection import scan_sql
from .checks.xss import scan_xss
from .checks.misconfig import scan_misconfig
from .checks.ports import scan_ports
from .report import build_report


def run_scan(base_url, max_pages=50, include_ports=True):
    pages = crawl(base_url, max_pages=max_pages)

    findings = []
    findings += scan_sql(pages)
    findings += scan_xss(pages)
    findings += scan_misconfig(base_url)
    if include_ports:
        findings += scan_ports(base_url)

    report = build_report(base_url, findings)
    return report
