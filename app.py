from urllib.parse import urlparse

from flask import Flask, render_template, request

from scanner import run_scan
from scanner.burp_import import BurpImportError, parse_burp_xml
from scanner.zap import ZapError, zap_health, zap_scan


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

last_report_basic = None
last_report_zap = None
last_report_burp = None
last_error = None


def _is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.netloc


@app.get("/")
def index():
    return render_template(
        "index.html",
        report_basic=last_report_basic,
        report_zap=last_report_zap,
        report_burp=last_report_burp,
        error=last_error,
    )


@app.post("/scan")
def scan():
    global last_report_basic, last_error

    base_url = request.form.get("base_url", "").strip()
    max_pages = request.form.get("max_pages", "50").strip()
    include_ports = request.form.get("include_ports") == "on"

    if not _is_valid_url(base_url):
        last_error = "Please enter a valid http(s) URL."
        last_report_basic = None
        return index()

    try:
        max_pages_int = max(1, min(int(max_pages), 500))
    except ValueError:
        max_pages_int = 50

    try:
        last_report_basic = run_scan(
            base_url=base_url, max_pages=max_pages_int, include_ports=include_ports
        )
        last_error = None
    except Exception as exc:
        last_error = f"Scan failed: {exc}"
        last_report_basic = None

    return index()


@app.post("/zap-scan")
def zap_scan_route():
    global last_report_zap, last_error

    base_url = request.form.get("zap_target", "").strip()
    zap_url = request.form.get("zap_url", "http://localhost:8080").strip()
    api_key = request.form.get("zap_api_key", "").strip()
    do_spider = request.form.get("zap_spider") == "on"
    do_active = request.form.get("zap_active") == "on"

    if not _is_valid_url(base_url):
        last_error = "Please enter a valid http(s) URL for ZAP."
        last_report_zap = None
        return index()

    try:
        zap_version = zap_health(zap_url, api_key)
    except ZapError as exc:
        last_error = f"ZAP not reachable: {exc}"
        last_report_zap = None
        return index()

    try:
        last_report_zap = zap_scan(
            target_url=base_url,
            zap_base_url=zap_url,
            api_key=api_key,
            spider=do_spider,
            active=do_active,
        )
        last_report_zap["zap_version"] = zap_version
        last_error = None
    except ZapError as exc:
        last_error = f"ZAP scan failed: {exc}"
        last_report_zap = None

    return index()


@app.post("/burp-import")
def burp_import_route():
    global last_report_burp, last_error

    file = request.files.get("burp_xml")
    if not file:
        last_error = "Please upload a Burp XML export."
        last_report_burp = None
        return index()

    try:
        xml_bytes = file.read()
        last_report_burp = parse_burp_xml(xml_bytes)
        last_error = None
    except BurpImportError as exc:
        last_error = f"Burp import failed: {exc}"
        last_report_burp = None

    return index()


if __name__ == "__main__":
    app.run(debug=True)
