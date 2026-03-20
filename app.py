from datetime import datetime, timezone
from threading import Lock, Thread
from urllib.parse import urlparse

import json
from io import BytesIO

from flask import Flask, Response, render_template, request
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from scanner import run_scan
from scanner.burp_import import BurpImportError, parse_burp_xml
from scanner.zap import ZapError, zap_health, zap_scan


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

last_report_basic = None
last_report_zap = None
last_report_burp = None
last_error = None

zap_job = {
    "status": "idle",  # idle | running | done | error
    "message": "",
}
zap_lock = Lock()


def _is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.netloc


def _severity_bucket(value):
    v = (value or "").strip().lower()
    if v in {"high", "critical"}:
        return "high"
    if v in {"medium", "med"}:
        return "medium"
    if v in {"low"}:
        return "low"
    if v in {"info", "informational"}:
        return "info"
    return "unknown"


def _filter_report(report, severity):
    if not report or severity in {"", "all"}:
        return report

    target = severity.lower()
    filtered = []
    for item in report.get("findings", []):
        if item.get("type") == "ZAP Alert":
            sev = _severity_bucket(item.get("risk"))
        elif item.get("type") == "Burp Issue":
            sev = _severity_bucket(item.get("severity"))
        else:
            sev = "info"

        if sev == target:
            filtered.append(item)

    new_report = dict(report)
    new_report["findings"] = filtered
    new_report["count"] = len(filtered)
    new_report["filtered_by"] = target
    return new_report


def _combine_reports(*reports):
    combined = {"target": "Combined", "findings": []}
    for report in reports:
        if report:
            combined["findings"].extend(report.get("findings", []))
    combined["count"] = len(combined["findings"])
    combined["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    return combined


def _render_combined_html(report):
    lines = []
    lines.append("<!doctype html><html><head><meta charset='utf-8'>")
    lines.append("<title>Web Scanner Report</title></head><body>")
    lines.append(f"<h1>Web Scanner Report</h1>")
    lines.append(f"<p>UTC Time: {report.get('timestamp_utc','')}</p>")
    lines.append(f"<p>Total Findings: {report.get('count',0)}</p>")
    lines.append("<ul>")
    for item in report.get("findings", []):
        lines.append(f"<li><pre>{json.dumps(item, ensure_ascii=True)}</pre></li>")
    lines.append("</ul></body></html>")
    return "\n".join(lines)


def _render_pdf(report):
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Web Scanner Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"UTC Time: {report.get('timestamp_utc','')}")
    y -= 14
    c.drawString(40, y, f"Total Findings: {report.get('count',0)}")
    y -= 20
    for item in report.get("findings", []):
        text = json.dumps(item, ensure_ascii=True)
        for line in _wrap_text(text, 95):
            if y < 60:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)
            c.drawString(40, y, line)
            y -= 12
    c.save()
    buf.seek(0)
    return buf


def _wrap_text(text, max_len):
    lines = []
    while text:
        lines.append(text[:max_len])
        text = text[max_len:]
    return lines


@app.get("/")
def index():
    severity = request.args.get("severity", "all")
    return render_template(
        "index.html",
        report_basic=_filter_report(last_report_basic, severity),
        report_zap=_filter_report(last_report_zap, severity),
        report_burp=_filter_report(last_report_burp, severity),
        error=last_error,
        severity=severity,
        zap_status=zap_job["status"],
        zap_message=zap_job["message"],
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

    _start_zap_job(
        target_url=base_url,
        zap_base_url=zap_url,
        api_key=api_key,
        spider=do_spider,
        active=do_active,
    )
    last_error = None

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


@app.post("/pro-scan")
def pro_scan_route():
    global last_report_basic, last_report_zap, last_error

    base_url = request.form.get("pro_target", "").strip()
    zap_url = request.form.get("pro_zap_url", "http://localhost:8080").strip()
    api_key = request.form.get("pro_zap_api_key", "").strip()
    max_pages = request.form.get("pro_max_pages", "50").strip()
    include_ports = request.form.get("pro_include_ports") == "on"
    do_spider = request.form.get("pro_zap_spider") == "on"
    do_active = request.form.get("pro_zap_active") == "on"

    if not _is_valid_url(base_url):
        last_error = "Please enter a valid http(s) URL for the professional scan."
        return index()

    try:
        max_pages_int = max(1, min(int(max_pages), 500))
    except ValueError:
        max_pages_int = 50

    try:
        last_report_basic = run_scan(
            base_url=base_url, max_pages=max_pages_int, include_ports=include_ports
        )
        _start_zap_job(
            target_url=base_url,
            zap_base_url=zap_url,
            api_key=api_key,
            spider=do_spider,
            active=do_active,
        )
        last_error = None
    except (ZapError, Exception) as exc:
        last_error = f"Professional scan failed: {exc}"

    return index()


@app.get("/zap-status")
def zap_status():
    return {
        "status": zap_job["status"],
        "message": zap_job["message"],
        "has_report": last_report_zap is not None,
    }


def _start_zap_job(target_url, zap_base_url, api_key, spider, active):
    global last_report_zap

    def _runner():
        global last_report_zap, last_error
        with zap_lock:
            zap_job["status"] = "running"
            zap_job["message"] = "ZAP scan running..."
            last_report_zap = None
        try:
            zap_version = zap_health(zap_base_url, api_key)
            report = zap_scan(
                target_url=target_url,
                zap_base_url=zap_base_url,
                api_key=api_key,
                spider=spider,
                active=active,
            )
            report["zap_version"] = zap_version
            with zap_lock:
                last_report_zap = report
                zap_job["status"] = "done"
                zap_job["message"] = "ZAP scan completed."
        except ZapError as exc:
            with zap_lock:
                zap_job["status"] = "error"
                zap_job["message"] = f"ZAP scan failed: {exc}"
        except Exception as exc:
            with zap_lock:
                zap_job["status"] = "error"
                zap_job["message"] = f"ZAP scan failed: {exc}"

    # Avoid starting multiple ZAP scans at once.
    with zap_lock:
        if zap_job["status"] == "running":
            zap_job["message"] = "ZAP scan already running..."
            return

    Thread(target=_runner, daemon=True).start()


@app.get("/export/<kind>")
def export_report(kind):
    download = request.args.get("download") == "1"
    if kind == "basic":
        report = last_report_basic
    elif kind == "zap":
        report = last_report_zap
    elif kind == "burp":
        report = last_report_burp
    elif kind == "combined":
        report = _combine_reports(last_report_basic, last_report_zap, last_report_burp)
    else:
        report = None

    if not report:
        return Response("No report available", status=404, mimetype="text/plain")

    if kind == "combined" and request.path.endswith(".html"):
        html = _render_combined_html(report)
        resp = Response(html, mimetype="text/html")
        if download:
            resp.headers["Content-Disposition"] = "attachment; filename=report.html"
        return resp

    if kind == "combined" and request.path.endswith(".pdf"):
        pdf_buf = _render_pdf(report)
        resp = Response(pdf_buf.read(), mimetype="application/pdf")
        if download:
            resp.headers["Content-Disposition"] = "attachment; filename=report.pdf"
        return resp

    payload = json.dumps(report, indent=2, ensure_ascii=True)
    resp = Response(payload, mimetype="application/json")
    if download:
        resp.headers["Content-Disposition"] = f"attachment; filename={kind}.json"
    return resp


@app.get("/export/combined.html")
def export_combined_html():
    return export_report("combined")


@app.get("/export/combined.pdf")
def export_combined_pdf():
    return export_report("combined")


if __name__ == "__main__":
    app.run(debug=True)
