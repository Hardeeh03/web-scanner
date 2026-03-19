from urllib.parse import urlparse

from flask import Flask, render_template, request

from scanner import run_scan


app = Flask(__name__)
last_report = None
last_error = None


def _is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.netloc


@app.get("/")
def index():
    return render_template("index.html", report=last_report, error=last_error)


@app.post("/scan")
def scan():
    global last_report, last_error

    base_url = request.form.get("base_url", "").strip()
    max_pages = request.form.get("max_pages", "50").strip()
    include_ports = request.form.get("include_ports") == "on"

    if not _is_valid_url(base_url):
        last_error = "Please enter a valid http(s) URL."
        last_report = None
        return render_template("index.html", report=last_report, error=last_error)

    try:
        max_pages_int = max(1, min(int(max_pages), 500))
    except ValueError:
        max_pages_int = 50

    try:
        last_report = run_scan(
            base_url=base_url, max_pages=max_pages_int, include_ports=include_ports
        )
        last_error = None
    except Exception as exc:
        last_error = f"Scan failed: {exc}"
        last_report = None

    return render_template("index.html", report=last_report, error=last_error)


if __name__ == "__main__":
    app.run(debug=True)
