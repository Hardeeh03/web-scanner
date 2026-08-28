# Web Scanner

This project is a **Python + Flask** web security scanner UI that combines:

- A basic heuristic scanner (SQLi/XSS reflection checks, missing headers, common ports)
- OWASP ZAP automation (spider + active scan via local ZAP API)
- Burp Suite XML import (view findings in the same UI)
- Combined report export (HTML / PDF / JSON)
- Severity filtering (High / Medium / Low / Info)

> **Authorized testing only.** Use this tool only on systems you own or have explicit permission to test.

## What This Project Does

You can run quick scans from the browser, trigger ZAP from Docker, and import Burp results.  
It’s intended as a practical UI for organizing findings—not a full replacement for professional tools.

## Requirements

- Python 3.9+
- Java 11+ (for OWASP ZAP)
- Burp Suite (optional, for XML export)

## Install & Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## OWASP ZAP (Local, No Docker)

Install ZAP and run it in daemon mode:

```powershell
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true
```

With API key:

```powershell
zap.bat -daemon -host 127.0.0.1 -port 8080 -config api.key=YOUR_KEY
```

In the UI:
- ZAP API URL: `http://localhost:8080`
- API Key: `YOUR_KEY` (if set)

## Burp Import

Export your Burp scan as **XML**, then upload it using the Burp Import section in the UI.

## Exports

### Individual JSON
- `/export/basic?download=1`
- `/export/zap?download=1`
- `/export/burp?download=1`

### Combined Report
- HTML: `/export/combined.html?download=1`
- PDF: `/export/combined.pdf?download=1`
- JSON: `/export/combined?download=1`

## Severity Filter

Use the dropdown at the top of the UI to filter results by severity.

## Example Workflow

1. Start ZAP in Docker (see the ZAP section above).
2. Run the app and open `http://127.0.0.1:5000`.
3. Use **Professional Scan** for a combined Basic + ZAP run.
4. (Optional) Import Burp XML for external testing results.
5. Download JSON or a combined HTML/PDF report.

## Roadmap Ideas (Optional)

- Add results history
- Export ZIP bundle (HTML + PDF + JSON)
- CWE tagging

## Notes

- This project is for authorized testing only.
- The basic scanner is heuristic and should be used as a supplement to professional tools like ZAP and Burp.

## Daily Maintenance Log

- 2026-06-09 10:43:20 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-10 11:05:16 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-14 10:33:18 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-15 13:27:27 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-19 11:42:53 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-20 10:14:59 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-24 10:28:59 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-25 10:22:28 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-29 12:12:00 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-06-30 10:40:49 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-04 09:33:15 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-05 09:50:35 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-09 10:43:16 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-10 10:30:17 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-14 09:19:53 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-15 09:23:46 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-19 09:21:26 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-20 10:21:10 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-24 09:38:36 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-25 09:14:25 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-29 10:00:44 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-07-30 09:46:17 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-03 10:51:57 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-04 10:02:25 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-08 08:03:30 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-09 08:04:41 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-13 08:46:31 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-14 08:39:47 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-18 07:56:52 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-19 07:56:52 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-23 07:50:38 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-24 08:07:33 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
- 2026-08-28 19:28:43 UTC: automated maintenance check-in for `Hardeeh03/web-scanner`.
