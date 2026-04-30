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
python -m pip install -r C:\Users\Hardee\OneDrive\Documents\Playground\requirements.txt
python C:\Users\Hardee\OneDrive\Documents\Playground\app.py
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

