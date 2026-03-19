# Web Scanner

Authorized testing only. This project provides a simple Flask UI that combines:

- Basic heuristic scanning (SQLi/XSS reflections, missing headers, common ports)
- OWASP ZAP automation (spider + active scan via ZAP API)
- Burp Suite XML import and display

## Quick Start

```powershell
python -m pip install -r C:\Users\Hardee\OneDrive\Documents\Playground\requirements.txt
python C:\Users\Hardee\OneDrive\Documents\Playground\app.py
```

Open `http://127.0.0.1:5000`.

## Run ZAP with Docker

No API key (simpler for local use):

```powershell
docker pull owasp/zap2docker-stable
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable `
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

With API key:

```powershell
docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable `
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=YOUR_KEY
```

In the UI:
- ZAP API URL: `http://localhost:8080`
- API Key: `YOUR_KEY` (if set)

## Burp Import

Export a Burp scan as XML and upload it in the UI. The findings will be displayed and can be exported as JSON.

## JSON Export

After a scan, use the export links:
- `/export/basic`
- `/export/zap`
- `/export/burp`

## Notes

- This project is for authorized testing only.
- The basic scanner is heuristic and should be used as a supplement to professional tools like ZAP and Burp.
