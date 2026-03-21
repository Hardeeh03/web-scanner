from datetime import datetime, timezone
from xml.etree import ElementTree as ET


class BurpImportError(Exception):
    pass


def _text(node, tag):
    child = node.find(tag)
    return child.text.strip() if child is not None and child.text else ""


def parse_burp_xml(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise BurpImportError("Invalid XML file") from exc

    issues = root.findall(".//issue")
    if not issues:
        raise BurpImportError("No <issue> entries found in XML")

    findings = []
    for issue in issues:
        host_node = issue.find("host")
        host = host_node.text.strip() if host_node is not None and host_node.text else ""
        path = _text(issue, "path")
        url = f"{host}{path}" if host or path else ""

        findings.append(
            {
                "type": "Burp Issue",
                "name": _text(issue, "name") or "Unknown",
                "severity": _text(issue, "severity") or "Unknown",
                "confidence": _text(issue, "confidence") or "Unknown",
                "url": url,
                "summary": "Burp reported a security issue. Review the details and fix the underlying risk.",
            }
        )

    return {
        "target": "Burp Import",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
        "source": "burp",
    }
