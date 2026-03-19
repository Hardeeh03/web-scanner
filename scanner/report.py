import json
from datetime import datetime, timezone


def build_report(base_url, findings):
    report = {
        "target": base_url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
    }
    return report


def report_as_text(report):
    lines = []
    lines.append(f"Target: {report['target']}")
    lines.append(f"UTC Time: {report['timestamp_utc']}")
    lines.append(f"Findings: {report['count']}")
    lines.append("")
    for item in report["findings"]:
        lines.append(json.dumps(item, ensure_ascii=True))
    return "\n".join(lines)
