import time
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests


class ZapError(Exception):
    pass


def _zap_request_json(
    zap_base_url, path, params, timeout_s=180, retries=3, backoff_s=2.0
):
    url = urljoin(zap_base_url.rstrip("/") + "/", path.lstrip("/"))
    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, params=params, timeout=timeout_s)
            last_exc = None
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff_s * (attempt + 1))
                continue
            raise ZapError(f"Failed to reach ZAP at {zap_base_url}: {exc}") from exc

    if r.status_code != 200:
        snippet = (r.text or "").strip().replace("\n", " ")[:200]
        raise ZapError(f"ZAP returned HTTP {r.status_code}: {snippet}")

    try:
        return r.json()
    except ValueError as exc:
        snippet = (r.text or "").strip().replace("\n", " ")[:200]
        raise ZapError(f"ZAP returned invalid JSON: {snippet}") from exc


def _add_apikey(params, api_key):
    if api_key:
        params["apikey"] = api_key
    return params


def zap_health(zap_base_url, api_key="", timeout_s=180, retries=3):
    data = _zap_request_json(
        zap_base_url,
        "/JSON/core/view/version/",
        _add_apikey({}, api_key),
        timeout_s=timeout_s,
        retries=retries,
    )
    return data.get("version", "unknown")


def _wait_for_status(zap_base_url, api_key, view_path, scan_id, timeout_s):
    start = time.time()
    while True:
        data = _zap_request_json(
            zap_base_url,
            view_path,
            _add_apikey({"scanId": scan_id}, api_key),
            timeout_s=timeout_s,
        )
        status = data.get("status")
        try:
            pct = int(status)
        except (TypeError, ValueError):
            pct = 0

        if pct >= 100:
            return

        if time.time() - start > timeout_s:
            raise ZapError("ZAP scan timed out")

        time.sleep(2)


def zap_scan(
    target_url,
    zap_base_url="http://localhost:8080",
    api_key="",
    spider=True,
    active=True,
    timeout_s=600,
):
    # Ensure ZAP can access the target URL before scanning.
    _zap_request_json(
        zap_base_url,
        "/JSON/core/action/accessUrl/",
        _add_apikey({"url": target_url, "followRedirects": True}, api_key),
        timeout_s=timeout_s,
    )
    if spider:
        data = _zap_request_json(
            zap_base_url,
            "/JSON/spider/action/scan/",
            _add_apikey({"url": target_url}, api_key),
            timeout_s=timeout_s,
        )
        scan_id = data.get("scan")
        if not scan_id:
            raise ZapError("ZAP did not return a spider scan id")
        _wait_for_status(
            zap_base_url, api_key, "/JSON/spider/view/status/", scan_id, timeout_s
        )

    if active:
        data = _zap_request_json(
            zap_base_url,
            "/JSON/ascan/action/scan/",
            _add_apikey({"url": target_url, "recurse": True}, api_key),
            timeout_s=timeout_s,
        )
        scan_id = data.get("scan")
        if not scan_id:
            raise ZapError("ZAP did not return an active scan id")
        _wait_for_status(
            zap_base_url, api_key, "/JSON/ascan/view/status/", scan_id, timeout_s
        )

    alerts = _zap_request_json(
        zap_base_url,
        "/JSON/core/view/alerts/",
        _add_apikey({"baseurl": target_url}, api_key),
        timeout_s=timeout_s,
    ).get("alerts", [])

    findings = []
    for alert in alerts:
        findings.append(
            {
                "type": "ZAP Alert",
                "name": alert.get("alert", "Unknown"),
                "risk": alert.get("risk", "Unknown"),
                "confidence": alert.get("confidence", "Unknown"),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
            }
        )

    return {
        "target": target_url,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": findings,
        "source": "zap",
    }


