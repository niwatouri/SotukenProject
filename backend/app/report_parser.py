import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

Severity = str

# ZAPのriskcodeをUI側のseverityにマップ
_SEVERITY_MAP = {
    0: "low",
    1: "low",
    2: "medium",
    3: "high",
}

# 簡易スコア算出用の重み
_SEVERITY_WEIGHT = {
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}


def _map_severity(riskcode: Any) -> Severity:
    try:
        code = int(riskcode)
    except (TypeError, ValueError):
        return "low"
    return _SEVERITY_MAP.get(code, "low")


def _extract_port_from_uri(uri: Optional[str]) -> Optional[int]:
    if not uri:
        return None
    parsed = urlparse(uri)
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _find_cve(reference: str) -> Optional[str]:
    match = re.search(r"(CVE-\d{4}-\d+)", reference, re.IGNORECASE)
    return match.group(1) if match else None


def parse_zap_report(raw_json: Dict[str, Any], default_scan_type: str = "bulk", default_target_url: Optional[str] = None) -> Dict[str, Any]:
    """
    ZAPのJSONレポートをフロントのScanResults形式に変換する。
    """
    sites = raw_json.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]

    vulnerabilities: List[Dict[str, Any]] = []
    open_ports: set[int] = set()
    target_url = default_target_url or ""

    for site_index, site in enumerate(sites):
        site_name = site.get("@name") or site.get("name")
        site_port_raw = site.get("@port") or site.get("port")
        site_port = None
        if site_name and not target_url:
            target_url = site_name
        if site_port_raw:
            try:
                site_port = int(site_port_raw)
            except (TypeError, ValueError):
                site_port = None

        alerts = site.get("alerts") or []
        for idx, alert in enumerate(alerts):
            plugin_id = str(alert.get("pluginid") or alert.get("id") or "unknown")
            vuln_id = f"{plugin_id}-{site_index}-{idx}"

            severity = _map_severity(alert.get("riskcode"))
            description = alert.get("description") or alert.get("desc") or ""
            impact = alert.get("riskdesc") or alert.get("otherinfo") or ""
            solution = alert.get("solution") or ""
            reference = alert.get("reference") or ""
            cve_id = _find_cve(reference)

            instances = alert.get("instances") or []
            port_for_vuln: Optional[int] = None
            for inst in instances:
                uri = inst.get("uri")
                port_candidate = _extract_port_from_uri(uri)
                if port_candidate:
                    open_ports.add(port_candidate)
                    if port_for_vuln is None:
                        port_for_vuln = port_candidate

            if port_for_vuln is None and site_port:
                port_for_vuln = site_port
                open_ports.add(site_port)
            if port_for_vuln is None:
                port_for_vuln = 80

            vulnerabilities.append({
                "id": vuln_id,
                "type": alert.get("alert") or alert.get("name") or "Unknown",
                "severity": severity,
                "port": port_for_vuln,
                "description": description,
                "impact": impact,
                "solution": solution,
                "cveId": cve_id,
            })

    # ポート情報をinstancesにも基づいてできるだけ網羅
    if not open_ports and target_url:
        port_from_target = _extract_port_from_uri(target_url)
        if port_from_target:
            open_ports.add(port_from_target)

    severity_score = sum(_SEVERITY_WEIGHT.get(v["severity"], 0) for v in vulnerabilities)
    risk_score = min(severity_score, 100) if vulnerabilities else 0

    return {
        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "targetUrl": target_url or "",
        "scanType": default_scan_type or "bulk",
        "openPorts": sorted(open_ports),
        "vulnerabilities": vulnerabilities,
        "riskScore": risk_score,
    }
