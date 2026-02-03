import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

Severity = str

# ZAPのriskcodeをUI側のseverityにマップ
_SEVERITY_MAP = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
}

# 簡易スコア算出用の重み
_SEVERITY_WEIGHT = {
    "info": 0,
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}

_CONFIDENCE_MAP = {
    0: "low",
    1: "low",
    2: "medium",
    3: "high",
}


def _map_severity(riskcode: Any) -> Severity:
    if isinstance(riskcode, str):
        lowered = riskcode.strip().lower()
        if lowered in {"informational", "info"}:
            return "info"
        if lowered in {"low", "medium", "high"}:
            return lowered
    try:
        code = int(riskcode)
    except (TypeError, ValueError):
        return "low"
    return _SEVERITY_MAP.get(code, "low")


def _map_confidence(confidence: Any) -> Optional[str]:
    if confidence is None:
        return None
    if isinstance(confidence, str):
        lowered = confidence.strip().lower()
        if lowered in {"high", "medium", "low"}:
            return lowered
        for key in ("high", "medium", "low"):
            if key in lowered:
                return key
        try:
            confidence = int(lowered)
        except (TypeError, ValueError):
            return None
    try:
        code = int(confidence)
    except (TypeError, ValueError):
        return None
    return _CONFIDENCE_MAP.get(code)


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


def _pick_best_instance(instances: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not instances:
        return None
    for inst in instances:
        if inst.get("evidence") or inst.get("attack") or inst.get("param"):
            return inst
    return instances[0]


def _shorten_text(value: Optional[str], limit: int = 120) -> Optional[str]:
    if not value:
        return None
    compact = re.sub(r"\s+", " ", str(value)).strip()
    if not compact:
        return None
    if len(compact) <= limit:
        return compact
    return compact[:limit - 1] + "…"


def _mask_sensitive_line(line: str) -> str:
    lowered = line.lower()
    if lowered.startswith("authorization:") or lowered.startswith("cookie:") or lowered.startswith("set-cookie:"):
        key = line.split(":", 1)[0]
        return f"{key}: <redacted>"
    masked = re.sub(
        r"(?i)(token|apikey|api_key|api-key|password|passwd|secret)=([^\s&]+)",
        r"\1=<redacted>",
        line,
    )
    return masked


def _build_snippet(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    if not isinstance(raw, str):
        raw = str(raw)
    lines = raw.splitlines()
    snippet: List[str] = []
    for line in lines:
        if len(snippet) >= 10:
            break
        masked = _mask_sensitive_line(line)
        if len(masked) > 200:
            masked = masked[:199] + "…"
        snippet.append(masked)
    return snippet or None


def _combine_header_body(header: Optional[str], body: Optional[str]) -> Optional[str]:
    if header and body:
        return f"{header}\n{body}"
    return header or body


def build_alert_key(plugin_id: str, affected_url: Optional[str], parameter: Optional[str]) -> str:
    parts = [str(plugin_id or "unknown")]
    if affected_url:
        parts.append(affected_url)
    if parameter:
        parts.append(parameter)
    return "|".join(parts)


def parse_zap_report(
    raw_json: Dict[str, Any],
    default_scan_type: str = "bulk",
    default_target_url: Optional[str] = None,
    include_risks: Optional[list[str]] = None,
    scope_same_host_only: bool = False,
) -> Dict[str, Any]:
    """
    ZAPのJSONレポートをフロントのScanResults形式に変換する。
    """
    sites = raw_json.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]

    vulnerabilities: List[Dict[str, Any]] = []
    open_ports: set[int] = set()
    target_url = default_target_url or ""
    target_host = urlparse(target_url).netloc if target_url else ""

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
            confidence = _map_confidence(alert.get("confidence"))
            description = alert.get("description") or alert.get("desc") or ""
            impact = alert.get("riskdesc") or alert.get("otherinfo") or ""
            solution = alert.get("solution") or ""
            reference = alert.get("reference") or ""
            cve_id = _find_cve(reference)

            instances = alert.get("instances") or []
            if isinstance(instances, dict):
                instances = [instances]
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

            best_instance = _pick_best_instance(instances)
            affected_url = None
            path_value = None
            parameter = None
            method = None
            attack = None
            evidence = None
            request_snippet = None
            response_snippet = None
            if isinstance(best_instance, dict):
                affected_url = best_instance.get("uri") or best_instance.get("url")
                if affected_url:
                    parsed = urlparse(affected_url)
                    path_value = parsed.path or None
                    if parsed.query and not parameter:
                        parameter = parsed.query.split("=", 1)[0]
                parameter = best_instance.get("param") or best_instance.get("parameter") or parameter
                method = best_instance.get("method")
                attack = best_instance.get("attack")
                evidence = best_instance.get("evidence")
                request_header = best_instance.get("requestHeader") or best_instance.get("requestheader")
                request_body = best_instance.get("requestBody") or best_instance.get("requestbody")
                response_header = best_instance.get("responseHeader") or best_instance.get("responseheader")
                response_body = best_instance.get("responseBody") or best_instance.get("responsebody")
                request_snippet = _build_snippet(_combine_header_body(request_header, request_body))
                response_snippet = _build_snippet(_combine_header_body(response_header, response_body))

            rationale = _shorten_text(evidence) or _shorten_text(alert.get("otherinfo")) or _shorten_text(description)
            if not rationale and attack:
                rationale = f"攻撃ペイロード {attack} を検出"

            reproduction = None
            if affected_url and parameter and attack:
                reproduction = f"{affected_url}?{parameter}={attack} にアクセスし、レスポンスに {evidence or '変化'} が含まれることを確認"
            elif affected_url and attack:
                reproduction = f"{affected_url} に {attack} を送信し、レスポンスの変化を確認"

            vulnerabilities.append({
                "id": vuln_id,
                "alertKey": build_alert_key(plugin_id, affected_url, parameter),
                "type": alert.get("alert") or alert.get("name") or "Unknown",
                "severity": severity,
                "port": port_for_vuln,
                "description": description,
                "impact": impact,
                "solution": solution,
                "cveId": cve_id,
                "evidence": {
                    "affected_url": affected_url,
                    "path": path_value,
                    "parameter": parameter,
                    "method": method,
                    "confidence": confidence,
                    "rationale": rationale,
                    "reproduction": reproduction,
                    "request_snippet": request_snippet,
                    "response_snippet": response_snippet,
                },
            })

    # ポート情報をinstancesにも基づいてできるだけ網羅
    if not open_ports and target_url:
        port_from_target = _extract_port_from_uri(target_url)
        if port_from_target:
            open_ports.add(port_from_target)

    if include_risks:
        allowed = {risk.strip().lower() for risk in include_risks if isinstance(risk, str)}
        normalized_allowed = set()
        for risk in allowed:
            if risk == "informational":
                normalized_allowed.add("info")
            elif risk:
                normalized_allowed.add(risk)
        vulnerabilities = [v for v in vulnerabilities if v.get("severity") in normalized_allowed]

    if scope_same_host_only and target_host:
        filtered: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            evidence = vuln.get("evidence") or {}
            affected_url = evidence.get("affected_url")
            if not affected_url:
                filtered.append(vuln)
                continue
            try:
                affected_host = urlparse(affected_url).netloc
            except Exception:
                affected_host = ""
            if not affected_host or affected_host == target_host:
                filtered.append(vuln)
        vulnerabilities = filtered

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
