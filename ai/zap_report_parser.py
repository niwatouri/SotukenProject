import html as html_module
import json
import re
import xml.etree.ElementTree as ET

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(value):
    if value is None:
        return ""
    text = _TAG_RE.sub(" ", str(value))
    text = html_module.unescape(text)
    return " ".join(text.split()).strip()


def _parse_xml_report(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    vulns = []
    for alertitem in root.findall(".//alertitem"):
        instance = alertitem.find(".//instance")
        url = ""
        param = ""
        if instance is not None:
            url = instance.findtext("uri") or ""
            param = instance.findtext("param") or ""
        if not url:
            url = alertitem.findtext("uri") or ""
        if not param:
            param = alertitem.findtext("param") or ""

        vulns.append({
            "id": _strip_html(alertitem.findtext("pluginid") or ""),
            "title": _strip_html(alertitem.findtext("alert") or alertitem.findtext("name") or ""),
            "risk": _strip_html(alertitem.findtext("riskdesc") or alertitem.findtext("risk") or ""),
            "description": _strip_html(alertitem.findtext("desc") or alertitem.findtext("description") or ""),
            "solution": _strip_html(alertitem.findtext("solution") or ""),
            "url": _strip_html(url),
            "param": _strip_html(param),
        })
    return vulns


def _parse_json_report(report_json):
    sites = report_json.get("site") if isinstance(report_json, dict) else []
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        sites = []

    vulns = []
    for site in sites:
        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") or []
            first_instance = instances[0] if isinstance(instances, list) and instances else {}
            url = (
                first_instance.get("uri")
                or first_instance.get("url")
                or alert.get("uri")
                or alert.get("url")
                or site.get("@name")
                or ""
            )
            param = first_instance.get("param") or alert.get("param") or ""
            vulns.append({
                "id": _strip_html(alert.get("pluginid") or alert.get("id") or ""),
                "title": _strip_html(alert.get("alert") or alert.get("name") or ""),
                "risk": _strip_html(alert.get("riskdesc") or alert.get("risk") or ""),
                "description": _strip_html(alert.get("desc") or alert.get("description") or ""),
                "solution": _strip_html(alert.get("solution") or ""),
                "url": _strip_html(url),
                "param": _strip_html(param),
            })
    return vulns


def _extract_table_value(block, label):
    pattern = re.compile(
        rf"<td[^>]*>\s*(?:<b[^>]*>)?{re.escape(label)}(?:</b>)?\s*</td>\s*<td[^>]*>(.*?)</td>",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        return ""
    return _strip_html(match.group(1))


def _extract_first_url(block):
    match = re.search(r"https?://[^\s\"'<>]+", block)
    if not match:
        return ""
    return _strip_html(match.group(0))


def _parse_html_report(html_text):
    sections = []
    pattern = re.compile(r"<h2[^>]*>\s*Alert\s*:?\s*(.*?)</h2>", re.IGNORECASE | re.DOTALL)
    matches = list(pattern.finditer(html_text))
    if not matches:
        return sections

    for index, match in enumerate(matches):
        title = _strip_html(match.group(1))
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(html_text)
        block = html_text[start:end]
        risk = _extract_table_value(block, "Risk") or _extract_table_value(block, "Risk Level")
        description = _extract_table_value(block, "Description") or _extract_table_value(block, "Desc")
        solution = _extract_table_value(block, "Solution")
        url = (
            _extract_table_value(block, "URL")
            or _extract_table_value(block, "URI")
            or _extract_first_url(block)
        )
        param = _extract_table_value(block, "Param") or _extract_table_value(block, "Parameter")
        sections.append({
            "id": "",
            "title": title,
            "risk": risk,
            "description": description,
            "solution": solution,
            "url": url,
            "param": param,
        })
    return sections


def parse_zap_report(report_path):
    with open(report_path, "r", encoding="utf-8", errors="ignore") as handle:
        content = handle.read()

    trimmed = content.lstrip()
    if not trimmed:
        return []

    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            return []
        return _parse_json_report(parsed)

    lower_head = trimmed[:200].lower()
    if "<html" in lower_head:
        return _parse_html_report(content)

    if trimmed.startswith("<"):
        return _parse_xml_report(content)

    return []
