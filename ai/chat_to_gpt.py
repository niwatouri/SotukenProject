import json
import os
import sys
import tempfile

from zap_report_parser import parse_zap_report
from chatgpt_helper import generate_suggestion


def write_atomic(path, data, mode="w"):
    dirn = os.path.dirname(path)
    if dirn:
        os.makedirs(dirn, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirn or None)
    with os.fdopen(fd, mode, encoding="utf-8") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _clip(value, limit=1500):
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


if __name__ == "__main__":
    report_path = os.environ.get("REPORT_PATH", "/reports/zap_report.xml")
    out_json_path = os.environ.get("AI_JSON_PATH", "/reports/ai_advice.json")
    out_txt_path = os.environ.get("AI_TXT_PATH", "/reports/ai_advice.txt")

    if not os.path.isfile(report_path):
        print(f"Report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    vulns = parse_zap_report(report_path)
    if not vulns:
        write_atomic(out_json_path, json.dumps([], ensure_ascii=False, indent=2))
        write_atomic(out_txt_path, "No vulnerabilities found.\n")
        sys.exit(0)

    results = []
    txt_lines = []
    for index, vuln in enumerate(vulns, start=1):
        normalized = {
            "id": vuln.get("id"),
            "title": _clip(vuln.get("title")),
            "risk": _clip(vuln.get("risk")),
            "description": _clip(vuln.get("description")),
            "solution": _clip(vuln.get("solution")),
            "url": _clip(vuln.get("url")),
            "param": _clip(vuln.get("param")),
        }

        try:
            suggestion = generate_suggestion(normalized)
        except Exception as exc:
            suggestion = f"AI request failed: {exc}"
        entry = {
            "index": index,
            "title": normalized.get("title") or "Unknown",
            "risk": normalized.get("risk"),
            "url": normalized.get("url"),
            "param": normalized.get("param"),
            "suggestion": suggestion,
        }
        results.append(entry)

        txt_lines.append(f"--- [{index}] {entry['title']} ---")
        txt_lines.append(suggestion)
        txt_lines.append("")

    json_data = json.dumps(results, ensure_ascii=False, indent=2)
    txt_data = "\n".join(txt_lines)

    try:
        write_atomic(out_json_path, json_data)
        write_atomic(out_txt_path, txt_data)
        print(f"Saved AI output: {out_json_path}, {out_txt_path}")
    except Exception as exc:
        print(f"Failed to write output: {exc}", file=sys.stderr)
        sys.exit(2)
