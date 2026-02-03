from __future__ import annotations

import copy
from typing import Any, Dict, Optional


SCAN_PRESETS: Dict[str, Dict[str, Any]] = {
    "fast": {
        "preset": "fast",
        "max_duration_seconds": 120,
        "scope_same_host_only": True,
        "spider": {
            "max_depth": 3,
            "max_children": 20,
            "max_duration_seconds": 60,
        },
        "active_scan": {
            "enabled": True,
            "max_duration_seconds": 60,
            "attack_strength": "Low",
            "alert_threshold": "High",
        },
        "passive_wait_seconds": 15,
        "rate_limit": {
            "delay_ms": 150,
        },
        "alert_fetch": {
            "include_risks": ["High", "Medium", "Low", "Informational"],
        },
    },
    "balanced": {
        "preset": "balanced",
        "max_duration_seconds": 300,
        "scope_same_host_only": True,
        "spider": {
            "max_depth": 5,
            "max_children": 120,
            "max_duration_seconds": 180,
        },
        "active_scan": {
            "enabled": True,
            "max_duration_seconds": 180,
            "attack_strength": "Medium",
            "alert_threshold": "Medium",
        },
        "passive_wait_seconds": 30,
        "rate_limit": {
            "delay_ms": 80,
        },
        "alert_fetch": {
            "include_risks": ["High", "Medium", "Low", "Informational"],
        },
    },
    "deep": {
        "preset": "deep",
        "max_duration_seconds": 600,
        "scope_same_host_only": True,
        "spider": {
            "max_depth": 8,
            "max_children": 120,
            "max_duration_seconds": 180,
        },
        "active_scan": {
            "enabled": True,
            "max_duration_seconds": 420,
            "attack_strength": "High",
            "alert_threshold": "Low",
        },
        "passive_wait_seconds": 45,
        "rate_limit": {
            "delay_ms": 50,
        },
        "alert_fetch": {
            "include_risks": ["High", "Medium", "Low", "Informational"],
        },
    },
}

DEFAULT_PRESET = "balanced"


def _to_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _to_bool(value: Any, fallback: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return fallback


def build_scan_config(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    preset = payload.get("preset") or DEFAULT_PRESET
    if preset not in SCAN_PRESETS:
        preset = DEFAULT_PRESET
    config = copy.deepcopy(SCAN_PRESETS[preset])
    config["preset"] = preset

    max_duration = _to_int(payload.get("max_duration_seconds"), config["max_duration_seconds"])
    max_duration = max(30, max_duration)
    config["max_duration_seconds"] = max_duration

    config["scope_same_host_only"] = _to_bool(
        payload.get("scope_same_host_only"),
        config.get("scope_same_host_only", True),
    )

    spider = config.get("spider", {})
    spider["max_depth"] = _to_int(payload.get("spider_max_depth"), spider.get("max_depth", 5))
    spider["max_children"] = _to_int(payload.get("spider_max_children"), spider.get("max_children", 60))
    spider["max_duration_seconds"] = _to_int(
        payload.get("spider_max_duration_seconds"),
        spider.get("max_duration_seconds", 120),
    )

    active = config.get("active_scan", {})
    active["enabled"] = _to_bool(payload.get("active_scan_enabled"), active.get("enabled", True))
    active["max_duration_seconds"] = _to_int(
        payload.get("active_scan_max_duration_seconds"),
        active.get("max_duration_seconds", 180),
    )
    if payload.get("attack_strength"):
        active["attack_strength"] = str(payload.get("attack_strength"))
    if payload.get("alert_threshold"):
        active["alert_threshold"] = str(payload.get("alert_threshold"))

    config["passive_wait_seconds"] = _to_int(
        payload.get("passive_wait_seconds"),
        config.get("passive_wait_seconds", 30),
    )

    rate_limit = config.get("rate_limit", {})
    rate_limit["delay_ms"] = _to_int(payload.get("delay_ms"), rate_limit.get("delay_ms", 80))
    config["rate_limit"] = rate_limit

    alert_fetch = config.get("alert_fetch", {})
    include_risks = payload.get("include_risks")
    if isinstance(include_risks, list) and include_risks:
        alert_fetch["include_risks"] = include_risks
    config["alert_fetch"] = alert_fetch

    # Clamp stage durations to overall max_duration_seconds
    spider["max_duration_seconds"] = max(5, min(spider["max_duration_seconds"], max_duration))
    active["max_duration_seconds"] = max(5, min(active["max_duration_seconds"], max_duration))
    config["passive_wait_seconds"] = max(0, min(config["passive_wait_seconds"], max_duration))
    config["spider"] = spider
    config["active_scan"] = active

    return config


def get_presets_payload() -> Dict[str, Any]:
    return {
        "default_preset": DEFAULT_PRESET,
        "presets": copy.deepcopy(SCAN_PRESETS),
    }
