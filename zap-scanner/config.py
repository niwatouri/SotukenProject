import os


def _read_str_env(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _read_int_env(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    return int(raw)


def _read_float_env(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    return float(raw)


ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_SCANNER_API_KEY = os.getenv("ZAP_SCANNER_API_KEY")
ZAP_PROXY = "http://127.0.0.1:8090"
BACKEND_URL = _read_str_env("BACKEND_URL", "http://backend:8000")
SPIDER_MAX_DURATION_MINUTES = _read_int_env("SPIDER_MAX_DURATION_MINUTES", 20)
SPIDER_MAX_DEPTH = _read_int_env("SPIDER_MAX_DEPTH", 5)
SPIDER_MAX_CHILDREN = _read_int_env("SPIDER_MAX_CHILDREN", 0)
SPIDER_THREAD_COUNT = _read_int_env("SPIDER_THREAD_COUNT", 5)
ASCAN_MAX_DURATION_MINUTES = _read_int_env("ASCAN_MAX_DURATION_MINUTES", 40)
ASCAN_MAX_RULE_DURATION_MINUTES = _read_int_env("ASCAN_MAX_RULE_DURATION_MINUTES", 5)
ASCAN_MAX_RESULTS = _read_int_env("ASCAN_MAX_RESULTS", 1000)
ASCAN_THREADS_PER_HOST = _read_int_env("ASCAN_THREADS_PER_HOST", 5)
ASCAN_DELAY_IN_MS = _read_int_env("ASCAN_DELAY_IN_MS", 0)
PORT_SCAN_TIMEOUT = _read_float_env("PORT_SCAN_TIMEOUT", 0.7)
PORT_SCAN_PORTS = os.getenv("PORT_SCAN_PORTS")

DEFAULT_PORT_SCAN_PORTS = [
    80,
    443,
    8080,
    8443,
    8000,
    3000,
    22,
    21,
    25,
    110,
    143,
    3306,
    5432,
    6379,
]
