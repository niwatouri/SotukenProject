import os


def _read_str_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def _read_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    return int(raw)


DB_HOST = _read_str_env("DB_HOST", "db")
DB_PORT = _read_int_env("DB_PORT", 5432)
DB_USER = _read_str_env("DB_USER", "postgres")
DB_PASSWORD = _read_str_env("DB_PASSWORD", "postgres")
DB_NAME = _read_str_env("DB_NAME", "mydb")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

SCAN_TIMEOUT_SECONDS = _read_int_env("SCAN_TIMEOUT_SECONDS", 3600)
ZAP_SCANNER_URL = os.getenv("ZAP_SCANNER_URL", "http://zap-scanner:5000")
ZAP_SCANNER_API_KEY = os.getenv("ZAP_SCANNER_API_KEY")

JWT_SECRET = os.getenv("JWT_SECRET")
OPENAI_API_KEY = _read_str_env("OPENAI_API_KEY", "")
OPENAI_MODEL = _read_str_env("OPENAI_MODEL", "gpt-4o-mini")
