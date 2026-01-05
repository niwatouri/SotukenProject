import os
import re
import threading
import time
from urllib.parse import quote, urlparse
from zapv2 import ZAPv2
from flask import Flask, request, jsonify

app = Flask(__name__)

ZAP_API_KEY = os.getenv('ZAP_API_KEY')
ZAP_PROXY = 'http://127.0.0.1:8090'
SPIDER_MAX_DURATION_MINUTES = int(os.getenv("SPIDER_MAX_DURATION_MINUTES", "20"))
SPIDER_MAX_DEPTH = int(os.getenv("SPIDER_MAX_DEPTH", "5"))
SPIDER_MAX_CHILDREN = int(os.getenv("SPIDER_MAX_CHILDREN", "0"))
SPIDER_THREAD_COUNT = int(os.getenv("SPIDER_THREAD_COUNT", "5"))
ASCAN_MAX_DURATION_MINUTES = int(os.getenv("ASCAN_MAX_DURATION_MINUTES", "40"))
ASCAN_MAX_RULE_DURATION_MINUTES = int(os.getenv("ASCAN_MAX_RULE_DURATION_MINUTES", "5"))
ASCAN_MAX_RESULTS = int(os.getenv("ASCAN_MAX_RESULTS", "1000"))
ASCAN_THREADS_PER_HOST = int(os.getenv("ASCAN_THREADS_PER_HOST", "5"))
ASCAN_DELAY_IN_MS = int(os.getenv("ASCAN_DELAY_IN_MS", "0"))

zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY}
)

SCAN_LOCK = threading.Lock()

# 脆弱性タイプ → plugin ID
VULN_TYPE_IDS = {
    "sqli": [
        '40018', '40019', '40020',
        '40021', '40022', '40024', '40027'
    ],
    "xss": [
        '40012', '40014', '40016',
        '40017', '40026'
    ],
    "path_traversal": ['6'],
}

def _get_available_scanner_ids():
    """
    現在のZAPで有効なスキャナID一覧を取得する。
    """
    try:
        scanners_attr = zap.ascan.scanners
        scanners = scanners_attr() if callable(scanners_attr) else scanners_attr
    except Exception as exc:
        print(f"[!] Failed to load scanners list: {exc}")
        return None

    if isinstance(scanners, dict):
        scanners = scanners.get("scanners", [])
    if not isinstance(scanners, list):
        return None

    available = set()
    for scanner in scanners:
        if isinstance(scanner, dict) and scanner.get("id") is not None:
            available.add(str(scanner["id"]))
    return available


def _build_auth_status(used=False, method=None, success=None, message=None):
    status = {"used": used}
    if method:
        status["method"] = method
    if success is not None:
        status["success"] = success
    if message:
        status["message"] = message
    return status


def _safe_set_option(target, method_name, value):
    method = getattr(target, method_name, None)
    if not method:
        return False
    try:
        method(value)
        return True
    except TypeError:
        try:
            method(str(value))
            return True
        except Exception:
            return False
    except Exception:
        return False


def _apply_spider_options():
    _safe_set_option(zap.spider, "set_option_max_duration", SPIDER_MAX_DURATION_MINUTES)
    _safe_set_option(zap.spider, "set_option_max_depth", SPIDER_MAX_DEPTH)
    _safe_set_option(zap.spider, "set_option_max_children", SPIDER_MAX_CHILDREN)
    _safe_set_option(zap.spider, "set_option_thread_count", SPIDER_THREAD_COUNT)


def _apply_ascan_options():
    _safe_set_option(zap.ascan, "set_option_max_duration", ASCAN_MAX_DURATION_MINUTES)
    _safe_set_option(zap.ascan, "set_option_max_scan_duration_in_min", ASCAN_MAX_DURATION_MINUTES)
    _safe_set_option(zap.ascan, "set_option_max_scan_duration_in_mins", ASCAN_MAX_DURATION_MINUTES)
    _safe_set_option(zap.ascan, "set_option_max_rule_duration_in_minutes", ASCAN_MAX_RULE_DURATION_MINUTES)
    _safe_set_option(zap.ascan, "set_option_max_rule_duration_in_mins", ASCAN_MAX_RULE_DURATION_MINUTES)
    _safe_set_option(zap.ascan, "set_option_max_results_to_list", ASCAN_MAX_RESULTS)
    _safe_set_option(zap.ascan, "set_option_threads_per_host", ASCAN_THREADS_PER_HOST)
    _safe_set_option(zap.ascan, "set_option_delay_in_ms", ASCAN_DELAY_IN_MS)


def _build_context_regex(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return ".*"
    base = f"{parsed.scheme}://{parsed.netloc}"
    return re.escape(base) + ".*"


def _normalize_numeric_id(value):
    if value is None:
        return None
    value_str = str(value).strip()
    return value_str if value_str.isdigit() else None


def _normalize_scan_id(value):
    if isinstance(value, dict):
        value = value.get("scanId") or value.get("scan_id") or value.get("id") or value.get("scan")
    return _normalize_numeric_id(value)


def _safe_stop_scan(stop_func, scan_id):
    if not stop_func:
        return
    try:
        stop_func(scan_id)
    except TypeError:
        try:
            stop_func()
        except Exception:
            pass
    except Exception:
        pass


def _poll_scan_status(status_func, scan_id, sleep_seconds, label, max_seconds=None, stop_func=None):
    start_time = time.time()
    while True:
        if max_seconds is not None and (time.time() - start_time) > max_seconds:
            _safe_stop_scan(stop_func, scan_id)
            return False, f"{label} が上限時間に達しました"
        try:
            status_value = status_func(scan_id)
        except Exception:
            _safe_stop_scan(stop_func, scan_id)
            return False, f"{label} のステータス取得に失敗しました"
        if isinstance(status_value, dict):
            status_value = status_value.get("status") or status_value.get("statusCode") or status_value.get("code")
        try:
            status_int = int(status_value)
        except (TypeError, ValueError):
            _safe_stop_scan(stop_func, scan_id)
            return False, f"{label} のステータスが不正です: {status_value}"
        if status_int >= 100:
            return True, None
        time.sleep(sleep_seconds)


def _mark_auth_fallback(auth_status, message):
    if isinstance(auth_status, dict) and auth_status.get("used"):
        auth_status["success"] = False
        auth_status["message"] = message


def _append_auth_message(auth_status, message):
    if not isinstance(auth_status, dict) or not message or not auth_status.get("used"):
        return
    current = auth_status.get("message")
    if current:
        auth_status["message"] = f"{current} / {message}"
    else:
        auth_status["message"] = message


def _extract_spider_urls(spider_id):
    try:
        urls = zap.spider.results(spider_id)
    except Exception:
        return []

    if isinstance(urls, dict):
        urls = urls.get("results") or urls.get("urls") or urls.get("result")
    if not isinstance(urls, list):
        return []
    return [u for u in urls if isinstance(u, str)]


def _is_valid_scan_url(candidate, target):
    try:
        parsed = urlparse(candidate)
        target_parsed = urlparse(target)
    except Exception:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    if target_parsed.scheme and target_parsed.netloc:
        return parsed.scheme == target_parsed.scheme and parsed.netloc == target_parsed.netloc
    return True


def _pick_scan_target(target, spider_id):
    urls = _extract_spider_urls(spider_id)
    if not urls:
        return target
    valid_urls = [url for url in urls if _is_valid_scan_url(url, target)]
    if not valid_urls:
        return target
    if target in valid_urls:
        return target
    for url in valid_urls:
        if url.startswith(target):
            return url
    return valid_urls[0]


def _access_target(target_url):
    try:
        zap.core.access_url(target_url, "true", apikey=ZAP_API_KEY)
    except TypeError:
        try:
            zap.core.access_url(target_url, "true")
        except Exception:
            try:
                zap.core.access_url(target_url)
            except Exception:
                pass
    except Exception:
        pass


def _build_login_request_data(auth):
    login_request_data = auth.get("login_request_data")
    if isinstance(login_request_data, str) and login_request_data.strip():
        return login_request_data.strip()

    username_field = auth.get("username_field") or "username"
    password_field = auth.get("password_field") or "password"
    extra_params = auth.get("extra_params") or ""

    username_field = str(username_field).strip() or "username"
    password_field = str(password_field).strip() or "password"

    base = f"{username_field}=%username%&{password_field}=%password%"
    if isinstance(extra_params, str) and extra_params.strip():
        extra = extra_params.strip()
        if extra.startswith("&"):
            extra = extra[1:]
        return f"{base}&{extra}"
    return base


def _send_request_via_zap(raw_request):
    try:
        return zap.core.send_request(raw_request, "true", apikey=ZAP_API_KEY)
    except TypeError:
        try:
            return zap.core.send_request(raw_request, "true")
        except Exception:
            try:
                return zap.core.send_request(raw_request)
            except Exception:
                return None
    except Exception:
        return None


def _verify_form_auth(context_id, user_id, login_indicator):
    if not login_indicator:
        return None, "ログイン成功判定が未設定のため未検証です"

    try:
        auth_req = zap.users.authenticate_as_user(context_id, user_id, apikey=ZAP_API_KEY)
    except Exception:
        return None, "認証チェックに失敗しました"

    if not isinstance(auth_req, dict):
        return None, "認証リクエストを取得できませんでした"

    request_header = auth_req.get("requestHeader")
    request_body = auth_req.get("requestBody") or ""
    if not request_header:
        return None, "認証リクエストが不正です"

    raw_request = request_header
    if request_body:
        raw_request += "\r\n\r\n" + request_body

    response = _send_request_via_zap(raw_request)
    if not isinstance(response, dict):
        return None, "認証チェックの応答が取得できませんでした"

    response_body = response.get("responseBody") or ""
    if login_indicator in response_body:
        return True, "ログイン成功判定を確認しました"
    return False, "ログイン成功判定が見つかりませんでした"

def _apply_form_auth(auth, target_url):
    login_url = auth.get("login_url")
    username = auth.get("username")
    password = auth.get("password")
    login_indicator = auth.get("login_indicator")

    if not login_url or not username or not password:
        return None, None, _build_auth_status(
            used=True,
            method="form",
            success=False,
            message="フォーム認証の必須項目が不足しています",
        )

    context_name = f"auth-context-{int(time.time() * 1000)}"
    context_id = zap.context.new_context(context_name)
    if isinstance(context_id, dict):
        context_id = context_id.get("contextId") or context_id.get("context_id") or context_id.get("id")
    context_id = _normalize_numeric_id(context_id)
    if not context_id:
        return None, None, _build_auth_status(
            used=True,
            method="form",
            success=False,
            message="認証コンテキストの作成に失敗しました",
        )
    include_regex = _build_context_regex(target_url)
    zap.context.include_in_context(context_name, include_regex)
    zap.context.set_context_in_scope(context_name, "true")

    login_request_data = _build_login_request_data(auth)
    if not login_request_data:
        return None, None, _build_auth_status(
            used=True,
            method="form",
            success=False,
            message="ログインリクエストパラメータが不正です",
        )
    auth_params = (
        f"loginUrl={quote(login_url, safe='')}&"
        f"loginRequestData={quote(login_request_data, safe='')}"
    )
    zap.authentication.set_authentication_method(
        context_id,
        "formBasedAuthentication",
        auth_params,
        apikey=ZAP_API_KEY,
    )

    if login_indicator:
        zap.authentication.set_logged_in_indicator(context_id, login_indicator, apikey=ZAP_API_KEY)

    user_id = zap.users.new_user(context_id, "scan-user")
    if isinstance(user_id, dict):
        user_id = user_id.get("userId") or user_id.get("user_id") or user_id.get("id")
    user_id = _normalize_numeric_id(user_id)
    if not user_id:
        return None, None, _build_auth_status(
            used=True,
            method="form",
            success=False,
            message="認証ユーザーの作成に失敗しました",
        )
    cred_params = f"username={quote(username, safe='')}&password={quote(password, safe='')}"
    zap.users.set_authentication_credentials(context_id, user_id, cred_params, apikey=ZAP_API_KEY)
    zap.users.set_user_enabled(context_id, user_id, "true", apikey=ZAP_API_KEY)
    zap.forcedUser.set_forced_user(context_id, user_id, apikey=ZAP_API_KEY)
    zap.forcedUser.set_forced_user_mode_enabled("true", apikey=ZAP_API_KEY)

    return context_name, (context_id, user_id), _build_auth_status(
        used=True,
        method="form",
        success=None,
        message="フォーム認証を設定しました",
    )


def _apply_header_auth(header_value):
    if not header_value:
        return None, _build_auth_status(
            used=True,
            method="header",
            success=False,
            message="Authorizationヘッダの値が空です",
        )

    rule_id = zap.replacer.add_rule(
        description="scan-auth-header",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Authorization",
        replacement=header_value,
        apikey=ZAP_API_KEY,
    )
    if isinstance(rule_id, dict):
        rule_id = rule_id.get("ruleId") or rule_id.get("rule_id") or rule_id.get("id")
    return rule_id, _build_auth_status(
        used=True,
        method="header",
        success=True,
        message="Authorizationヘッダを付与してスキャンします",
    )


def _apply_cookie_auth(cookie_value):
    if not cookie_value:
        return None, _build_auth_status(
            used=True,
            method="cookie",
            success=False,
            message="セッションCookieが空です",
        )

    rule_id = zap.replacer.add_rule(
        description="scan-auth-cookie",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring="Cookie",
        replacement=cookie_value,
        apikey=ZAP_API_KEY,
    )
    if isinstance(rule_id, dict):
        rule_id = rule_id.get("ruleId") or rule_id.get("rule_id") or rule_id.get("id")
    return rule_id, _build_auth_status(
        used=True,
        method="cookie",
        success=True,
        message="Cookieヘッダを付与してスキャンします",
    )


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('url')
    scan_types = data.get('scan_types', [])
    if not isinstance(scan_types, list):
        scan_types = []
    scan_types = [str(t).lower() for t in scan_types if isinstance(t, (str, bytes))]
    if len(scan_types) == 0:
        scan_types = ["all"]  # 指定が無い場合は全スキャン扱い

    if not target:
        return jsonify({"error": "URL is required"}), 400

    lock_acquired = SCAN_LOCK.acquire(blocking=False)
    if not lock_acquired:
        return jsonify({"error": "scanner busy"}), 429

    print(f"[*] Start scan target={target}, scan_types={scan_types}")

    # --- plugin IDの決定 ---
    enabled_ids = []

    if "all" in scan_types:
        # 全タイプ ON
        for ids in VULN_TYPE_IDS.values():
            enabled_ids.extend(ids)
    else:
        # 指定されたタイプのみ
        for t in scan_types:
            enabled_ids.extend(VULN_TYPE_IDS.get(t, []))

    enabled_ids = list(set(enabled_ids))           # 重複除去
    enabled_ids_str = ",".join(enabled_ids)        # カンマ区切り文字列

    print(f"[+] Enable plugin IDs: {enabled_ids_str}")


    auth_config = data.get("auth") if isinstance(data, dict) else None
    auth_status = _build_auth_status(used=False, success=None)
    replacer_rules = []
    context_name = None
    user_context = None

    try:
        if isinstance(auth_config, dict):
            method = auth_config.get("method")
            try:
                if method == "form":
                    context_name, user_context, auth_status = _apply_form_auth(auth_config, target)
                elif method == "cookie":
                    rule_id, auth_status = _apply_cookie_auth(auth_config.get("cookie"))
                    if rule_id is not None:
                        replacer_rules.append(rule_id)
                elif method == "header":
                    rule_id, auth_status = _apply_header_auth(auth_config.get("header"))
                    if rule_id is not None:
                        replacer_rules.append(rule_id)
                else:
                    auth_status = _build_auth_status(
                        used=True,
                        method=method,
                        success=False,
                        message="未対応の認証方式です",
                    )
            except Exception:
                auth_status = _build_auth_status(
                    used=True,
                    method=method,
                    success=False,
                    message="認証設定に失敗しました",
                )

        if user_context and isinstance(auth_config, dict) and auth_config.get("method") == "form":
            context_id, user_id = user_context
            success, message = _verify_form_auth(context_id, user_id, auth_config.get("login_indicator"))
            if success is not None:
                auth_status["success"] = success
            if message:
                auth_status["message"] = message
            if auth_status.get("success") is False:
                try:
                    zap.forcedUser.set_forced_user_mode_enabled("false", apikey=ZAP_API_KEY)
                except Exception:
                    pass
                user_context = None

        _apply_spider_options()
        _apply_ascan_options()

        # --- パッシブスキャン停止 ---
        zap.pscan.set_enabled(enabled='false', apikey=ZAP_API_KEY)


        # --- Spider ---
        print("[*] Starting spider...")
        if user_context:
            context_id, user_id = user_context
            try:
                spider_id = zap.spider.scan_as_user(
                    contextid=context_id,
                    userid=user_id,
                    url=target,
                )
            except TypeError:
                spider_id = zap.spider.scan_as_user(context_id, user_id, target)
        else:
            spider_id = zap.spider.scan(target)

        spider_id = _normalize_scan_id(spider_id)
        if not spider_id and user_context:
            _mark_auth_fallback(auth_status, "認証スパイダー開始に失敗したため未認証で実行します")
            spider_id = _normalize_scan_id(zap.spider.scan(target))

        if not spider_id:
            raise RuntimeError("Spider start failed")

        spider_completed, spider_message = _poll_scan_status(
            zap.spider.status,
            spider_id,
            2,
            "Spider",
            max_seconds=SPIDER_MAX_DURATION_MINUTES * 60,
            stop_func=zap.spider.stop,
        )
        if not spider_completed and spider_message:
            _append_auth_message(auth_status, spider_message)
        print("[+] Spider complete.")


        # --- Active Scan ---
        print("[*] Starting Active Scan...")

        # 全無効化
        zap.ascan.disable_all_scanners(apikey=ZAP_API_KEY)
        print("[+] Disabled all scanners.")

        # 未知のscan_typesなどで有効IDがなければデフォルトセットを有効化
        if not enabled_ids_str:
            for ids in VULN_TYPE_IDS.values():
                enabled_ids.extend(ids)
            enabled_ids = list(set(enabled_ids))
            enabled_ids_str = ",".join(enabled_ids)
            print(f"[!] No valid scan_types provided. Falling back to default set: {enabled_ids_str}")

        # 必要な plugin IDs だけ有効化
        if enabled_ids_str:
            available_ids = _get_available_scanner_ids()
            if available_ids:
                enabled_ids = [sid for sid in enabled_ids if sid in available_ids]
                enabled_ids_str = ",".join(enabled_ids)
                if enabled_ids_str:
                    zap.ascan.enable_scanners(ids=enabled_ids_str, apikey=ZAP_API_KEY)
                    print(f"[+] Enabled scanners: {enabled_ids_str}")
                else:
                    print("[!] No valid scanner IDs matched. Falling back to enable all scanners.")
                    zap.ascan.enable_all_scanners(apikey=ZAP_API_KEY)
            else:
                try:
                    zap.ascan.enable_scanners(ids=enabled_ids_str, apikey=ZAP_API_KEY)
                    print(f"[+] Enabled scanners: {enabled_ids_str}")
                except Exception as exc:
                    print(f"[!] Failed to enable scanners by ID: {exc}. Falling back to enable all scanners.")
                    zap.ascan.enable_all_scanners(apikey=ZAP_API_KEY)
        else:
            return jsonify({"error": "No valid scan_types provided"}), 400

        # Active Scan 実行
        scan_target = _pick_scan_target(target, spider_id)
        if scan_target != target:
            _access_target(scan_target)
        else:
            _access_target(target)

        if user_context:
            context_id, user_id = user_context
            try:
                ascan_id = zap.ascan.scan_as_user(
                    url=scan_target,
                    contextid=context_id,
                    userid=user_id,
                    apikey=ZAP_API_KEY,
                )
            except TypeError:
                ascan_id = zap.ascan.scan_as_user(scan_target, context_id, user_id, apikey=ZAP_API_KEY)
        else:
            ascan_id = zap.ascan.scan(scan_target, apikey=ZAP_API_KEY)

        ascan_id = _normalize_scan_id(ascan_id)
        active_scan_ran = False

        if not ascan_id and user_context:
            _mark_auth_fallback(auth_status, "認証アクティブスキャン開始に失敗したため未認証で実行します")
            ascan_id = _normalize_scan_id(zap.ascan.scan(scan_target, apikey=ZAP_API_KEY))

        if not ascan_id:
            _mark_auth_fallback(auth_status, "アクティブスキャン開始に失敗したためスキャンを継続します（結果が不完全な可能性があります）")
        else:
            ascan_completed, ascan_message = _poll_scan_status(
                zap.ascan.status,
                ascan_id,
                5,
                "Active Scan",
                max_seconds=ASCAN_MAX_DURATION_MINUTES * 60,
                stop_func=zap.ascan.stop,
            )
            if ascan_completed:
                active_scan_ran = True
            else:
                if ascan_message:
                    _append_auth_message(auth_status, ascan_message)
                if user_context:
                    _mark_auth_fallback(auth_status, "認証アクティブスキャンが完了しなかったため未認証で再実行します")
                    ascan_id = _normalize_scan_id(zap.ascan.scan(scan_target, apikey=ZAP_API_KEY))
                    if ascan_id:
                        fallback_completed, fallback_message = _poll_scan_status(
                            zap.ascan.status,
                            ascan_id,
                            5,
                            "Active Scan",
                            max_seconds=ASCAN_MAX_DURATION_MINUTES * 60,
                            stop_func=zap.ascan.stop,
                        )
                        if fallback_completed:
                            active_scan_ran = True
                        elif fallback_message:
                            _append_auth_message(auth_status, fallback_message)
                    else:
                        _append_auth_message(auth_status, "アクティブスキャン開始に失敗しました")
                else:
                    _append_auth_message(auth_status, "アクティブスキャンが完了しませんでした")

        if active_scan_ran:
            print("[+] Active Scan complete.")
        else:
            print("[!] Active Scan skipped.")

    finally:
        for rule_id in replacer_rules:
            try:
                zap.replacer.remove_rule(rule_id, apikey=ZAP_API_KEY)
            except Exception:
                pass
        if user_context:
            try:
                zap.forcedUser.set_forced_user_mode_enabled("false", apikey=ZAP_API_KEY)
            except Exception:
                pass
        if context_name:
            try:
                zap.context.remove_context(context_name, apikey=ZAP_API_KEY)
            except Exception:
                pass
        if lock_acquired:
            SCAN_LOCK.release()

    # レポート取得
    report = zap.core.jsonreport(apikey=ZAP_API_KEY)

    # JSONレポートをファイル保存（任意）
    with open('/reports/zap_report.json', 'w') as f:
        f.write(report)

    return jsonify({"message": "Scan complete", "report": report, "auth_status": auth_status})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
