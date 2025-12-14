import os
import time
from zapv2 import ZAPv2
from flask import Flask, request, jsonify

app = Flask(__name__)

ZAP_API_KEY = os.getenv('ZAP_API_KEY')
ZAP_PROXY = 'http://127.0.0.1:8090'

zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY}
)

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


    # --- パッシブスキャン停止 ---
    zap.pscan.set_enabled(enabled='false', apikey=ZAP_API_KEY)


    # --- Spider ---
    print("[*] Starting spider...")
    spider_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_id)) < 100:
        print(f"    Spider progress: {zap.spider.status(spider_id)}%")
        time.sleep(2)
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
        zap.ascan.enable_scanners(ids=enabled_ids_str, apikey=ZAP_API_KEY)
        print(f"[+] Enabled scanners: {enabled_ids_str}")
    else:
        return jsonify({"error": "No valid scan_types provided"}), 400

    # Active Scan 実行
    ascan_id = zap.ascan.scan(target, apikey=ZAP_API_KEY)
    while int(zap.ascan.status(ascan_id)) < 100:
        print(f"    Scan progress: {zap.ascan.status(ascan_id)}%")
        time.sleep(5)
    print("[+] Active Scan complete.")


    # レポート取得
    report = zap.core.jsonreport(apikey=ZAP_API_KEY)

    # JSONレポートをファイル保存（任意）
    with open('/reports/zap_report.json', 'w') as f:
        f.write(report)

    return jsonify({"message": "Scan complete", "report": report})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
