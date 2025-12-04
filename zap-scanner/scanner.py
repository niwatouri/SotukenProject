from flask import Flask, request, jsonify
import os
import time
from zapv2 import ZAPv2
import requests
from datetime import datetime

app = Flask(__name__)

ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_PROXY = "http://zap-scanner:8090"


# ZAP インスタンス
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY}
)

def wait_for_zap_ready(timeout=120):
    """ZAP が起動完了するまで待つ（entrypoint.sh でも待つが二重保険）"""
    print("Checking if ZAP is ready from scanner.py...")
    start = time.time()

    while time.time() - start < timeout:
        try:
            r = requests.get(f"{ZAP_PROXY}/JSON/core/view/version/", timeout=3)
            if r.status_code == 200:
                print("ZAP is ready.")
                return True
        except Exception:
            pass
        time.sleep(1)

    raise Exception("ZAP did not become ready in time.")

wait_for_zap_ready()


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("url")

    if not target:
        return jsonify({"error": "URL is required"}), 400

    print(f"Starting scan for: {target}")

    try:
        # Spider
        spider_id = zap.spider.scan(target)
        print(f"Spider started: {spider_id}")

        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(2)

        print("Spider completed")

        # Active Scan
        ascan_id = zap.ascan.scan(target)
        print(f"Active scan started: {ascan_id}")

        while int(zap.ascan.status(ascan_id)) < 100:
            time.sleep(5)

        print("Active scan completed")

        # レポート取得
        report_json = zap.core.jsonreport()

        # 保存先確保（Docker 内）
        report_dir = "/reports"
        os.makedirs(report_dir, exist_ok=True)

        # タイムスタンプ付きファイル名
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"zap_report_{timestamp}.json"
        filepath = os.path.join(report_dir, filename)

        # 保存
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_json)

        print(f"Saved report to: {filepath}")

        return jsonify({
            "message": "Scan completed",
            "saved_file": filename,
            "report_path": filepath,
            "report": report_json
        })

    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """コンテナ稼働チェック用"""
    return jsonify({"status": "running"})


if __name__ == "__main__":
    # デバッグ OFF（本番向け）
    app.run(host="0.0.0.0", port=5000)
