from flask import Flask, request, jsonify
import os
import time
from zapv2 import ZAPv2

app = Flask(__name__)

ZAP_API_KEY = os.getenv('ZAP_API_KEY')
ZAP_PROXY = 'http://127.0.0.1:8090'

zap = ZAPv2(apikey=ZAP_API_KEY,
           proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('url')
    if not target:
        return jsonify({"error": "URL is required"}), 400

    print(f"Starting scan for target: {target}")

    # Spider
    spider_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(2)

    # Active scan
    ascan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(ascan_id)) < 100:
        time.sleep(5)

    # レポート取得
    report = zap.core.jsonreport(apikey=ZAP_API_KEY)

    # JSONレポートをファイル保存（任意）
    with open('/reports/zap_report.json', 'w') as f:
        f.write(report)

    return jsonify({"message": "Scan complete", "report": report})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
