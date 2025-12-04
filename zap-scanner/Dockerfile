FROM ghcr.io/zaproxy/zaproxy:latest

USER root

RUN apt-get update -y && \
    apt-get install -y python3 python3-venv curl && \
    rm -rf /var/lib/apt/lists/*

# ZAP のログ用ディレクトリを作成（これが重要）
RUN mkdir -p /zap/logs

WORKDIR /app

COPY requirements.txt .
RUN python3 -m venv venv && \
    ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install -r requirements.txt

COPY scanner.py entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

EXPOSE 8090 5000

ENTRYPOINT ["/app/entrypoint.sh"]
