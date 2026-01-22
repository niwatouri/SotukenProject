FROM ghcr.io/zaproxy/zaproxy:latest

USER root

RUN apt-get update || true \
    && apt-get install -y tzdata curl \
    && ln -fs /usr/share/zoneinfo/Asia/Tokyo /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && apt-get install -y python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

COPY requirements.txt ./

RUN python3 -m venv venv && \
    ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt

COPY scanner.py config.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

EXPOSE 8090 5000

ENTRYPOINT ["./entrypoint.sh"]
