FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/wait_for_report.sh

CMD ["/app/wait_for_report.sh"]
