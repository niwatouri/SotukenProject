# backend/app/worker.py
import os
import sys

# Ensure project root is on sys.path so app.* imports resolve when RQ loads jobs.
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from redis import Redis
from rq import Worker, Queue, Connection
from app.config import REDIS_HOST, REDIS_PORT
from app.db import init_scan_schema

listen = ['default']
redis_conn = Redis(host=REDIS_HOST, port=REDIS_PORT)

if __name__ == '__main__':
    init_scan_schema()
    with Connection(redis_conn):
        # Runs on the default queue; adjust `listen` if queues are added later.
        worker = Worker(list(map(Queue, listen)))
        worker.work()
