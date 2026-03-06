#!/bin/bash
source .venv/bin/activate
echo "Starting Sentinel-Core Event Forwarder in Offline Demo Mode..."
echo "Simulating events from fixtures/sample-tetragon-raw.jsonl"
echo "--------------------------------------------------------"

cat << 'PYEOF' > loop_demo.py
import json
import logging
import time
import threading
import sys

from forwarder.main import process_line
from forwarder.publisher import EventPublisher
from forwarder.config import Config
from forwarder.api import app as fastapi_app
import uvicorn
from forwarder.api import set_redis_status

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("sentinel.demo")

# Start API
config = Config()
def run_api():
    uvicorn.run(fastapi_app, host="0.0.0.0", port=8081, log_level="warning")
    
threading.Thread(target=run_api, daemon=True).start()
time.sleep(1) # wait for api to start

publisher = EventPublisher(config)
set_redis_status(publisher.is_connected)

print(f"\n🚀 Forwarder API is running at http://127.0.0.1:8081\n")

# Read lines once
lines = []
with open("fixtures/sample-tetragon-raw.jsonl", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

# Infinite loop processing
try:
    loop_count = 1
    while True:
        logger.info(f"--- Processing Loop #{loop_count} ---")
        for line in lines:
            process_line(line, publisher)
            time.sleep(1) # stagger events slightly
        time.sleep(10) # wait before next loop
        loop_count += 1
except KeyboardInterrupt:
    print("\nStopping demo...")
    publisher.close()
    sys.exit(0)
PYEOF

python loop_demo.py
