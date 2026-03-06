#!/usr/bin/env bash
source .venv/bin/activate
echo "Starting event forwarder in demo mode..."
python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl &
PID=$!
sleep 2
echo "Forwarder is running (PID: $PID)"
echo "You can view the latest events at: http://localhost:8081/events/latest"
wait $PID
