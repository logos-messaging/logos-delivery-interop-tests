#!/bin/bash

#this script build the canary app and make basic run to connect to well-known peer via TCP . 
set -e

PEER_ADDRESS="/dns4/node-01.do-ams3.waku.sandbox.status.im/tcp/8000/wss/p2p/16Uiu2HAmNaeL4p3WEYzC9mgXBmBWSgWjPHRvatZTXnp8Jgv3iKsb"
PROTOCOL="relay"
LOG_DIR="logs"
CLUSTER="16"
SHARD="64"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="$LOG_DIR/canary_run_$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

echo "Building Waku Canary app..."
make wakucanary >> "$LOG_FILE" 2>&1


echo "Running Waku Canary against:"
echo "  Peer    : $PEER_ADDRESS"
echo "  Protocol: $PROTOCOL"
echo "Log file  : $LOG_FILE"
echo "-----------------------------------"

{
  echo "=== Canary Run: $TIMESTAMP ==="
  echo "Peer     : $PEER_ADDRESS"
  echo "Protocol : $PROTOCOL"
  echo "LogLevel : DEBUG"
  echo "-----------------------------------"
  ./build/wakucanary \
    --address="$PEER_ADDRESS" \
    --protocol="$PROTOCOL" \
	--cluster-id="$CLUSTER"\
	--shard="$SHARD"\
    --log-level=DEBUG
  echo "-----------------------------------"
  echo "Exit code: $?"
} 2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}


if [ $EXIT_CODE -eq 0 ]; then
  echo "SUCCESS: Connected to peer and protocol '$PROTOCOL' is supported."
else
  echo "FAILURE: Could not connect or protocol '$PROTOCOL' is unsupported."
fi

exit $EXIT_CODE
