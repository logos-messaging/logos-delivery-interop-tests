#!/bin/bash

set -e

WAKUCANARY_BIN="./wakucanary"

PEERS=(
  "/ip4/147.75.80.165/tcp/30303/p2p/16Uiu2HAmAj6uqzKX6F1M7Mf97TLGFeXkNiNzV7MvFpxRExo6FNTN"
  "/dns4/node.waku.example.com/tcp/30304/p2p/16Uiu2HAmYkD6x6Bj6h1fRfQtbMz5Epqfj12NpywPSrFNiLwo7uQ7"
)

REQUIRED_PROTOCOLS=(
  "/vac/waku/relay/2.0.0"
  "/vac/waku/store/2.0.0"
  "/vac/waku/filter/2.0.0"
  "/vac/waku/lightpush/2.0.0"
)

LOGFILE="protocol_check_$(date +%Y%m%d_%H%M%S).log"

echo "Starting protocol support verification..." | tee "$LOGFILE"
echo "------------------------------------" | tee -a "$LOGFILE"

for PEER in "${PEERS[@]}"; do
  echo "Checking peer: $PEER" | tee -a "$LOGFILE"
  OUTPUT=$("$WAKUCANARY_BIN" --peer="$PEER" --list-protocols 2>&1)
  EXIT_CODE=$?
  if [[ $EXIT_CODE -ne 0 ]]; then
    echo "❌ Failed to check protocols for $PEER" | tee -a "$LOGFILE"
    echo "$OUTPUT" >> "$LOGFILE"
    echo "------------------------------------" | tee -a "$LOGFILE"
    continue
  fi
  for PROTO in "${REQUIRED_PROTOCOLS[@]}"; do
    if echo "$OUTPUT" | grep -q "$PROTO"; then
      echo "✅ $PROTO supported" | tee -a "$LOGFILE"
    else
      echo "❌ $PROTO NOT supported" | tee -a "$LOGFILE"
    fi
  done
  echo "------------------------------------" | tee -a "$LOGFILE"
done

echo "Protocol verification completed. Results saved to: $LOGFILE"
