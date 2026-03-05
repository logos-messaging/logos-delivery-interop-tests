#!/bin/bash


WAKUCANARY_BIN="./wakucanary"

PEERS=(
  "/ip4/147.75.80.165/tcp/30303/p2p/16Uiu2HAmAj6uqzKX6F1M7Mf97TLGFeXkNiNzV7MvFpxRExo6FNTN"
  "/dns4/node.waku.example.com/tcp/30304/p2p/16Uiu2HAmYkD6x6Bj6h1fRfQtbMz5Epqfj12NpywPSrFNiLwo7uQ7"
)

LOGFILE="ping_results_$(date +%Y%m%d_%H%M%S).log"

PING_COUNT=3

echo "Starting peer ping test..." | tee "$LOGFILE"
echo "------------------------------------" | tee -a "$LOGFILE"

for PEER in "${PEERS[@]}"; do
  echo "Pinging peer: $PEER" | tee -a "$LOGFILE"
  "$WAKUCANARY_BIN" --peer="$PEER" --ping --count="$PING_COUNT" >> "$LOGFILE" 2>&1
  EXIT_CODE=$?
  if [[ $EXIT_CODE -eq 0 ]]; then
    echo "✅ Ping successful: $PEER" | tee -a "$LOGFILE"
  else
    echo "❌ Ping failed: $PEER (exit code: $EXIT_CODE)" | tee -a "$LOGFILE"
  fi
  echo "------------------------------------" | tee -a "$LOGFILE"
done

echo "Ping test completed. Results saved to: $LOGFILE"
