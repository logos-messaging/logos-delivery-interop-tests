#!/bin/bash
set -e

#  Store stress via high Sonda concurrency & query rate,
#   while stepping message sizes and LPT counts to fill history fast.

cd ./waku-simulator

export NWAKU_IMAGE=wakuorg/nwaku:latest
export NUM_NWAKU_NODES=15
export RLN_ENABLED=false

# Service node config
export SERVICENODE_CPU_CORES="0-3"
export SERVICENODE_MEM_LIMIT=2g
export POSTGRES_CPU_CORES="0-3"
export POSTGRES_MEM_LIMIT=2g
export POSTGRES_SHM=1g

docker compose up -d

# Wait until service node is running
while true; do
  sid="$(docker compose ps -q servicenode || true)"
  if [[ -n "$sid" ]]; then
    state="$(docker inspect --format '{{.State.Status}}' "$sid" 2>/dev/null || true)"
    [[ "$state" == "running" ]] && break
  fi
  sleep 1
done

cd ../lpt

# -------------------- LPT config ---------------------------
export LPT_IMAGE=harbor.status.im/wakuorg/liteprotocoltester:latest
export START_PUBLISHING_AFTER=15
export NUM_MESSAGES=0
export MESSAGE_INTERVAL_MILLIS=100

# Service peers 
export LIGHTPUSH_SERVICE_PEER=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
export FILTER_SERVICE_PEER=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n

# Topics
export PUBSUB=/waku/2/rs/66/0
export CONTENT_TOPIC=/tester/2/light-pubsub-test/wakusim
export CLUSTER_ID=66

# sleep before traffic
sleep 60

cd ../sonda
docker build -t local-perf-sonda -f ./Dockerfile.sonda .

cat <<EOF > perf-test.env
RELAY_NODE_REST_ADDRESS=http://127.0.0.1:8645
STORE_NODE_REST_ADDRESS=http://127.0.0.1:8644
QUERY_DELAY=0.5
STORE_NODES=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
CLUSTER_ID=66
SHARD=0
EOF

sleep 5

# Clean up
docker rm -f sonda1 sonda2 sonda3 sonda4 sonda5 >/dev/null 2>&1 || true

# Start a baseline Sonda (0.5s)
docker run -d --name sonda1 --network host -l sonda \
  --env-file ./perf-test.env local-perf-sonda

cd ../lpt

# ============================================================================ #
# PHASE 1: Moderate traffic 
# LPT 6/6, 50–90 KB; Sonda x1  time 0.5s
# ============================================================================ #
export NUM_PUBLISHER_NODES=6
export NUM_RECEIVER_NODES=6
export MIN_MESSAGE_SIZE=50Kb
export MAX_MESSAGE_SIZE=90Kb

docker compose down -v >/dev/null 2>&1 || true
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[scenario_6_store_stress] Phase 1: LPT 6/6, 50–90KB; Sonda x1 @0.5s — $current_time"
sleep 120

# ============================================================================ #
# PHASE 2: Same traffic but triple query rate
# Keep LPT, add Sonda x2 more time 0.1s 
# ============================================================================ #
docker run -d --name sonda2 --network host -l sonda \
  --env-file ../sonda/perf-test.env -e QUERY_DELAY=0.1 local-perf-sonda
docker run -d --name sonda3 --network host -l sonda \
  --env-file ../sonda/perf-test.env -e QUERY_DELAY=0.1 local-perf-sonda

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[scenario_6_store_stress] Phase 2: add Sonda x2 @0.1s (total 3) — $current_time"
sleep 120

# ============================================================================ #
# PHASE 3: Heavier traffic + peak query rate
# LPT 10/10, 130–149 KB; add Sonda x2 more time 0.05s 
# ============================================================================ #
docker compose down -v
export NUM_PUBLISHER_NODES=10
export NUM_RECEIVER_NODES=10
export MIN_MESSAGE_SIZE=130Kb
export MAX_MESSAGE_SIZE=149Kb
docker compose up -d

docker run -d --name sonda4 --network host -l sonda \
  --env-file ../sonda/perf-test.env -e QUERY_DELAY=0.05 local-perf-sonda
docker run -d --name sonda5 --network host -l sonda \
  --env-file ../sonda/perf-test.env -e QUERY_DELAY=0.05 local-perf-sonda

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[scenario_6_store_stress] Phase 3: LPT 10/10, 130–149KB; Sonda total x5 (0.5s + 0.1s + 0.05s) — $current_time"
sleep 120

# ============================================================================ #
# PHASE 4: Store-only 
# Stop LPT; keep all Sonda x5 times
# ============================================================================ #
docker compose down -v

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[scenario_6_store_stress] Phase 4: LPT down; Store-only flood via Sonda x5 — $current_time"
sleep 120

# -------------------- Cleanup -------------------------------------------------
docker rm -f sonda1 sonda2 sonda3 sonda4 sonda5 >/dev/null 2>&1 || true

cd ..

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[scenario_6_store_stress] Test finished at $current_time"

# finish
# exec ./stop_test.sh
