#!/bin/bash
set -e
if ! typeset -f wn >/dev/null 2>&1; then
  wn() { docker compose "$@"; }
fi
# - waku-simulator: 15-node network, 1 service, 1 edge
# - Service node limited by env below (CPU cores 0-3; memory 512 MiB)
# - Phases driven by LPT; Sonda runs throughout to exercise Store
# - This variant stresses CPU more and uses 120s observe windows

echo " Running test..."

# -------------------- Bring up simulator ------------------------
cd ./waku-simulator

export NWAKU_IMAGE=wakuorg/nwaku:latest
export NUM_NWAKU_NODES=15
export RLN_ENABLED=false

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

# -------------------- LPT common knobs (same exports) -------------------------
export LPT_IMAGE=harbor.status.im/wakuorg/liteprotocoltester:latest
export START_PUBLISHING_AFTER=15
export NUM_MESSAGES=0
export MESSAGE_INTERVAL_MILLIS=100

export MIN_MESSAGE_SIZE=120Kb
export MAX_MESSAGE_SIZE=145Kb

export LIGHTPUSH_SERVICE_PEER=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
export FILTER_SERVICE_PEER=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n

export PUBSUB=/waku/2/rs/66/0
export CONTENT_TOPIC=/tester/2/light-pubsub-test/wakusim
export CLUSTER_ID=66

# wait time  before starting traffic
sleep 60


# -------------------- Sonda (Store monitor) -----------------------------------
cd ../sonda

docker build -t local-perf-sonda -f ./Dockerfile.sonda .

# perf-test.env 
cat <<EOF > perf-test.env
RELAY_NODE_REST_ADDRESS=http://127.0.0.1:8645
STORE_NODE_REST_ADDRESS=http://127.0.0.1:8644
QUERY_DELAY=0.5
STORE_NODES=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
CLUSTER_ID=66
SHARD=0
EOF

sleep 5

docker rm -f sonda >/dev/null 2>&1 || true
docker run --env-file ./perf-test.env -l sonda -d --network host local-perf-sonda

cd ../lpt

# -------------------- Phase 1: 6 pub / 6 recv --------------------------------
export NUM_PUBLISHER_NODES=6
export NUM_RECEIVER_NODES=6
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] LPT is running with 6 publishers and 6 receivers + sonda from now: $current_time"

sleep 120

# -------------------- Phase 2: 3 pub / 12 recv -------------------------------
docker compose down -v
export NUM_PUBLISHER_NODES=3
export NUM_RECEIVER_NODES=12
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] LPT is running with 3 publishers and 12 receivers from now: $current_time"

sleep 120

# -------------------- Phase 3: 12 pub / 3 recv -------------------------------
docker compose down -v
export NUM_PUBLISHER_NODES=12
export NUM_RECEIVER_NODES=3
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] LPT is running with 12 publishers and 3 receivers from now: $current_time"

sleep 120

# -------------------- Phase 4: receivers down; keep publisher + sonda --------
docker compose down -v
export NUM_PUBLISHER_NODES=12
export NUM_RECEIVER_NODES=0
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] LPT receivers are down; sonda and lightpush publisher running from now: $current_time"

sleep 120

# -------------------- Phase 5: LPT down; only sonda --------------------------
docker compose down -v

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] LPT down; only sonda is working from now: $current_time"

sleep 120

# -------------------- Phase 6: final high-load burst  -----------------

export NUM_PUBLISHER_NODES=12
export NUM_RECEIVER_NODES=12
docker compose up -d

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] Final burst: LPT running with 12 publishers and 12 receivers from now: $current_time"

sleep 120

cd ..

current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "[test] Test finished at $current_time"

# finish
# exec ./stop_test.sh
