#!/bin/bash
set -e

export SCENARIO_ID="cpu_store_stress"
export TEST_NAME="${SCENARIO_ID}_$(date +%Y%m%d_%H%M%S)"
echo "[${TEST_NAME}] start"

export GF_SECURITY_ADMIN_USER="admin"
export GF_SECURITY_ADMIN_PASSWORD="admin"
export NODEKEY="${NODEKEY:-}"
export STORAGE_SIZE="${STORAGE_SIZE:-}"

export NWAKU_IMAGE="wakuorg/nwaku:latest"
export NUM_NWAKU_NODES=15
export RLN_ENABLED=false

# Service node 
export SERVICENODE_METRICS_PORT=8008
export SERVICENODE_HTTP_PORT=8644
export SERVICENODE_REST_PORT=8645

export POSTGRES_EXPORTER_PORT=9187
export PROMETHEUS_PORT=9090
export GRAFANA_PORT=3001

export SERVICENODE_CPU_CORES="0-1"
export SERVICENODE_MEM_LIMIT=512m
export POSTGRES_CPU_CORES="0-3"
export POSTGRES_MEM_LIMIT=2g
export POSTGRES_SHM=1g

export LPT_IMAGE="harbor.status.im/wakuorg/liteprotocoltester:latest"

# Topic / shard 
export CLUSTER_ID=66
export SHARD=0
export PUBSUB_TOPIC="/waku/2/rs/${CLUSTER_ID}/${SHARD}"

export RELAY_NODE_REST_ADDRESS="http://127.0.0.1:${SERVICENODE_REST_PORT}"
export STORE_NODE_REST_ADDRESS="http://127.0.0.1:${SERVICENODE_HTTP_PORT}"

# Phase 0 — bring up simulator
echo "[${TEST_NAME}] Phase 0: bring up simulator"
cd ./waku-simulator
docker compose up -d
cd ..
echo "[${TEST_NAME}] wait 30s"
sleep 30

# =========================
# Phase 1 — CPU-heavy writers (small msgs, high rate)
# =========================
export NUM_PUBLISHER_NODES=24
export NUM_RECEIVER_NODES=8
export MESSAGE_INTERVAL_MILLIS=10
export MIN_MESSAGE_SIZE=256
export MAX_MESSAGE_SIZE=1024
export START_PUBLISHING_AFTER=10
export NUM_MESSAGES=0

echo "[${TEST_NAME}] Phase 1: start writers"
docker run -d --rm --name lpt_cpu \
  -e PUB_NODES=${NUM_PUBLISHER_NODES} \
  -e RCV_NODES=${NUM_RECEIVER_NODES} \
  -e MSG_INTERVAL_MS=${MESSAGE_INTERVAL_MILLIS} \
  -e MIN_MSG=${MIN_MESSAGE_SIZE} \
  -e MAX_MSG=${MAX_MESSAGE_SIZE} \
  -e PUBSUB_TOPIC=${PUBSUB_TOPIC} \
  --network host ${LPT_IMAGE}

# =========================
# Phase 2 
# =========================
echo "[${TEST_NAME}] Phase 2: build and start Sonda"
cd ./sonda
docker build -t local-perf-sonda -f ./Dockerfile.sonda .

cat <<EOF > perf-test.env
RELAY_NODE_REST_ADDRESS=${RELAY_NODE_REST_ADDRESS}
STORE_NODE_REST_ADDRESS=${STORE_NODE_REST_ADDRESS}
QUERY_DELAY=0.5
STORE_NODES=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
CLUSTER_ID=${CLUSTER_ID}
SHARD=${SHARD}
PUBSUB_TOPIC=/waku/2/rs/${CLUSTER_ID}/${SHARD}
EOF

docker run --env-file perf-test.env -l sonda -d --network host local-perf-sonda
cd ..

echo "[${TEST_NAME}] hold 240s"
sleep 240

# =========================
# Phase 3 — recovery
# =========================
echo "[${TEST_NAME}] Phase 3: stop writers; observe 120s"
docker kill lpt_cpu || true
sleep 120

# =========================
# Cleanup
# =========================
echo "[${TEST_NAME}] cleanup"
docker kill $(docker ps -q --filter "label=sonda") || true
cd ./waku-simulator
docker compose down -v
