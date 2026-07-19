#!/bin/bash
# Stress Filter with high receiver  (subscribe/unsubscribe) while publishing continuously.
set -e

STORE_NODES="/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n"
RELAY_NODE_REST_ADDRESS="http://127.0.0.1:8645"
STORE_NODE_REST_ADDRESS="http://127.0.0.1:8644"
PUBSUB_TOPIC="/waku/2/default-waku/proto"
CONTENT_TOPIC="/sonda/2/polls/proto"
PHASE_SLEEP=120

echo "Running test..."
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Bringing up simulator at $current_time"

cd ./waku-simulator
export SERVICENODE_CPU_CORES=0
export POSTGRES_CPU_CORES=1-3
export GF_SECURITY_ADMIN_USER=admin
export GF_SECURITY_ADMIN_PASSWORD=admin
docker compose up -d
while [ "$(docker inspect --format "{{.State.Status}}" $(docker compose ps -q servicenode))" != "running" ]; do
  sleep 1
done
cd ..

cd ./sonda
docker build -t local-perf-sonda -f ./Dockerfile.sonda .
cat > ./perf-test.env <<EOF
RELAY_NODE_REST_ADDRESS=${RELAY_NODE_REST_ADDRESS}
STORE_NODE_REST_ADDRESS=${STORE_NODE_REST_ADDRESS}
STORE_NODES=${STORE_NODES}
QUERY_DELAY=0.5
CLUSTER_ID=66
SHARD=0
HEALTH_THRESHOLD=0.9
PUBSUB_TOPIC=${PUBSUB_TOPIC}
CONTENT_TOPIC=${CONTENT_TOPIC}
EOF
docker run --env-file ./perf-test.env -l sonda -d --network host local-perf-sonda
cd ..

cd ./lpt
export LPT_IMAGE=harbor.status.im/wakuorg/liteprotocoltester:latest
export START_PUBLISHING_AFTER=15
export NUM_PUBLISHER_NODES=12
export NUM_RECEIVER_NODES=30
export MESSAGE_MIN_BYTES=2048
export MESSAGE_MAX_BYTES=32768
export LIGHTPUSH_INTERVAL_MS=80
docker compose up -d
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Phase 1: up recv, 12 pub / 30 recv (80ms, 2–32KB) $current_time"
sleep ${PHASE_SLEEP}

docker compose down receivernode
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Phase 2: down recv, publishers + sonda $current_time"
sleep ${PHASE_SLEEP}

docker compose up -d receivernode
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Phase 3: up recv again $current_time"
sleep ${PHASE_SLEEP}

docker compose down receivernode
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Phase 4: down recv again $current_time"
sleep ${PHASE_SLEEP}

docker compose up -d receivernode
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Phase 5: up recv final $current_time"
sleep ${PHASE_SLEEP}

docker compose down
cd ..
current_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Scenario 3 finished at $current_time"
