#!/bin/bash
set -e

# ID
export SCENARIO_ID="cpu_store_stress"
export TEST_NAME="${SCENARIO_ID}_$(date +%Y%m%d_%H%M%S)"
echo "[${TEST_NAME}] start"

# Images (pin for comparability)
export NWAKU_IMAGE="wakuorg/nwaku:stable"
export LPT_IMAGE="wakuorg/liteprotocoltester:latest"
export SONDA_IMAGE="wakuorg/sonda:latest"   

# Service/DB resources (CPU bottleneck on service)
export SERVICENODE_CPU_CORES=0       
export POSTGRES_CPU_CORES=1-3
export SERVICE_MEM_LIMIT="2g"
export POSTGRES_MEM_LIMIT="2g"
export POSTGRES_SHM_SIZE="1g"

# Topic/shards
export CLUSTER_ID=66
export SHARD=0
export PUBSUB_TOPIC="/waku/2/rs/${CLUSTER_ID}/${SHARD}"
export CONTENT_TOPIC="/sonda/2/polls/proto"

# REST endpoints
export RELAY_NODE_REST_ADDRESS="http://127.0.0.1:8645"
export STORE_NODE_REST_ADDRESS="http://127.0.0.1:8644"
export STORE_NODES="/ip4/127.0.0.1/tcp/30303/p2p/SERVICE_PEER_ID"

# Health
export HEALTH_THRESHOLD=0.85

# ---------- Phase 0: up ----------
echo "[${TEST_NAME}] up simulator"
cd ./waku-simulator
docker compose up -d
cd ..
echo "[${TEST_NAME}] wait 30s"
sleep 30

# ---------- Phase 1: CPU write hammer (small msgs, high rate) ----------
# Small payloads + high publisher count => per-message CPU (encode/verify/route) dominates.
export NUM_PUBLISHER_NODES=24
export NUM_RECEIVER_NODES=8           
export MESSAGE_INTERVAL_MILLIS=8      
export MIN_MESSAGE_SIZE=256           
export MAX_MESSAGE_SIZE=1024         
export START_PUBLISHING_AFTER=10
export NUM_MESSAGES=0                 

echo "[${TEST_NAME}] phase1 writers: ${NUM_PUBLISHER_NODES} pubs @ ${MESSAGE_INTERVAL_MILLIS}ms, 256-1024B"
docker run -d --rm --name lpt_cpu \
  -e PUB_NODES=${NUM_PUBLISHER_NODES} \
  -e RCV_NODES=${NUM_RECEIVER_NODES} \
  -e MSG_INTERVAL_MS=${MESSAGE_INTERVAL_MILLIS} \
  -e MIN_MSG=${MIN_MESSAGE_SIZE} \
  -e MAX_MSG=${MAX_MESSAGE_SIZE} \
  -e PUBSUB_TOPIC=${PUBSUB_TOPIC} \
  --network host ${LPT_IMAGE}

# ---------- Phase 2: Store read hammer (concurrent readers) ----------
# Mix includeData true/false and page sizes to exercise CPU (serialization/JSON) & DB.
echo "[${TEST_NAME}] phase2 store readers"
docker run -d --rm --name sonda_idx \
  --network host ${SONDA_IMAGE} \
  --relay-node-rest-address "${RELAY_NODE_REST_ADDRESS}" \
  --store-node-rest-address "${STORE_NODE_REST_ADDRESS}" \
  --pubsub-topic "${PUBSUB_TOPIC}" \
  --store-nodes "${STORE_NODES}" \
  --delay-seconds 0.07 --health-threshold ${HEALTH_THRESHOLD} \
  --metrics-port 8004 --include-data=false --page-size 150

docker run -d --rm --name sonda_smallpages \
  --network host ${SONDA_IMAGE} \
  --relay-node-rest-address "${RELAY_NODE_REST_ADDRESS}" \
  --store-node-rest-address "${STORE_NODE_REST_ADDRESS}" \
  --pubsub-topic "${PUBSUB_TOPIC}" \
  --store-nodes "${STORE_NODES}" \
  --delay-seconds 0.05 --health-threshold ${HEALTH_THRESHOLD} \
  --metrics-port 8005 --include-data=true --page-size 5

docker run -d --rm --name sonda_bigpages \
  --network host ${SONDA_IMAGE} \
  --relay-node-rest-address "${RELAY_NODE_REST_ADDRESS}" \
  --store-node-rest-address "${STORE_NODE_REST_ADDRESS}" \
  --pubsub-topic "${PUBSUB_TOPIC}" \
  --store-nodes "${STORE_NODES}" \
  --delay-seconds 0.05 --health-threshold ${HEALTH_THRESHOLD} \
  --metrics-port 8006 --include-data=true --page-size 50

# Extra readers to push CPU on the service process:
docker run -d --rm --name sonda_mix1 \
  --network host ${SONDA_IMAGE} \
  --relay-node-rest-address "${RELAY_NODE_REST_ADDRESS}" \
  --store-node-rest-address "${STORE_NODE_REST_ADDRESS}" \
  --pubsub-topic "${PUBSUB_TOPIC}" \
  --store-nodes "${STORE_NODES}" \
  --delay-seconds 0.03 --health-threshold ${HEALTH_THRESHOLD} \
  --metrics-port 8007 --include-data=true --page-size 25

docker run -d --rm --name sonda_mix2 \
  --network host ${SONDA_IMAGE} \
  --relay-node-rest-address "${RELAY_NODE_REST_ADDRESS}" \
  --store-node-rest-address "${STORE_NODE_REST_ADDRESS}" \
  --pubsub-topic "${PUBSUB_TOPIC}" \
  --store-nodes "${STORE_NODES}" \
  --delay-seconds 0.03 --health-threshold ${HEALTH_THRESHOLD} \
  --metrics-port 8008 --include-data=false --page-size 200

echo "[${TEST_NAME}] hold 12m"
sleep 720

# ---------- Phase 3: plateau & recovery ----------
echo "[${TEST_NAME}] phase3 stop writers; keep readers 2m (recovery CPU/GC)"
docker kill lpt_cpu || true
sleep 120

# ---------- Cleanup ----------
echo "[${TEST_NAME}] cleanup"
docker kill sonda_idx sonda_smallpages sonda_bigpages sonda_mix1 sonda_mix2 || true
cd ./waku-simulator
docker compose down -v
