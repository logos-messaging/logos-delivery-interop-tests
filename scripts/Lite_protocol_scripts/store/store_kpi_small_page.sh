#!/bin/bash
set -e



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
while true; do
  sid="$(docker compose ps -q servicenode || true)"
  if [[ -n "$sid" ]]; then
    state="$(docker inspect --format '{{.State.Status}}' "$sid" 2>/dev/null || true)"
    [[ "$state" == "running" ]] && break
  fi
  sleep 1
done

cd ..

export RELAY_NODE_REST_ADDRESS=http://127.0.0.1:8645
export STORE_NODE_REST_ADDRESS=http://127.0.0.1:8644
export STORE_NODES=/ip4/10.2.0.101/tcp/60001/p2p/16Uiu2HAkyte8uj451tGkbww4Mjcg6DRnmAHxNeWyF4zp23RbpG3n
export QUERY_DELAY=0.5
export CLUSTER_ID=66
export SHARD=0
export PUBSUB=/waku/2/rs/66/0
export CONTENT_TOPIC=/tester/2/light-pubsub-test/wakusim

cd ./sonda
docker build -t local-perf-sonda -f ./Dockerfile.sonda .

cat <<EOF > perf-test.env
RELAY_NODE_REST_ADDRESS=${RELAY_NODE_REST_ADDRESS}
STORE_NODE_REST_ADDRESS=${STORE_NODE_REST_ADDRESS}
QUERY_DELAY=${QUERY_DELAY}
STORE_NODES=${STORE_NODES}
CLUSTER_ID=${CLUSTER_ID}
SHARD=${SHARD}
EOF

sleep 5
docker rm -f sonda >/dev/null 2>&1 || true
docker run --env-file ./perf-test.env -l sonda -d --network host local-perf-sonda
cd ..

echo "[store_kpi_smallpage] warmup 60s to build history…"
sleep 60

URL="${STORE_NODE_REST_ADDRESS}/store/v3/messages"
PEERADDR="${STORE_NODES%%,*}"   # fixed to first entry

burst_once() {
  local now start
  now=$(( $(date +%s) * 1000 ))
  start=$(( now - 600 * 1000 ))   # 10-minute window
  local par=20
  echo "[burst-smallpage] 10m window, ${par} parallel → ${URL}"
  for i in $(seq 1 $par); do
    curl -s --get "$URL" \
      --data-urlencode "peerAddr=$PEERADDR" \
      --data-urlencode "pubsubTopic=$PUBSUB" \
      --data-urlencode "contentTopics=$CONTENT_TOPIC" \
      --data-urlencode "includeData=true" \
      --data-urlencode "pageSize=5" \
      --data-urlencode "startTime=$start" \
      > /dev/null &
  done
  wait
}

# run bursts for a full 10 minutes
RUN_MINUTES=10
END_TS=$(( $(date +%s) + RUN_MINUTES*60 ))
iter=0
echo "[store_kpi_smallpage] querying for ${RUN_MINUTES} minutes…"
while (( $(date +%s) < END_TS )); do
  iter=$((iter+1))
  burst_once
  echo "[burst-smallpage] iter=$iter done; sleeping 10s"
  sleep 10
done

