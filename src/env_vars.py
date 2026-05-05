import os
from dotenv import load_dotenv

load_dotenv()  # This will load environment variables from a .env file if it exists


def get_env_var(var_name, default=None):
    env_var = os.getenv(var_name, default)
    if env_var in [None, ""]:
        print(f"{var_name} is not set; using default value: {default}")
        env_var = default
    print(f"{var_name}: {env_var}")
    return env_var


# Configuration constants. Need to be upercase to appear in reports
DEFAULT_NWAKU = "wakuorg/nwaku:v0.38.0"
STRESS_ENABLED = False
USE_WRAPPERS = True
NODE_1 = get_env_var("NODE_1", DEFAULT_NWAKU)
NODE_2 = get_env_var("NODE_2", DEFAULT_NWAKU)
ADDITIONAL_NODES = get_env_var("ADDITIONAL_NODES", f"{DEFAULT_NWAKU},{DEFAULT_NWAKU},{DEFAULT_NWAKU}")
# more nodes need to follow the NODE_X pattern
DOCKER_LOG_DIR = get_env_var("DOCKER_LOG_DIR", "./log/docker")
NETWORK_NAME = get_env_var("NETWORK_NAME", "waku")
SUBNET = get_env_var("SUBNET", "172.18.0.0/16")
IP_RANGE = get_env_var("IP_RANGE", "172.18.0.0/24")
GATEWAY = get_env_var("GATEWAY", "172.18.0.1")
RUNNING_IN_CI = get_env_var("CI")
API_REQUEST_TIMEOUT = get_env_var("API_REQUEST_TIMEOUT", 20)
RLN_CREDENTIALS = get_env_var("RLN_CREDENTIALS")
PG_USER = get_env_var("POSTGRES_USER", "postgres")
PG_PASS = get_env_var("POSTGRES_PASSWORD", "test123")

FLEET_NODES = [
    # Amsterdam
    "/dns4/node-01.do-ams3.waku.test.status.im/tcp/30303/p2p/16Uiu2HAkykgaECHswi3YKJ5dMLbq2kPVCo89fcyTd38UcQD6ej5W",
    # US Central
    "/dns4/node-01.gc-us-central1-a.waku.test.status.im/tcp/30303/p2p/16Uiu2HAmDCp8XJ9z1ev18zuv8NHekAsjNyezAvmMfFEJkiharitG",
    # Hong Kong
    "/dns4/node-01.ac-cn-hongkong-c.waku.test.status.im/tcp/30303/p2p/16Uiu2HAkzHaTP5JsUwfR9NR8Rj9HC24puS6ocaU8wze4QrXr9iXp",
]
FLEET_PRIMARY_MULTIADDR = FLEET_NODES[0]
FLEET_DNS_DISCOVERY_URL = "enrtree://AOGYWMBYOUIMOENHXCHILPKY3ZRFEULMFI4DOM442QSZ73TT2A7VI@test.waku.nodes.status.im"

FLEET_N1_MULTIADDR = FLEET_NODES[0]  # node-01.do-ams3 – used by NODE1 in --fleet mode
FLEET_N2_MULTIADDR = FLEET_NODES[1]  # node-01.gc-us-central1-a – used by NODE2 in --fleet mode

# example for .env file
# RLN_CREDENTIALS = {"rln-relay-cred-password": "password", "rln-relay-eth-client-address": "https://rpc.sepolia.linea.build",  "rln-relay-eth-contract-address": "0xB9cd878C90E49F797B4431fBF4fb333108CB90e6",  "rln-relay-eth-private-key-1": "",  "rln-relay-eth-private-key-2": "", "rln-relay-eth-private-key-3": "", "rln-relay-eth-private-key-4": "", "rln-relay-eth-private-key-5": ""}
