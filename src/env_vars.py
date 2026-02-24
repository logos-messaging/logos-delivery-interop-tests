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
DEFAULT_NWAKU = "harbor.status.im/wakuorg/nwaku:v0.38.0-rc.0"
STRESS_ENABLED = False
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

# example for .env file
# RLN_CREDENTIALS = {"rln-relay-cred-password": "password", "rln-relay-eth-client-address": "wss://sepolia.infura.io/ws/v3/api_key",  "rln-relay-eth-contract-address": "0xF471d71E9b1455bBF4b85d475afb9BB0954A29c4",  "rln-relay-eth-private-key-1": "1111111111111111111111111111111111111111111111111111111111111111",  "rln-relay-eth-private-key-2": "1111111111111111111111111111111111111111111111111111111111111111"}
