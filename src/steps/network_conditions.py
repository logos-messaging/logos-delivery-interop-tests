import subprocess
from src.libs.custom_logger import get_custom_logger

logger = get_custom_logger(__name__)


class TrafficController:
    def _pid(self, node) -> int:
        if not node.container:
            raise RuntimeError("Node container not started yet")

        node.container.reload()
        pid = node.container.attrs.get("State", {}).get("Pid")
        if not pid or pid == 0:
            raise RuntimeError("Container PID not available (container not running?)")
        return int(pid)

    def _exec(self, node, tc_args: list[str], iface: str = "eth0"):
        pid = self._pid(node)

        cmd = ["sudo", "-n", "nsenter", "-t", str(pid), "-n", "tc"] + tc_args
        logger.info(f"TC exec: {cmd}")

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"TC failed: {' '.join(cmd)}\n" f"stdout: {res.stdout}\n" f"stderr: {res.stderr}")

        return res.stdout

    def log_tc_stats(self, node, iface: str = "eth0"):
        """
        Log tc statistics for an interface (best-effort).
        Useful to confirm netem loss/delay counters (sent/dropped/etc.).
        """
        try:
            out = self._exec(node, ["-s", "qdisc", "show", "dev", iface], iface=iface)
            out = (out or "").strip()
            if out:
                logger.debug(f"tc -s qdisc show dev {iface}:\n{out}")
            else:
                logger.debug(f"tc -s qdisc show dev {iface}: (no output)")
        except Exception as e:
            logger.debug(f"Failed to read tc stats for {iface}: {e}")

    def clear(self, node, iface: str = "eth0"):
        try:
            self._exec(node, ["qdisc", "del", "dev", iface, "root"], iface=iface)
        except RuntimeError as e:
            msg = str(e)
            if "Cannot delete qdisc with handle of zero" in msg or "No such file or directory" in msg:
                return
            raise

    def add_latency(self, node, ms: int, iface: str = "eth0"):
        self.clear(node, iface=iface)
        self._exec(node, ["qdisc", "add", "dev", iface, "root", "netem", "delay", f"{ms}ms"], iface=iface)

    def add_packet_loss(self, node, percent: float, iface: str = "eth0"):
        self.clear(node, iface=iface)

        self._exec(
            node,
            ["qdisc", "add", "dev", iface, "root", "netem", "loss", f"{percent}%"],
            iface=iface,
        )
        try:
            stats = self._exec(node, ["-s", "qdisc", "show", "dev", iface], iface=iface)
            if stats is not None:
                if isinstance(stats, (bytes, bytearray)):
                    stats = stats.decode(errors="replace")
                logger.debug(f"tc -s qdisc show dev {iface}:\n{stats}")
            else:
                logger.debug(f"Executed: tc -s qdisc show dev {iface} (no output returned by _exec)")
        except Exception as e:
            logger.debug(f"Failed to read tc stats for {iface}: {e}")

    def add_bandwidth(self, node, rate: str, iface: str = "eth0"):
        self.clear(node, iface=iface)
        self._exec(
            node,
            ["qdisc", "add", "dev", iface, "root", "tbf", "rate", rate, "burst", "32kbit", "limit", "12500"],
            iface=iface,
        )

    def add_packet_loss_correlated(
        self,
        node,
        percent: float,
        correlation: float,
        iface: str = "eth0",
    ):
        self.clear(node, iface=iface)
        self._exec(
            node,
            [
                "qdisc",
                "add",
                "dev",
                iface,
                "root",
                "netem",
                "loss",
                f"{percent}%",
                f"{correlation}%",
            ],
            iface=iface,
        )

    def add_packet_reordering(
        self,
        node,
        percent: int = 25,
        correlation: int = 50,
        delay_ms: int = 10,
        iface: str = "eth0",
    ):
        self.clear(node, iface=iface)

        self._exec(
            node,
            [
                "qdisc",
                "add",
                "dev",
                iface,
                "root",
                "netem",
                "delay",
                f"{delay_ms}ms",
                "reorder",
                f"{percent}%",
                f"{correlation}%",
            ],
            iface=iface,
        )

    def _install_rest_bypass_prio(self, node, iface: str, netem_args: list[str]):
        """
        Build a prio qdisc where REST API traffic bypasses netem.

        Layout:
            root 1: prio (3 bands)
              |-- 1:1  unshaped (REST traffic lands here via u32 filter)
              |-- 1:2  leaf -> netem (default band per priomap; everything else)
              `-- 1:3  unshaped (unused)

        The filter matches packets whose TCP source OR destination port equals
        the node's REST port, so both incoming requests and outgoing responses
        bypass the netem queue. Libp2p and other traffic hits netem.
        """
        rest_port = str(node._rest_port)
        filter_prefix = f"filter add dev {iface} protocol ip parent 1: prio 1 u32 match ip"

        self._exec(node, f"qdisc add dev {iface} root handle 1: prio".split(), iface=iface)
        self._exec(node, f"qdisc add dev {iface} parent 1:2 handle 20: netem".split() + netem_args, iface=iface)
        self._exec(node, f"{filter_prefix} sport {rest_port} 0xffff flowid 1:1".split(), iface=iface)
        self._exec(node, f"{filter_prefix} dport {rest_port} 0xffff flowid 1:1".split(), iface=iface)

    def add_packet_loss_p2p_only(self, node, percent: float, iface: str = "eth0"):
        """
        Apply packet loss to all traffic EXCEPT the node's REST API port.

        Use this instead of add_packet_loss when measuring Waku protocol
        behavior under loss, to avoid contaminating the test harness's
        control plane (REST requests/responses between pytest and the node).
        """
        self.clear(node, iface=iface)
        self._install_rest_bypass_prio(node, iface, ["loss", f"{percent}%"])

    def add_packet_loss_correlated_p2p_only(
        self,
        node,
        percent: float,
        correlation: float,
        iface: str = "eth0",
    ):
        """
        Correlated packet loss variant that leaves REST API traffic untouched.
        See add_packet_loss_p2p_only for the rationale.
        """
        self.clear(node, iface=iface)
        self._install_rest_bypass_prio(node, iface, ["loss", f"{percent}%", f"{correlation}%"])
