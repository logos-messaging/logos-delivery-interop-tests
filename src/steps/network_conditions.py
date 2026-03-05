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

    def _setup_prio_root(self, node, iface: str = "eth0"):
        self.clear(node, iface=iface)
        self._exec(
            node,
            [
                "qdisc",
                "add",
                "dev",
                iface,
                "root",
                "handle",
                "1:",
                "prio",
                "bands",
                "3",
                "priomap",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
                "1",
            ],
            iface=iface,
        )

    def _attach_netem_default_band(self, node, netem_args: list[str], iface: str = "eth0"):
        self._exec(
            node,
            ["qdisc", "replace", "dev", iface, "parent", "1:1", "handle", "10:", "netem"] + netem_args,
            iface=iface,
        )

    def _exempt_tcp_sport(self, node, port: int, band: int = 2, iface: str = "eth0"):
        self._exec(
            node,
            [
                "filter",
                "add",
                "dev",
                iface,
                "protocol",
                "ip",
                "parent",
                "1:",
                "prio",
                "1",
                "u32",
                "match",
                "ip",
                "protocol",
                "6",
                "0xff",
                "match",
                "ip",
                "sport",
                str(int(port)),
                "0xffff",
                "flowid",
                f"1:{int(band)}",
            ],
            iface=iface,
        )

    def _apply_netem_except_control_plane(
        self,
        node,
        netem_args: list[str],
        rest_port: int,
        metrics_port: int | None = None,
        iface: str = "eth0",
    ):
        self._setup_prio_root(node, iface=iface)
        self._attach_netem_default_band(node, netem_args, iface=iface)
        self._exempt_tcp_sport(node, rest_port, band=2, iface=iface)
        if metrics_port is not None:
            self._exempt_tcp_sport(node, metrics_port, band=2, iface=iface)
        self.log_tc_stats(node, iface=iface)

    def add_latency_except_rest(
        self,
        node,
        ms: int,
        rest_port: int,
        metrics_port: int | None = None,
        iface: str = "eth0",
    ):
        self._apply_netem_except_control_plane(
            node,
            netem_args=["delay", f"{int(ms)}ms"],
            rest_port=rest_port,
            metrics_port=metrics_port,
            iface=iface,
        )

    def add_packet_loss_except_rest(
        self,
        node,
        percent: float,
        rest_port: int,
        metrics_port: int | None = None,
        iface: str = "eth0",
    ):
        self._apply_netem_except_control_plane(
            node,
            netem_args=["loss", f"{float(percent)}%"],
            rest_port=rest_port,
            metrics_port=metrics_port,
            iface=iface,
        )

    def add_packet_loss_correlated_except_rest(
        self,
        node,
        percent: float,
        correlation: float,
        rest_port: int,
        metrics_port: int | None = None,
        iface: str = "eth0",
    ):
        self._apply_netem_except_control_plane(
            node,
            netem_args=["loss", f"{float(percent)}%", f"{float(correlation)}%"],
            rest_port=rest_port,
            metrics_port=metrics_port,
            iface=iface,
        )

    def add_packet_reordering_except_rest(
        self,
        node,
        rest_port: int,
        metrics_port: int | None = None,
        percent: int = 25,
        correlation: int = 50,
        delay_ms: int = 10,
        iface: str = "eth0",
    ):
        self._apply_netem_except_control_plane(
            node,
            netem_args=["delay", f"{int(delay_ms)}ms", "reorder", f"{int(percent)}%", f"{int(correlation)}%"],
            rest_port=rest_port,
            metrics_port=metrics_port,
            iface=iface,
        )

    def add_bandwidth_except_rest(
        self,
        node,
        rate: str,
        rest_port: int,
        metrics_port: int | None = None,
        iface: str = "eth0",
    ):
        self._setup_prio_root(node, iface=iface)
        self._exec(
            node,
            [
                "qdisc",
                "replace",
                "dev",
                iface,
                "parent",
                "1:1",
                "handle",
                "20:",
                "tbf",
                "rate",
                rate,
                "burst",
                "32kbit",
                "limit",
                "12500",
            ],
            iface=iface,
        )
        self._exempt_tcp_sport(node, rest_port, band=2, iface=iface)
        if metrics_port is not None:
            self._exempt_tcp_sport(node, metrics_port, band=2, iface=iface)
        self.log_tc_stats(node, iface=iface)
