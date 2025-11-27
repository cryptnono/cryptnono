#!/usr/bin/env python3
# Heavily influenced by https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py

import math
import os
import signal
from enum import Enum
from functools import partial
from glob import glob
from ipaddress import IPv4Address, IPv6Address
from logging import DEBUG, INFO
from pathlib import Path
from socket import AF_INET6, inet_ntop
from struct import pack

import structlog
from bcc import BPF
from cachetools import TTLCache, cached
from lookup_container import (
    ContainerNotFound,
    ContainerType,
    get_container_id,
    lookup_container_details_crictl,
    lookup_container_details_docker,
)
from prometheus_client import Counter, Histogram, start_http_server
from psutil import NoSuchProcess, Process
from traitlets import Bool, Dict, Integer, List, Unicode
from traitlets.config import Application


class KillReason(Enum):
    """
    Why was this process killed
    """

    BANNED_IP = "banned-ip"
    SCAN = "scan"


# Optionally override this in development to avoid polluting real metrics
cryptnono_metrics_prefix = os.getenv("CRYPTNONO_METRICS_PREFIX", "cryptnono")

connects_checked = Counter(
    f"{cryptnono_metrics_prefix}_flowkiller_connects_checked_total",
    "Total number of connections checked",
)
processes_killed = Counter(
    f"{cryptnono_metrics_prefix}_flowkiller_processes_killed_total",
    "Total number of processes killed",
    ["reason"],
)
processes_missed = Counter(
    f"{cryptnono_metrics_prefix}_flowkiller_processes_missed_total",
    "Total number of processes that independently exited whilst being processed",
    ["reason"],
)

log_and_kill_histogram = Histogram(
    f"{cryptnono_metrics_prefix}_flowkiller_log_and_kill_execution_seconds",
    "Time spent executing log_and_kill function (seconds)",
)


class FlowKiller(Application):

    config_file = Unicode("", help="Configuration file").tag(config=True)

    debug = Bool(
        False,
        config=True,
        help="""
        Enable debug logging
        """,
    )

    banned_ipv4_file_globs = List(
        Unicode(),
        default_value=[],
        help=(
            "Directory/file globs of files containing a list of banned IPv4 "
            "addresses, one per line. E.g. /ban-config/*.txt"
        ),
    ).tag(config=True)

    log_connects = Bool(
        False,
        config=True,
        help="""
        Log all connects, not just kills
        """,
    )

    log_container_info = Bool(
        True,
        config=True,
        help="""
        Determine and log information about the container killed process was part of
        """,
    )

    lookback_duration_seconds = Integer(
        30,
        config=True,
        help="""
        Number of seconds to 'look back' when determining if a process should be killed.

        If a process makes more than unique_destination_threshold outgoing TCP connections in the
        last lookback_duration_seconds, it's determined to be a network scan and killed.
        """,
    )

    # Currently metrics are served on any path under / since this is what
    # start_http_server does by default, but we may want to change
    # this in the future so only /metrics is supported
    metrics_port = Integer(
        0,
        config=True,
        help="Serve prometheus metrics on this port under /metrics, set to 0 to disable",
    )

    unique_destinations_threshold = Integer(
        15,
        config=True,
        help="""
        Number of unique outgoing destinations (ip, port) a process is allowed before it's killed.

        If a process makes more than unique_destination_threshold outgoing TCP connections in the
        last lookback_duration_seconds, it's determined to be a network scan and killed.
        """,
    )

    aliases = Dict({"config": "FlowKiller.config_file"})

    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)

        if self.config_file:
            self.load_config_file(self.config_file)

        # Lazily initialised with configuration on first use
        self.log = structlog.get_logger()

        # We remember processes for the last hour, no matter how many processes we have
        # FIXME: Watch for processes dying and clean this up to reduce our memory use
        self.pid_connections = TTLCache(maxsize=math.inf, ttl=60 * 60)

        self.recently_killed = TTLCache(maxsize=1024, ttl=60 * 60)

        # https://www.structlog.org/en/stable/standard-library.html
        # https://www.structlog.org/en/stable/performance.html
        structlog.configure(
            cache_logger_on_first_use=True,
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.dict_tracebacks,
                structlog.processors.ExceptionRenderer(),
                structlog.processors.JSONRenderer(),
            ],
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            wrapper_class=structlog.make_filtering_bound_logger(
                DEBUG if self.debug else INFO
            ),
        )

        # Initialise prometheus counters with known labels to 0 so they
        # show up straight away instead of only after the counter is first
        # incremented
        for reason in KillReason:
            for counter in [processes_killed, processes_missed]:
                counter.labels(reason=reason.value)

        self.banned_ipv4 = set()
        for file_glob in self.banned_ipv4_file_globs:
            for banned_ipv4_file in glob(file_glob):
                with open(banned_ipv4_file) as f:
                    for ip in f.read().splitlines():
                        ip = ip.strip()
                        if ip and not ip.startswith("#"):
                            self.banned_ipv4.add(ip)

        self.log.info(f"Banning {len(self.banned_ipv4)} IPv4 addresses")

    # Cache only for an hour, pid reuse should not be an issue here
    @cached(cache=TTLCache(1024, 60 * 60))
    def get_container_info(self, pid):
        try:
            cid, cgroupline, container_type = get_container_id(pid)
        except ContainerNotFound as e:
            self.log.info(e, action="container-lookup-failed")
            cid = None
        if cid:
            try:
                if container_type == ContainerType.CRI:
                    container_info = lookup_container_details_crictl(cid)
                elif container_type == ContainerType.DOCKER:
                    container_info = lookup_container_details_docker(cid)
                else:
                    raise ValueError(f"Unknown container type {container_type}")

                return container_info
            except ContainerNotFound as e:
                self.log.info(
                    e, action="container-lookup-failed", cgroupline=cgroupline
                )
            except Exception as e:
                self.log.exception(e)
        return None

    @log_and_kill_histogram.time()
    def log_and_kill(
        self, pid: int, reason: KillReason, kill_log_kwargs: dict | None = None
    ):
        if kill_log_kwargs is None:
            kill_log_kwargs = {}
        if self.log_container_info:
            container_info = self.get_container_info(pid)
            if container_info:
                kill_log_kwargs["container"] = container_info

        try:
            proc = Process(pid)
            with proc.oneshot():
                kill_log_kwargs["cmdline"] = proc.cmdline()
                kill_log_kwargs["connections"] = proc.connections()
        except NoSuchProcess:
            # FIXME: Make a note here? But should be caught by the missed-kill later
            pass
        try:
            os.kill(pid, signal.SIGKILL)
            self.log.info("Killed process", pid=pid, action="killed", **kill_log_kwargs)
            self.recently_killed[pid] = True
            processes_killed.labels(reason=reason.value).inc()
        except ProcessLookupError:
            self.log.info(
                "Process exited before we could kill it",
                pid=pid,
                action="missed-kill",
                **kill_log_kwargs,
            )
            processes_missed.labels(reason=reason.value).inc()

    def handle_connection(
        self,
        pid: int,
        saddr: IPv4Address | IPv6Address,
        sport: int,
        daddr: IPv4Address | IPv6Address,
        dport: int,
    ):
        """
        Handle a successful outgoing network connection for a particular process
        """
        connects_checked.inc()

        if str(daddr) in self.banned_ipv4:
            self.log_and_kill(pid, KillReason.BANNED_IP, {"banned-ip": str(daddr)})
            return

        # Filter out all traffic to private IPs
        # In the future, possibly optimize this by doing this check in ebpf
        if daddr.is_private:
            return
        if pid in self.recently_killed:
            return

        process_connections: TTLCache = self.pid_connections.setdefault(
            pid, TTLCache(math.inf, 60)
        )

        key = f"{daddr}:{dport}"
        process_connections[key] = process_connections.get(key, 0) + 1

        if self.log_connects:
            log_params = {
                "pid": pid,
                "action": "connect",
                "addresses": dict(process_connections),
            }
            if self.log_container_info:
                container = self.get_container_info(pid)
                if container:
                    log_params["container"] = container
            self.log.info("Connection established", **log_params)

        if len(process_connections) > self.unique_destinations_threshold:
            self.log_and_kill(
                pid, KillReason.SCAN, {"addresses": dict(process_connections)}
            )
            # Stop storing info about this pid now that we're done
            del self.pid_connections[pid]

    def handle_event(self, event_name: str, b: BPF, cpu, data, size):
        """
        Handle successful tcp connect events from ebpf
        """
        event = b[event_name].event(data)
        if event_name == "ipv4_events":
            saddr = IPv4Address(pack("I", event.saddr))
            daddr = IPv4Address(pack("I", event.daddr))
        elif event_name == "ipv6_events":
            saddr = IPv6Address(inet_ntop(AF_INET6, event.saddr))
            daddr = IPv6Address(inet_ntop(AF_INET6, event.daddr))
        self.handle_connection(event.pid, saddr, event.lport, daddr, event.dport)

    def start(self):
        self.log.info("Compiling and loading BPF program...")
        bpf_text = (Path(__file__).parent / "flowkiller.bpf.c").read_text()
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
        b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
        b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

        b["ipv4_events"].open_perf_buffer(partial(self.handle_event, "ipv4_events", b))
        b["ipv6_events"].open_perf_buffer(partial(self.handle_event, "ipv6_events", b))

        if self.metrics_port:
            start_http_server(self.metrics_port)

        self.log.info("Watching for processes we don't like...")
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()


if __name__ == "__main__":
    app = FlowKiller()
    app.initialize()
    app.start()
