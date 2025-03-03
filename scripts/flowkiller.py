#!/usr/bin/env python
# Heavily influenced by https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py

import math
import os
import signal
from functools import partial
from ipaddress import IPv4Address, IPv6Address
from logging import DEBUG, INFO
from pathlib import Path
from socket import AF_INET6, inet_ntop
from struct import pack

import structlog
from bcc import BPF
from cachetools import TTLCache
from lookup_container import (
    ContainerNotFound,
    ContainerType,
    get_container_id,
    lookup_container_details_crictl,
    lookup_container_details_docker,
)
from traitlets import Bool, Integer
from traitlets.config import Application


class FlowKiller(Application):

    debug = Bool(
        False,
        config=True,
        help="""
        Turn on debug logging.

        Logs all completed TCP connections, not just kills.
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
        60,
        config=True,
        help="""
        Number of seconds to 'look back' when determining if a process should be killed.

        If a process makes more than unique_destination_threshold outgoing TCP connections in the
        last lookback_duration_seconds, it's determined to be a network scan and killed.
        """,
    )

    unique_destinations_threshold = Integer(
        100,
        config=True,
        help="""
        Number of unique outgoing destinations (ip, port) a process is allowed before it's killed.

        If a process makes more than unique_destination_threshold outgoing TCP connections in the
        last lookback_duration_seconds, it's determined to be a network scan and killed.
        """,
    )

    def initialize(self, *args, **kwargs):
        super().initialize(*args, **kwargs)

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

    def log_and_kill(self, pid: int, kill_log_kwargs: dict | None = None):
        if kill_log_kwargs is None:
            kill_log_kwargs = {}
        if self.log_container_info:
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

                    kill_log_kwargs["container"] = container_info
                except ContainerNotFound as e:
                    self.log.info(
                        e, action="container-lookup-failed", cgroupline=cgroupline
                    )
                except Exception as e:
                    self.log.exception(e)

        try:
            os.kill(pid, signal.SIGKILL)
            self.log.info("Killed process", pid=pid, action="killed", **kill_log_kwargs)
            self.recently_killed[pid] = True
        except ProcessLookupError:
            self.log.info(
                "Process exited before we could kill it",
                pid=pid,
                action="missed-kill",
                **kill_log_kwargs,
            )

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

        self.log.debug(
            "Connection established",
            pid=pid,
            action="connect",
            addresses=dict(process_connections),
        )

        if len(process_connections) > self.unique_destinations_threshold:
            self.log_and_kill(pid, {"addresses": dict(process_connections)})
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
