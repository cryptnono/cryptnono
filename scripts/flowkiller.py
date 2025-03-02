#!/usr/bin/env python
# Heavily influenced by https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py

import argparse
import math
import os
import signal
import time
from functools import partial
from ipaddress import IPv4Address, IPv6Address, ip_address
from logging import DEBUG, INFO
from pathlib import Path
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

pid_connections = TTLCache(maxsize=math.inf, ttl=60 * 60)
cutoff = 10

# Lazily initialised with configuration on first use
log = structlog.get_logger()

recently_killed = TTLCache(maxsize=1024, ttl=60 * 60)


def log_and_kill(pid: int, lookup_container: bool, kill_log_kwargs: dict = None):
    if kill_log_kwargs is None:
        kill_log_kwargs = {}
    if lookup_container:
        try:
            cid, cgroupline, container_type = get_container_id(pid)
        except ContainerNotFound as e:
            log.info(e, action="container-lookup-failed")
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
                log.info(e, action="container-lookup-failed", cgroupline=cgroupline)
            except Exception as e:
                log.exception(e)

    try:
        os.kill(pid, signal.SIGKILL)
        log.info("Killed process", pid=pid, action="killed", **kill_log_kwargs)
        recently_killed[pid] = True
    except ProcessLookupError:
        log.info(
            "Process exited before we could kill it",
            pid=pid,
            action="missed-kill",
            **kill_log_kwargs,
        )


def handle_connection(
    pid: int,
    saddr: IPv4Address | IPv6Address,
    sport: int,
    daddr: IPv4Address | IPv6Address,
    dport: int,
    lookup_container: bool,
):
    """
    Handle a successful outgoing network connection for a particular process
    """
    # Filter out all traffic to private IPs
    # In the future, possibly optimize this by doing this check in ebpf
    if daddr.is_private:
        return
    if pid in recently_killed:
        return

    process_connections: TTLCache = pid_connections.setdefault(
        pid, TTLCache(math.inf, 60)
    )

    key = f"{daddr}:{dport}"
    process_connections[key] = process_connections.get(key, 0) + 1

    log.debug(
        "Connection established",
        pid=pid,
        action="connect",
        addresses=dict(process_connections),
    )

    if len(process_connections) > cutoff:
        log_and_kill(pid, lookup_container, {"addresses": dict(process_connections)})
        # Stop storing info about this pid now that we're done
        del pid_connections[pid]


def handle_event(event_name: str, b: BPF, lookup_container: bool, cpu, data, size):
    """
    Handle successful tcp connect events from ebpf
    """
    event = b[event_name].event(data)
    saddr = ip_address(pack("I", event.saddr))
    daddr = ip_address(pack("I", event.daddr))
    handle_connection(
        event.pid, saddr, event.lport, daddr, event.dport, lookup_container
    )


def main():
    start_time = time.perf_counter()
    parser = argparse.ArgumentParser(description="Kill processes based on tcp flows")
    parser.add_argument("--debug", action="store_true", help="Run with debug logging")
    parser.add_argument(
        "--lookup-container",
        action="store_true",
        help="Attempt to lookup the container details for a process before killing it",
    )
    args = parser.parse_args()

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
            DEBUG if args.debug else INFO
        ),
    )

    log.info("Compiling and loading BPF program...")
    bpf_text = (Path(__file__).parent / "flowkiller.bpf.c").read_text()
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

    b["ipv4_events"].open_perf_buffer(
        partial(handle_event, "ipv4_events", b, args.lookup_container)
    )
    b["ipv6_events"].open_perf_buffer(
        partial(handle_event, "ipv6_events", b, args.lookup_container)
    )

    startup_duration = time.perf_counter() - start_time
    log.info(f"Took {startup_duration:0.2f}s to startup")

    log.info("Watching for processes we don't like...")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
