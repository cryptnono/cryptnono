#!/usr/bin/env python
# Adapted from https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py

import argparse
import math
import os
import signal
from functools import partial
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from struct import pack

import structlog
from bcc import BPF
from cachetools import TTLCache

pid_connections = TTLCache(maxsize=math.inf, ttl=60 * 60)
cutoff = 10

# Lazily initialised with configuration on first use
logging = structlog.get_logger()

recently_killed = TTLCache(maxsize=1024, ttl=60 * 60)


def handle_connection(
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
    if pid in recently_killed:
        return

    log = logging.bind(pid=pid)
    process_connections: TTLCache = pid_connections.setdefault(
        pid, TTLCache(math.inf, 60)
    )

    key = f"{daddr}:{dport}"
    process_connections[key] = process_connections.get(key, 0) + 1

    if len(process_connections) > cutoff:
        try:
            os.kill(pid, signal.SIGKILL)
            logging.info(
                "Killed process",
                pid=pid,
                action="killed",
                addresses=dict(process_connections),
            )
            recently_killed[pid] = True
        except ProcessLookupError:
            log.info(
                "Process exited before we could kill it",
                pid=pid,
                action="missed-kill",
                addresses=dict(process_connections),
            )

        # Stop storing info about this pid now that we're done
        del pid_connections[pid]


def handle_event(event_name: str, b: BPF, cpu, data, size):
    """
    Handle successful tcp connect events from ebpf
    """
    event = b[event_name].event(data)
    saddr = ip_address(pack("I", event.saddr))
    daddr = ip_address(pack("I", event.daddr))
    handle_connection(event.pid, saddr, event.lport, daddr, event.dport)


def main():
    parser = argparse.ArgumentParser(description="Kill processes based on tcp flows")
    args = parser.parse_args()

    bpf_text = (Path(__file__).parent / "flowkiller.bpf.c").read_text()
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

    b["ipv4_events"].open_perf_buffer(partial(handle_event, "ipv4_events", b))
    b["ipv6_events"].open_perf_buffer(partial(handle_event, "ipv6_events", b))
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
