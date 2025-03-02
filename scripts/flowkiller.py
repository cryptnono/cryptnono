#!/usr/bin/env python
# Adapted from https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py

from functools import partial
from pathlib import Path
from bcc import BPF
import argparse
from ipaddress import ip_address, IPv4Address, IPv6Address
from struct import pack

parser = argparse.ArgumentParser(
    description="Kill processes based on tcp flows"
)
args = parser.parse_args()
bpf_text = (Path(__file__).parent / "flowkiller.bpf.c").read_text()

def handle_connection(pid: int, saddr: IPv4Address | IPv6Address, sport: int, daddr: IPv4Address | IPv6Address, dport: int):
    print([pid, saddr, sport, daddr, dport])

def handle_event(event_name: str, b: BPF, cpu, data, size):
    event = b[event_name].event(data)
    saddr = ip_address(pack("I", event.saddr))
    daddr = ip_address(pack("I", event.daddr))
    handle_connection(event.pid, saddr, event.lport, daddr, event.dport)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

# read events
b["ipv4_events"].open_perf_buffer(partial(handle_event, "ipv4_events", b))
b["ipv6_events"].open_perf_buffer(partial(handle_event, "ipv6_events", b))
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()