#!/usr/bin/env python
# Adapted from https://github.com/iovisor/bcc/blob/3f5e402bcadf44ce0250864db52673bf7317797b/tools/tcpconnect.py
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-c] [-t] [-p PID] [-P PORT [PORT ...]] [-4 | -6]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
# 09-Jan-2019   Takuma Kume     Support filtering by UID
# 30-Jul-2019   Xiaozhou Liu    Count connects.
# 07-Oct-2020   Nabil Schear    Correlate connects with DNS responses
# 08-Mar-2021   Suresh Kumar    Added LPORT option

from __future__ import print_function
from pathlib import Path
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime

# arguments
examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -d        # include DNS queries associated with connects
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -P 80,81  # only trace port 80 and 81
    ./tcpconnect -4        # only trace IPv4 family
    ./tcpconnect -6        # only trace IPv6 family
    ./tcpconnect -U        # include UID
    ./tcpconnect -u 1000   # only trace UID 1000
    ./tcpconnect -c        # count connects per src ip and dest ip/port
    ./tcpconnect -L        # include LPORT while printing outputs
    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--port",
    help="comma-separated list of destination ports to trace.")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("-L", "--lport", action="store_true",
    help="include LPORT on output")
parser.add_argument("-U", "--print-uid", action="store_true",
    help="include UID on output")
parser.add_argument("-u", "--uid",
    help="trace this UID only")
parser.add_argument("-c", "--count", action="store_true",
    help="count connects per src ip and dest ip/port")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-d", "--dns", action="store_true",
    help="include likely DNS query associated with each connect")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

bpf_text = (Path(__file__).parent / "flowkiller.bpf.c").read_text()


bpf_text = filter_by_containers(args) + bpf_text

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        dest_ip, event.dport))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    dest_ip = inet_ntop(AF_INET6, event.daddr).encode()
    printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d" % (event.pid,
        event.task, event.ip,
        inet_ntop(AF_INET6, event.saddr).encode(),
        dest_ip, event.dport))


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

print("Tracing connect ... Hit Ctrl-C to end")
# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
if args.print_uid:
    print("%-6s" % ("UID"), end="")
if args.lport:
    print("%-7s %-12s %-2s %-16s %-6s %-16s %-6s" % ("PID", "COMM", "IP", "SADDR",
        "LPORT", "DADDR", "DPORT"), end="")
else:
    print("%-7s %-12s %-2s %-16s %-16s %-6s" % ("PID", "COMM", "IP", "SADDR",
        "DADDR", "DPORT"), end="")
if args.dns:
    print(" QUERY")
else:
    print()

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()