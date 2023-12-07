#!/usr/bin/env python3
# Copied from * Copied from https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/execsnoop.py
# and modified to kill processes, rather than just log them

import re
import argparse
from enum import Enum
import json
import logging
import os
from pathlib import Path
from psutil import process_iter
import signal
import threading
import time
from functools import partial
from collections import defaultdict
from shlex import join

import ahocorasick
from bcc import BPF
from prometheus_client import Counter, start_http_server


class EventType:
    """
    Type of event dispatched from eBPF.

    Matches the `event_type` enum in execwhacker.bpf.c.
    """

    # Pass a single argument from eBPF to python
    EVENT_ARG = 0
    # Pass a return value from eBPF to python
    EVENT_RET = 1


class ProcessSource(Enum):
    """
    Where did execwhacker get the process information from?
    """
    BPF = "execwhacker.bpf"
    SCAN = "psutil.process_iter"


# ahocorasick is not thread-safe, so just in case use a lock
# https://github.com/WojciechMula/pyahocorasick/issues/114
banned_strings_automaton_lock = threading.Lock()

processes_checked = Counter("cryptnono_execwhacker_processes_checked_total", "Total number of processes checked", ["source"])
processes_killed = Counter("cryptnono_execwhacker_processes_killed_total", "Total number of processes killed", ["source"])


def kill_if_needed(banned_strings_automaton, allowed_patterns, cmdline, pid, source):
    """
    Kill given process (pid) with cmdline if appropriate, based on banned_command_strings
    """
    # Make all matches be case insensitive
    cmdline = cmdline.casefold()
    with banned_strings_automaton_lock:
        processes_checked.labels(source=source.value).inc()
        for _, b in banned_strings_automaton.iter(cmdline):
            for ap in allowed_patterns:
                if re.match(ap, cmdline, re.IGNORECASE):
                    if source != ProcessSource.SCAN:
                        logging.info(
                            f"action:spared pid:{pid} cmdline:{cmdline} matched:{b} allowed-by:{ap} source:{source.value}"
                        )
                    return
            try:
                os.kill(pid, signal.SIGKILL)
                logging.info(f"action:killed pid:{pid} cmdline:{cmdline} matched:{b} source:{source.value}")
                processes_killed.labels(source=source.value).inc()
                return True
            except ProcessLookupError:
                logging.info(
                    f"action:missed-kill pid:{pid} cmdline:{cmdline} matched:{b} source:{source.value} Process exited before we could kill it"
                )


def process_event(
    b: BPF,
    argv: dict,
    banned_strings_automaton: ahocorasick.Automaton,
    allowed_patterns: list,
    ctx,
    data,
    size,
):
    """
    Callback each time an event is sent from eBPF to python
    """
    event = b["events"].event(data)

    if event.type == EventType.EVENT_ARG:
        # We are getting a single argument passed in for this pid
        # Save it into a temporary dict so we can construct the whole
        # argv for a pid, event by event.
        argv[event.pid].append(event.argv.decode())
    elif event.type == EventType.EVENT_RET:
        # The exec call itself has returned, but the process has
        # not. This means we have the full set of args now.
        cmdline = join(argv[event.pid])
        start_time = time.perf_counter()
        kill_if_needed(banned_strings_automaton, allowed_patterns, cmdline, event.pid, ProcessSource.BPF)
        duration = time.perf_counter() - start_time
        logging.debug(
            f"action:observed pid:{event.pid} cmdline:{cmdline} duration:{duration:0.10f}s"
        )

        try:
            # Cleanup our dict, as we're no longer collecting args
            # via the ring buffer
            del argv[event.pid]
        except Exception as e:
            # Catch any possible exception here - either a KeyError from
            # argv not containing `event.pid` or something from ctypes as we
            # try to access `event.pid`. *Should* not happen, but better than
            # crashing? Also this was in the bcc execsnoop code, so it stays here.
            # Brendan knows best
            logging.exception(e)


def check_existing_processes(banned_strings_automaton, allowed_patterns, interval):
    """
    Scan all running processes for banned strings
    
    BPF only looks for new processes, this will find banned processes that were already
    running, and any that might've been missed by BPF for unknown reasons.
    """
    while True:
        count = 0
        for proc in process_iter():
            if proc.exe():
                if kill_if_needed(
                    banned_strings_automaton,
                    allowed_patterns,
                    join(proc.cmdline()),
                    proc.pid,
                    ProcessSource.SCAN,
                ):
                    count += 1
        logging.info(f"action:summarise-existing-killed count:{count} source:{ProcessSource.SCAN.value}")
        time.sleep(interval)


def main():
    start_time = time.perf_counter()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-args",
        default="128",
        help="maximum number of arguments parsed and displayed, defaults to 128",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--config",
        help="JSON config file listing what processes to snipe",
        action="append",
        default=[],
    )
    parser.add_argument("--scan-existing", type=int, default=600, help="Scan all existing processes at this interval (seconds), set to 0 to disable")

    parser.add_argument("--serve-metrics-port", type=int, default=0, help="Serve prometheus metrics on this port, set to 0 to disable")

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )

    banned_strings = set()
    allowed_patterns = []
    for config_file in args.config:
        with open(config_file) as f:
            config_file_contents = json.load(f)
            banned_strings.update(config_file_contents.get("bannedCommandStrings", []))

            allowed_patterns += config_file_contents.get("allowedCommandPatterns", [])

    # Use the Aho Corasick algorithm (https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
    # for *very* fast searching, given we always have only one cmdline but potentially tens of thousands
    # of banned substrings to search for inside it. This is run *every time a process spawns*, so should
    # be quick. Compared to a naive solution using set() and 'in', this is
    # roughly 60-100x faster, and uses a lot less CPU too!
    # Credit to Michael Rothwell on Mastodon for pointing me to this direction!
    # https://hachyderm.io/@mrothwell/111317806566634439
    banned_strings_automaton = ahocorasick.Automaton()
    for b in banned_strings:
        # casefold banned strings so we can do case insensitive matching
        banned_strings_automaton.add_word(b.casefold(), b.casefold())

    banned_strings_automaton.make_automaton()

    logging.info(
        f"Found {len(banned_strings)} substrings to check process cmdlines for"
    )
    if len(banned_strings) == 0:
        logging.warning("WARNING: No substrings to whack have been specified, so execwhacker is useless! Check your config?")

    logging.info(f"Found {len(allowed_patterns)} patterns to explicitly allow")

    # initialize BPF
    logging.info("Compiling and loading BPF program...")
    with open(os.path.join(os.path.dirname(__file__), "execwhacker.bpf.c")) as f:
        bpf_text = f.read()

    # FIXME: Investigate what exactly happens when this is different
    bpf_text = bpf_text.replace("MAXARG", args.max_args)
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
    b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

    argv = defaultdict(list)

    # Trigger our callback each time something is written to the
    # "events" ring buffer. We use a partial to pass in appropriate 'global'
    # context that's common to all callbacks instead of defining our callback
    # as an inline function and use closures, to keep things clean and hopefully
    # unit-testable in the future.
    b["events"].open_ring_buffer(
        partial(process_event, b, argv, banned_strings_automaton, allowed_patterns)
    )

    startup_duration = time.perf_counter() - start_time
    logging.info(f"Took {startup_duration:0.2f}s to startup")

    if args.serve_metrics_port:
        start_http_server(args.serve_metrics_port)

    if args.scan_existing:
        # Only run this after the BPF events are being captured, to avoid
        # processes slipping past
        t = threading.Thread(
            target=check_existing_processes,
            args=(banned_strings_automaton, allowed_patterns, args.scan_existing),
        )
        t.daemon = True
        t.start()
        # Don't care about waiting for thread to finish

    logging.info("Watching for processes we don't like...")
    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
