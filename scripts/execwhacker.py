#!/usr/bin/env python3
# Copied from * Copied from https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/execsnoop.py
# and modified to kill processes, rather than just log them

import re
import argparse
import json
import logging
import os
import signal
import time
from functools import partial
from collections import defaultdict
from shlex import join

import ahocorasick
from bcc import BPF


class EventType:
    """
    Type of event dispatched from eBPF.

    Matches the `event_type` enum in execwhacker.bpf.c.
    """

    # Pass a single argument from eBPF to python
    EVENT_ARG = 0
    # Pass a return value from eBPF to python
    EVENT_RET = 1


def kill_if_needed(banned_strings_automaton, allowed_patterns, cmdline, pid):
    """
    Kill given process (pid) with cmdline if appropriate, based on banned_command_strings
    """
    for _, b in banned_strings_automaton.iter(cmdline):
        for ap in allowed_patterns:
            if re.match(ap, cmdline):
                logging.info(
                    f"action:spared pid:{pid} cmdline:{cmdline} matched:{b} allowed-by:{ap}"
                )
                return
        try:
            os.kill(pid, signal.SIGKILL)
            logging.info(f"action:killed pid:{pid} cmdline:{cmdline} matched:{b}")
            break
        except ProcessLookupError:
            logging.info(
                f"action:missed-kill pid:{pid} cmdline:{cmdline} matched:{b} Process exited before we could kill it"
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
        kill_if_needed(banned_strings_automaton, allowed_patterns, cmdline, event.pid)
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
        banned_strings_automaton.add_word(b, b)

    banned_strings_automaton.make_automaton()

    logging.info(
        f"Found {len(banned_strings)} substrings to check process cmdlines for"
    )

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
    logging.info("Watching for processes we don't like...")
    while 1:
        try:
            b.ring_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
