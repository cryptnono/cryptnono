#!/usr/bin/env python
# Copied from * Copied from https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/execsnoop.py
# and modified to kill processes, rather than just log them

from shlex import join
import logging
import json
import time
from bcc import BPF
import os
import signal
import argparse
from collections import defaultdict


class EventType:
    """
    Type of event dispatched from eBPF.

    Matches the `event_type` enum in execsniper.bpf.c.
    """

    # Pass a single argument from eBPF to python
    EVENT_ARG = 0
    # Pass a return value from eBPF to python
    EVENT_RET = 1


def kill_if_needed(banned_command_strings, cmdline, pid):
    """
    Kill given process (pid) with cmdline if appropriate, based on banned_command_strings
    """
    for b in banned_command_strings:
        if b in cmdline:
            os.kill(pid, signal.SIGKILL)
            logging.info(f"action:killed pid:{pid} cmdline:{cmdline} matched:{b}")


def main():
    start_time = time.perf_counter()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-args",
        default="128",
        help="maximum number of arguments parsed and displayed, defaults to 128",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("config_file", help="JSON config file listing what processes to snipe")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    logging.info("Compiling and loading BPF program...")

    with open(os.path.join(os.path.dirname(__file__), "execsniper.bpf.c")) as f:
        bpf_text = f.read()

    # FIXME: Investigate what exactly happens when this is different
    bpf_text = bpf_text.replace("MAXARG", args.max_args)

    with open(args.config_file) as f:
        config = json.load(f)

    banned_command_strings = config.get("bannedCommandStrings", [])

    # initialize BPF
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
    b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

    argv = defaultdict(list)

    def process_event(ctx, data, size):
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
            kill_if_needed(banned_command_strings, cmdline, event.pid)
            logging.debug(f"action:observed pid:{event.pid} cmdline:{cmdline}")

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

    # Trigger our callback each time something is written to the
    # "events" ring buffer
    b["events"].open_ring_buffer(process_event)

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
