#!/usr/bin/env python
# Copied from * Copied from https://github.com/iovisor/bcc/blob/b57dbb397cb110433c743685a7d1eb1fb9c3b1f9/tools/execsnoop.py
# and modified to kill processes, rather than just log them

from shlex import join
import json
from bcc import BPF
import os
import signal
import argparse
from collections import defaultdict


class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1


def kill_if_needed(banned_command_strings, cmdline, pid):
    """
    Kill given process (pid) with cmdline if appropriate, based on banned_command_strings
    """
    for b in banned_command_strings:
        if b in cmdline:
            os.kill(pid, signal.SIGKILL)
            print(f"Killed {pid} because {cmdline} matched {b}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-args",
        default="128",
        help="maximum number of arguments parsed and displayed, defaults to 128",
    )
    parser.add_argument(
        "config_file", help="JSON config file listing what processes to snipe"
    )
    args = parser.parse_args()

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

    # process event
    def process_event(cpu, data, size):
        event = b["events"].event(data)

        if event.type == EventType.EVENT_ARG:
            # We are getting a single argument passed in for this pid
            argv[event.pid].append(event.argv.decode())
        elif event.type == EventType.EVENT_RET:
            # The exec call itself has returned, but the process has
            # not. This means we have the full set of args now.
            kill_if_needed(banned_command_strings, join(argv[event.pid]), event.pid)

            try:
                # Cleanup our dict, as we're no longer collecting args
                # via the ring buffer
                del argv[event.pid]
            except Exception:
                pass

    # loop with callback to print_event
    b["events"].open_perf_buffer(process_event)
    print("Watching for processes we don't like...")
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()


if __name__ == "__main__":
    main()
