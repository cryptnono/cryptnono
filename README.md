# cryptnono

Kill processes attempting to mine crypto on your k8s cluster.

Licensed as GPLv3 as that is the license of the original bpftrace program

## Installation

A [helm](https://helm.sh/) chart is provided for you to install
this onto your cluster.

```bash
helm install cryptnono cryptnono --repo=https://yuvipanda.github.io/cryptnono/ --devel
```
## Why use `bcc`?

There are *many* ways to interact with eBPF, and in this repo, we choose to do it
via [bcc](https://github.com/iovisor/bcc/) for the most part (with minor use of
[bpftrace](https://github.com/iovisor/bpftrace) that should be converted). The
reasons are:

1. [bpftrace](https://github.com/iovisor/bpftrace) is simple enough for me to write,
   but it can not really read any config files from within the `bpftrace` language, so
   it can not be standalone.
2. We *could* write output from `bpftrace` and read it in a python script (via `stdout`).
   This has some simplicity advantages - python code is just dealing with strings, and
   `bpftrace` just needs to output stuff. However, given `bpftrace` does not have the
   ability to output in a structured format (like JSON), we'll have to invent an ad-hoc
   way of passing parameters back safely (so an attacker can't just inject random stuff
   into the output!). Plus, the latency might open us up to some variant of
   [TOCTU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) attacks, as the
   process that triggers a detector might have spawned something else and be gone by
   the time our python process decides to do something with it.
3. [libbpf](https://github.com/libbpf/libbpf) has a lot of advantages, but it requires
   one to write C. I am however too smart to think I can actually write proper C, so
   this is not to be considered.
4. bcc uses python for the userspace, and I'm very familiar with Python.

So despite its drawbacks (primarily needing to compile at runtime), bcc is the best
choice for now. Perhaps some form of `libbpf` bindings (perhaps in Rust or Go?) would be
the way to go in the future, but not now.

## Detectors

`cryptnono` is organized as a series of *detectors* that all serve a specific purpose.
They are deployed as containers on the same `daemonset`.

### Monero detector

Based off the bpftrace program in [this wonderful blogpost](https://blog.px.dev/detect-monero-miners/).

![](./screenshot.png)
