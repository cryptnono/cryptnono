FROM ubuntu:22.04

RUN apt update --yes >/dev/null && \
    apt install --yes python3 python3-ahocorasick tini python3-bpfcc bpftrace

COPY scripts /scripts

# This container expects to be run with hostPID set to true, so `tini`
# will not actually be pid 1. So we pass `-s` to enable 'subreaper'
# mode. https://github.com/krallin/tini#subreaping has more info
ENTRYPOINT ["tini", "-s", "--"]