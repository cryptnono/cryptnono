FROM ubuntu:22.04

RUN apt-get update --yes >/dev/null && \
    apt-get install --yes -qq \
        python3 python3-ahocorasick python3-bpfcc \
        tini \
        bpftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY scripts /scripts

# This container expects to be run with hostPID set to true, so `tini`
# will not actually be pid 1. So we pass `-s` to enable 'subreaper'
# mode. https://github.com/krallin/tini#subreaping has more info
ENTRYPOINT ["tini", "-s", "--"]
