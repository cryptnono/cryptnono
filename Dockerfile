# Use latest possible released Ubuntu, so we get a newer
# version of bcc to deal with https://github.com/iovisor/bcc/issues/3366
# Should be bumped to an LTS when it becomes available
FROM ubuntu:23.10

RUN apt-get update --yes >/dev/null && \
    apt-get install --yes -qq \
        python3 python3-pip python3-bpfcc \
        tini \
        bpftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Try installing a newer version of pyahocorasick, as the version from apt
# is pretty old. Perhaps the cause of  https://github.com/yuvipanda/cryptnono/issues/8
RUN python3 -m pip install pyahocorasick

COPY scripts /scripts

# This container expects to be run with hostPID set to true, so `tini`
# will not actually be pid 1. So we pass `-s` to enable 'subreaper'
# mode. https://github.com/krallin/tini#subreaping has more info
ENTRYPOINT ["tini", "-s", "--"]
