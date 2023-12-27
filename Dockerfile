# Use latest possible released Ubuntu, so we get a newer
# version of bcc to deal with https://github.com/iovisor/bcc/issues/3366
# Should be bumped to an LTS when it becomes available
FROM ubuntu:23.10

RUN apt-get update --yes >/dev/null && \
    apt-get install --yes -qq \
        curl \
        python3 \
        python3-ahocorasick \
        python3-bpfcc \
        python3-docker \
        python3-prometheus-client \
        python3-structlog \
        python3-psutil \
        tar \
        tini \
        bpftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ARG CRICTL_VERSION=1.29.0
RUN MACHINE=`uname -m`; \
    if [ "$MACHINE" = "x86_64" ]; then \
        ARCH=amd64; \
    elif [ "$MACHINE" = "aarch64" ]; then \
        ARCH=arm64; \
    else \
        echo "Unsupported architecture: $MACHINE"; \
        exit 1; \
    fi; \
    curl -sSfL https://github.com/kubernetes-sigs/cri-tools/releases/download/v${CRICTL_VERSION}/crictl-v${CRICTL_VERSION}-linux-${ARCH}.tar.gz | \
        tar -C /usr/local/bin -xzf -

# These must match the values in daemonset.yaml
ENV CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
ENV IMAGE_SERVICE_ENDPOINT=unix:///run/containerd/containerd.sock
ENV DOCKER_HOST=unix:///run/docker/docker.sock

COPY scripts /scripts

# This container expects to be run with hostPID set to true, so `tini`
# will not actually be pid 1. So we pass `-s` to enable 'subreaper'
# mode. https://github.com/krallin/tini#subreaping has more info
ENTRYPOINT ["tini", "-s", "--"]
