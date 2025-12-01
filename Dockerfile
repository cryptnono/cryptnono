FROM docker.io/library/ubuntu:24.04

RUN apt-get update --yes >/dev/null && \
    apt-get install --yes -qq \
        curl \
        python3 \
        python3-ahocorasick \
        python3-bpfcc \
        python3-docker \
        python3-traitlets \
        python3-cachetools \
        # python3-docker package is missing the distutils dependency
        python3-distutils-extra \
        python3-prometheus-client \
        python3-structlog \
        python3-psutil \
        tar \
        tini \
        bpftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# available crictl versions: https://github.com/kubernetes-sigs/cri-tools/tags
ARG CRICTL_VERSION=1.33.0
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

COPY scripts /scripts

# This container expects to be run with hostPID set to true, so `tini`
# will not actually be pid 1. So we pass `-s` to enable 'subreaper'
# mode. https://github.com/krallin/tini#subreaping has more info
ENTRYPOINT ["tini", "-s", "--"]
