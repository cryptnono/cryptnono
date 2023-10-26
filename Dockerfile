FROM alpine:3.18

RUN apk add python3 bpftrace tini py3-bcc

COPY scripts /scripts

ENTRYPOINT ["tini", "-s", "--"]