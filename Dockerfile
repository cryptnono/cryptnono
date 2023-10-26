FROM alpine:3.18

RUN apk add python3 bpftrace tini

COPY scripts /scripts

ENTRYPOINT ["tini", "--"]