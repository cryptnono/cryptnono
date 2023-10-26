FROM alpine:3.18

RUN apk add python3 bpftrace

COPY scripts /scripts