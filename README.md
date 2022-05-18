# cryptnono

Kill processes attempting to mine Monero on your k8s cluster.

Based off the bpftrace program in [this wonderful blogpost](https://blog.px.dev/detect-monero-miners/).

![](./screenshot.png)

Licensed as GPLv3 as that is the license of the original bpftrace program

## Installation

A [helm](https://helm.sh/) chart is provided for you to install
this onto your cluster.

```bash
helm repo add cryptnono https://yuvipanda.github.io/cryptnono/
helm repo update
helm install cryptnono cryptnono/cryptnono --devel
```