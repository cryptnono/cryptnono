# Attempt to lookup a container/image/pod based on the host PID

import json
import re
import subprocess
from typing import Any, Optional


class ContainerNotFound(Exception):
    pass


def get_cri_container_id(pid: int, cgroup_file: Optional[str] = None) -> tuple[str, str]:
    """
    Find the CRI container ID for a process using crictl

    pid: process ID
    cgroup_file: optional path to /proc/<pid>/cgroup file
    returns: (container ID, cgroup line)
    """

    # https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/
    # In theory this is also possible using the Kubernetes API
    # https://github.com/containernetworking/cni/pull/936
    # but it's inefficient, as we'd need to list all pods and check
    # pod.status.containerStatuses[*].ContainerID for a match.

    if cgroup_file is None:
        cgroup_file = f"/proc/{pid}/cgroup"
    try:
        with open(cgroup_file) as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise ContainerNotFound(f"Could not find cgroup for PID {pid}") from None
    for line in lines:
        line = line.strip()
        cgroup_path = line.rsplit(":")[-1]
        m = re.match(r".*containerd-(\w+).scope$", cgroup_path)
        if m:
            return m.group(1), line
    raise ContainerNotFound(f"Could not find container ID for PID {pid}")


def _get_nested_key(d: dict, path: list[str], default: Any) -> Any:
    value = d
    for k in path:
        if k in value:
            value = value[k]
        else:
            return default
    return value


def lookup_container_details_crictl(container_id: str) -> tuple[str, str, str]:
    """
    Find a K8s pod by CRI container ID using crictl.

    https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/
    container_id: CRI container ID
    returns: (pod name, container name, container image)
    """
    cmd = ["crictl", "inspect", container_id]
    p = subprocess.run(cmd, capture_output=True, timeout=2)

    if p.returncode == 0:
        container = json.loads(p.stdout)
        pod_name = _get_nested_key(container, ["status", "labels", "io.kubernetes.pod.name"], "unknown")
        container_name = _get_nested_key(container, ["status", "labels", "io.kubernetes.container.name"], "unknown")
        image = _get_nested_key(container, ["status", "image", "image"], "unknown")
        return pod_name, container_name, image
    raise ContainerNotFound(f"Could not find pod with container {container_id}")
