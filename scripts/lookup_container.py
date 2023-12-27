# Attempt to lookup a container/image/pod based on the host PID

import docker
from enum import Enum
import json
from os import getenv
import re
import subprocess
from typing import Any, Optional


class ContainerType(Enum):
    CRI = "cri"
    DOCKER = "docker"


class ContainerNotFound(Exception):
    pass


def get_container_id(pid: int, cgroup_file: Optional[str] = None) -> tuple[str, str, ContainerType]:
    """
    Find the CRI or Docker container ID for a process

    pid: process ID
    cgroup_file: optional path to /proc/<pid>/cgroup file
    returns: (container ID, cgroup line, ContainerType)
    """

    # CRI (Kubernetes):
    #   https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/
    #   In theory this is also possible using the Kubernetes API
    #   https://github.com/containernetworking/cni/pull/936
    #   but it's inefficient, as we'd need to list all pods and check
    #   pod.status.containerStatuses[*].ContainerID for a match.
    #
    # Docker (Repo2docker via DinD):
    #   Basically found by inspection

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
        # Kubernetes
        cri = re.match(r".*containerd-(\w+).scope$", cgroup_path)
        if cri:
            return cri.group(1), line, ContainerType.CRI
        # Kubernetes DinD (BinderHub)
        docker_in_cri = re.match(r".*docker/(\w+)$", cgroup_path)
        if docker_in_cri:
            return docker_in_cri.group(1), line, ContainerType.DOCKER
        # Docker
        docker_host = re.match(r".*docker-(\w+).scope$", cgroup_path)
        if docker_host:
            return docker_host.group(1), line, ContainerType.DOCKER
        # TODO: We may need to detect other cgroup paths here
    raise ContainerNotFound(f"Could not find container ID for PID {pid}")


def _get_nested_key(d: dict, path: list[str], default: Any) -> Any:
    value = d
    for k in path:
        if k in value:
            value = value[k]
        else:
            return default
    return value


def lookup_container_details_crictl(container_id: str) -> dict[str, str]:
    """
    Find information about a K8s pod by CRI container ID using crictl.

    https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/
    container_id: CRI container ID
    returns: dictionary with information about container
    """
    cmd = ["crictl", "inspect", container_id]
    p = subprocess.run(cmd, capture_output=True, timeout=2)

    if p.returncode == 0:
        container = json.loads(p.stdout)
        pod_name = _get_nested_key(container, ["status", "labels", "io.kubernetes.pod.name"], None)
        container_name = _get_nested_key(container, ["status", "labels", "io.kubernetes.container.name"], None)
        image = _get_nested_key(container, ["status", "image", "image"], None)

        container_info = {"container_type": ContainerType.CRI.value}
        if pod_name is not None:
            container_info["pod_name"] = pod_name
        if container_name is not None:
            container_info["container_name"] = container_name
        if image is not None:
            container_info["container_image"] = image
        return container_info
    raise ContainerNotFound(f"Could not find pod with container {container_id}")


def lookup_container_details_docker(container_id: str) -> dict[str, str]:
    """
    Find information about a Docker container.

    container_id: CRI container ID
    returns: dictionary with information about container
    """
    client = docker.APIClient(getenv("DOCKER_HOST"))
    try:
        container = client.inspect_container(container_id)
    except docker.errors.NotFound:
        raise ContainerNotFound(f"Could not find container {container_id}") from None

    container_info = {
        "container_type": ContainerType.DOCKER.value,
        "container_image": container["Image"],
        "container_labels": container["Config"]["Labels"],
    }
    return container_info
