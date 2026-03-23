# Attempt to lookup a container/image/pod based on the host PID

import json
import re
import subprocess
from enum import Enum
from os import getenv

import docker


class ContainerType(Enum):
    CRI = "cri"
    DOCKER = "docker"
    BUILDKIT = "buildkit"


class ContainerNotFound(Exception):
    def __init__(self, *args, cgroupline: str | None = None) -> None:
        super().__init__(*args)
        self.cgroupline = cgroupline


def get_container_id(
    pid: int, cgroup_file: str | None = None
) -> tuple[str, str, ContainerType]:
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

    # /proc/pid/cgroup
    # https://man7.org/linux/man-pages/man7/cgroups.7.html
    # hierarchy-ID:controller-list:cgroup-path
    #
    # hierarchy-ID: Always 0 in cgroups v2
    # controller-list: Always empty in cgroups v2
    # cgroup-path: pathname of the control group
    #
    # i.e. for cgroups v2 this always starts with 0::/

    if cgroup_file is None:
        cgroup_file = f"/proc/{pid}/cgroup"
    try:
        with open(cgroup_file) as f:
            lines = f.readlines()
    except (FileNotFoundError, ProcessLookupError):
        # Process already exited
        raise ContainerNotFound(f"Could not find cgroup for PID {pid}") from None
    for line in lines:
        line = line.strip()
        # Kubernetes
        cri = re.search(r"containerd-(\w+).scope$", line)
        if cri:
            return cri.group(1), line, ContainerType.CRI

        # Docker Buildkit (ID is for builder, not for container)
        docker_buildkit = re.search(r"docker/buildkit/(\w+)$", line)
        if docker_buildkit:
            return docker_buildkit.group(1), line, ContainerType.BUILDKIT

        # Kubernetes DinD (BinderHub)
        docker_in_cri = re.search(r"docker/(\w+)$", line)
        if docker_in_cri:
            return docker_in_cri.group(1), line, ContainerType.DOCKER

        # Docker
        docker_host = re.search(r"docker-(\w+).scope$", line)
        if docker_host:
            return docker_host.group(1), line, ContainerType.DOCKER

        # TODO: We may need to parse cgroup values for other container runtimes here

    # Just return first cgroup line since there may be a several
    raise ContainerNotFound(
        f"Could not find container ID for PID {pid}", cgroupline=lines[0].strip()
    )


def lookup_container_details_crictl(
    container_id: str, include_envvars: list[str]
) -> dict[str, str]:
    """
    Find information about a K8s pod by CRI container ID using crictl.

    https://kubernetes.io/docs/tasks/debug/debug-cluster/crictl/
    container_id: CRI container ID
    include_envvars: List of container environment variables to include
    returns: dictionary with information about container
    """
    cmd = ["crictl", "inspect", container_id]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=2, check=True)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            raise ContainerNotFound(
                f"Could not find pod with container {container_id}"
            ) from None
        raise

    container = json.loads(p.stdout)
    labels = container.get("status", {}).get("labels", None)
    image = container.get("status", {}).get("image", {}).get("image", None)

    container_info = {"container_type": ContainerType.CRI.value}
    if labels is not None:
        container_info["labels"] = labels
    if image is not None:
        container_info["image"] = image
    if include_envvars:
        container_info["env"] = {}
        envs = container.get("info", {}).get("config", {}).get("envs", [])
        for env in envs:
            if env["key"] in include_envvars:
                container_info["env"][env["key"]] = env.get("value")

    return container_info


def lookup_container_details_docker(
    container_id: str, include_envvars: list[str]
) -> dict[str, str]:
    """
    Find information about a Docker container.

    container_id: CRI container ID
    include_envvars: List of container environment variables to include
    returns: dictionary with information about container
    """
    client = docker.APIClient(getenv("DOCKER_HOST"))
    try:
        container = client.inspect_container(container_id)
    except docker.errors.NotFound:
        raise ContainerNotFound(f"Could not find container {container_id}") from None

    container_info = {
        "container_type": ContainerType.DOCKER.value,
        "image": container["Image"],
        "labels": container["Config"]["Labels"],
    }
    if include_envvars:
        container_info["env"] = {}
        for kv in container["Config"]["Env"]:
            k, v = kv.split("=", 1)
            if k in include_envvars:
                container_info["env"][k] = v
    return container_info


def lookup_container_details_buildkit(container_id: str) -> dict[str, str]:
    """
    Return placeholder information about a BuildKit runner

    container_id: BuildKit builder ID
    returns: dictionary with placeholder information
    """
    container_info = {
        "container_type": ContainerType.BUILDKIT.value,
        "builder_id": container_id,
    }
    return container_info


def lookup_container_details(
    container_id: str, container_type: ContainerType, include_envvars: list[str]
) -> dict[str, str]:
    if container_type == ContainerType.CRI:
        return lookup_container_details_crictl(container_id, include_envvars)
    if container_type == ContainerType.BUILDKIT:
        return lookup_container_details_buildkit(container_id)
    if container_type == ContainerType.DOCKER:
        return lookup_container_details_docker(container_id, include_envvars)
    raise ValueError(f"Unknown container type {container_type}")
