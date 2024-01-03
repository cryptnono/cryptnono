import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch
import subprocess

from scripts.lookup_container import ContainerNotFound, ContainerType, get_container_id, lookup_container_details_crictl, lookup_container_details_docker


RESOURCES_DIR = Path(__file__).parent / "resources"
MOCK_CRI_CID = "4afca7c3013258aa1b81ac99fea8b68d9262f253ccb5f4ba2dd549d092afa6c3"
MOCK_CRI_DIND_CID = "9e9192d35808d67079f075531628e7c903f4eafc7b1e495592c80951fe9e037d"
"669735f6cb499a55be7cf29f06e82d706d2322a28e6259d2345a3ed85542a83d"
MOCK_DOCKER_CID = "669735f6cb499a55be7cf29f06e82d706d2322a28e6259d2345a3ed85542a83d"


def test_get_container_id():
    # Use mock data (PID ignored), CRI
    cid = get_container_id(12345, str(RESOURCES_DIR / "proc-pid-cgroup-cri.txt"))
    assert cid == (
        MOCK_CRI_CID,
        f"11:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7eed019f_1bfb_404f_8e0a_5687726fade6.slice/cri-containerd-{MOCK_CRI_CID}.scope",
        ContainerType.CRI,
    )

    # Use mock data (PID ignored), CRI Docker-in-Docker
    cid = get_container_id(12345, str(RESOURCES_DIR / "proc-pid-cgroup-cri-dind.txt"))
    assert cid == (
        MOCK_CRI_DIND_CID,
        f"11:memory:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb9f8981c_e025_499c_9482_589e013e7dc6.slice/cri-containerd-a5f1accb86d9c02649abac024e8ee50cc090fa3aea058b1438116902bae0a204.scope/docker/{MOCK_CRI_DIND_CID}",
        ContainerType.DOCKER,
    )

    # Use mock data (PID ignored), Docker
    cid = get_container_id(12345, str(RESOURCES_DIR / "proc-pid-cgroup-docker.txt"))
    assert cid == (
        MOCK_DOCKER_CID,
        f"0::/system.slice/docker-{MOCK_DOCKER_CID}.scope",
        ContainerType.DOCKER,
    )

    # This should be a real PID, of the root init process, so this should fail
    with pytest.raises(ContainerNotFound):
        get_container_id(1)


def test_lookup_container_details_crictl():
    mock_data = (RESOURCES_DIR / "crictl-inspect.json").read_bytes()
    mock_return = subprocess.CompletedProcess(args=["crictl", "inspect", MOCK_CRI_CID], returncode=0, stdout=mock_data, stderr="")

    with patch("subprocess.run", return_value=mock_return) as mock_run:
        container_info = lookup_container_details_crictl(MOCK_CRI_CID)

        mock_run.assert_called_once_with(["crictl", "inspect", MOCK_CRI_CID], capture_output=True, timeout=2, check=True)

    assert container_info == {
        "container_type": "cri",
        "image": "container.example.org/binderhub/binder-2dexamples-2dconda-8677da:f00a783146e9c6a2ed9726f01fc09fbfbad2f89e",
        "labels": {
            "io.kubernetes.container.name": "notebook",
            "io.kubernetes.pod.name": "jupyter-binder-2dexamples-2dconda-2d7ezx5gay",
            "io.kubernetes.pod.namespace": "test",
            "io.kubernetes.pod.uid": "7eed019f-1bfb-404f-8e0a-5687726fade6",
        }
    }


def test_lookup_missing_container_details_crictl():
    with patch("subprocess.run", side_effect=ContainerNotFound("Mock exception")) as mock_run:
        with pytest.raises(ContainerNotFound):
            lookup_container_details_crictl("nonexistent")
        mock_run.assert_called_once_with(["crictl", "inspect", "nonexistent"], capture_output=True, timeout=2, check=True)


def test_lookup_container_details_docker():
    mock_data = json.loads((RESOURCES_DIR / "docker-inspect.json").read_bytes())

    with patch('docker.APIClient', return_value=MagicMock(inspect_container=MagicMock(return_value=mock_data))) as mock_client:
        container_info = lookup_container_details_docker(MOCK_CRI_DIND_CID)

        mock_client().inspect_container.assert_called_once_with(MOCK_CRI_DIND_CID)

    assert container_info == {
        "container_type": "docker",
        "image": "sha256:040235dc5a23a454ee42151986c7c9b11c7a8f5f88c5f30af75733e205088ab4",
        "labels": {
            "org.opencontainers.image.ref.name": "ubuntu",
            "org.opencontainers.image.version": "22.04",
            "repo2docker.ref": "a1ed39428a442b2385b70e07ceb2fde003d6a1b6",
            "repo2docker.repo": "https://gist.github.com/manics/7fa84cf867b703f360e74dbe3e1bc2c0.git",
            "repo2docker.version": "2023.06.0+41.g57d229e",
        },
    }


def test_lookup_missing_container_details_docker():
    with patch('docker.APIClient', return_value=MagicMock(inspect_container=MagicMock(side_effect=ContainerNotFound("Mock exception")))) as mock_client:
        with pytest.raises(ContainerNotFound):
            lookup_container_details_docker("nonexistent")
        mock_client().inspect_container.assert_called_once_with("nonexistent")
