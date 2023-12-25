from pathlib import Path
import pytest
from unittest.mock import patch
import subprocess

from scripts.lookup_container import ContainerNotFound, get_cri_container_id, lookup_container_details_crictl


RESOURCES_DIR = Path(__file__).parent / "resources"
MOCK_CID = "4afca7c3013258aa1b81ac99fea8b68d9262f253ccb5f4ba2dd549d092afa6c3"


def test_get_cri_container_id():
    # Use mock data (PID ignored)
    cid = get_cri_container_id(12345, str(RESOURCES_DIR / "proc-pid-cgroup.txt"))
    assert cid == (
        MOCK_CID,
        f"11:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7eed019f_1bfb_404f_8e0a_5687726fade6.slice/cri-containerd-{MOCK_CID}.scope",
    )

    # This should be a real PID, of the root init process, so this should fail
    with pytest.raises(ContainerNotFound):
        get_cri_container_id(1)


def test_lookup_container_details_crictl():
    mock_data = (RESOURCES_DIR / "crictl-inspect.json").read_bytes()
    mock_return = subprocess.CompletedProcess(args=["crictl", "inspect", MOCK_CID], returncode=0, stdout=mock_data, stderr="")

    with patch("subprocess.run", return_value=mock_return) as mock_run:
        pod_name, container_name, image = lookup_container_details_crictl(MOCK_CID)

        mock_run.assert_called_once_with(["crictl", "inspect", MOCK_CID], capture_output=True, timeout=2)
        assert pod_name == "jupyter-binder-2dexamples-2dconda-2d7ezx5gay"
        assert container_name == "notebook"
        assert image == "container.example.org/binderhub/binder-2dexamples-2dconda-8677da:f00a783146e9c6a2ed9726f01fc09fbfbad2f89e"
