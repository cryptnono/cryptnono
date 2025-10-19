import os
from subprocess import run

import pytest


def test_ipv4_allowed():
    p = run(["curl", "--connect-timeout", "1", f"http://192.0.2.2"])
    # Should timeout
    assert p.returncode == 28


@pytest.mark.parametrize(
    "ip",
    [
        "192.0.2.1",
        "192.0.2.3",
    ],
)
def test_ipv4_killed(ip):
    p = run(["curl", "--connect-timeout", "1", f"http://{ip}"])
    assert p.returncode == -9
