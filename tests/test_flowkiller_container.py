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


def test_multiple_requests_killed():
    p = run(
        [
            os.path.join(
                os.path.dirname(__file__),
                "resources",
                "multiple_network_requests.py",
            )
        ]
    )
    assert p.returncode == -9
