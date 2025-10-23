import os
from subprocess import run

import pytest
import requests

FLOWKILLER_METRICS_PORT = os.getenv("FLOWKILLER_METRICS_PORT", 12122)


def get_metric(metric, default=0):
    r = requests.get(f"http://localhost:{FLOWKILLER_METRICS_PORT}")
    r.raise_for_status()
    for line in r.text.splitlines():
        m, value = line.split(" ", 1)
        if m == metric:
            return float(value)
    return default


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
    before = get_metric('cryptnono_flowkiller_processes_killed_total{source="ip"}')

    p = run(["curl", "--connect-timeout", "1", f"http://{ip}"])
    assert p.returncode == -9

    after = get_metric('cryptnono_flowkiller_processes_killed_total{source="ip"}')
    assert after > before


def test_multiple_requests_killed():
    before = get_metric('cryptnono_flowkiller_processes_killed_total{source="scan"}')

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

    after = get_metric('cryptnono_flowkiller_processes_killed_total{source="scan"}')
    assert after > before
