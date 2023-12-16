import os
import requests
import pytest
from subprocess import run
import sys


CRYPTNONO_METRICS_PORT = os.getenv("CRYPTNONO_METRICS_PORT", 12121)


def get_metric(metric, default=0):
    r = requests.get(f"http://localhost:{CRYPTNONO_METRICS_PORT}")
    r.raise_for_status()
    for line in r.text.splitlines():
        m, value = line.split(" ", 1)
        if m == metric:
            return float(value)
    return default


def test_allowed():
    p = run([sys.executable, "-c", "print('allowed cryptnono.banned.string1')"])
    assert p.returncode == 0


@pytest.mark.parametrize("s", [
    "Xcryptnono.banned.string1",
    "cryptnono.banned.string1X",
])
def test_substrings_allowed(s):
    p = run([sys.executable, "-c", f"print('{s}')"])
    assert p.returncode == 0


@pytest.mark.parametrize("s", [
    "cryptnono.banned.string1",
    ".cryptnono.banned.string1",
    "cryptnono.banned.string1-",
])
def test_killed(s):
    before = get_metric('cryptnono_execwhacker_processes_killed_total{source="execwhacker.bpf"}')
    p = run([sys.executable, "-c", f"print('{s}')"])
    assert p.returncode == -9

    after = get_metric('cryptnono_execwhacker_processes_killed_total{source="execwhacker.bpf"}')
    assert after > before


# Test the non-BPF psutil scanner by starting a safe process, and changing it's
# cmdline to one that's banned
def test_self_changing_killed():
    before = get_metric('cryptnono_execwhacker_processes_killed_total{source="psutil.process_iter"}')

    p = run([os.path.join(os.path.dirname(__file__), "resources", "cryptnono-test-self-changing-cmdline")])
    assert p.returncode == -9

    after = get_metric('cryptnono_execwhacker_processes_killed_total{source="psutil.process_iter"}')
    assert after > before
