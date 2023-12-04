import os
from subprocess import run
import sys


def test_allowed():
    p = run([sys.executable, "-c", "print('allowed cryptnono.banned.string1')"])
    assert p.returncode == 0


def test_killed():
    p = run([sys.executable, "-c", "print('cryptnono.banned.string1')"])
    assert p.returncode == -9


# Test the non-BPF psutil scanner by starting a safe process, and changing it's
# cmdline to one that's banned
def test_self_changing_killed():
    p = run([os.path.join(os.path.dirname(__file__), "resources", "cryptnono-test-self-changing-cmdline")])
    assert p.returncode == -9
