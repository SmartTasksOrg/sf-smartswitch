import filecmp
import os
import subprocess
import sys

from sf_smartswitch._bundled import path
from sf_smartswitch.conformance import FILES, run_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, 'spec', 'conformance')


def test_all_vectors_pass():
    total, failures = run_dir(SPEC)
    assert failures == []
    assert total == 302


def test_vectors_are_what_the_generator_writes():
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'spec', 'tools', 'make_vectors.py'), '--check'],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_wheel_ships_the_same_vectors():
    for name in FILES:
        assert filecmp.cmp(os.path.join(SPEC, name), str(path('conformance', name)), shallow=False), name
    assert sorted(os.listdir(SPEC)) == sorted(FILES)
