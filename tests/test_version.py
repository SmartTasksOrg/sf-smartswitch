import json
import os
import re

from sf_smartswitch import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_one_version_everywhere():
    py = re.search(r'^version = "([^"]+)"', open(os.path.join(ROOT, 'pyproject.toml'), encoding='utf-8').read(), re.M).group(1)
    smart = json.load(open(os.path.join(ROOT, '.smart.json'), encoding='utf-8'))['version']
    node = json.load(open(os.path.join(ROOT, 'ports', 'node', 'package.json'), encoding='utf-8'))['version']
    assert py == __version__ == smart == node
    assert f'## {py}' in open(os.path.join(ROOT, 'CHANGELOG.md'), encoding='utf-8').read()
