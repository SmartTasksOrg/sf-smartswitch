"""Private key files. One JSON object: {"type": "smartswitch.key", "name", "public_key", "seed"}.

The file is created with mode 0600 and never overwritten. Whoever reads it can vote as its owner:
keep it on the keyholder's own device (or a hardware token, outside this tool's scope), never in a
repository (the .gitignore ignores *.key) and never on the coordinator, except the coordinator's own key.
"""
from __future__ import annotations

import json
import os

from . import ed25519


def create(path: str, name: str) -> str:
    seed = ed25519.new_seed()
    pub = ed25519.public_key(seed)
    data = json.dumps({'type': 'smartswitch.key', 'name': name, 'public_key': pub, 'seed': seed.hex()}) + '\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data)
    return pub


def load(path: str) -> tuple[str, bytes]:
    """(name, seed). Refuses a file whose public key does not match its seed."""
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    if not isinstance(d, dict) or d.get('type') != 'smartswitch.key' or not isinstance(d.get('seed'), str) \
            or len(d['seed']) != 64:
        raise ValueError(f'{path} is not a SmartSwitch key file')
    seed = bytes.fromhex(d['seed'])
    if ed25519.public_key(seed) != d.get('public_key'):
        raise ValueError(f'{path}: public_key does not match the seed')
    return str(d.get('name', '')), seed
