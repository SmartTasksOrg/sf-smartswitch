#!/usr/bin/env python3
"""The Python reference's interop agent (see interop.py): URL FLEET_FILE AGENT_ID INSTANCE_ID."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'src'))

from sf_smartswitch.agent import Agent  # noqa: E402


def main():
    url, fleet, agent_id, inst = sys.argv[1:5]
    ag = Agent(url, os.environ.get('SMARTSWITCH_AGENT_TOKEN'), fleet, agent_id, inst, poll_ms=100, timeout_s=1)
    done = threading.Event()
    threading.Thread(target=lambda: (sys.stdin.read(), done.set()), daemon=True).start()
    last = None
    end = time.monotonic() + 60
    while not done.is_set() and time.monotonic() < end:
        code = ag.poll_once()['code']
        if code != last:
            print('STATUS ' + code, flush=True)
            last = code
        done.wait(0.1)


if __name__ == '__main__':
    main()
