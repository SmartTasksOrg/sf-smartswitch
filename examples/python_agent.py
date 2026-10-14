"""An agent loop under SmartSwitch, in-process.

    SMARTSWITCH_AGENT_TOKEN=... python examples/python_agent.py https://switch.internal fleet.json planner

The process wrapper (sf-smartswitch agent ... -- program) is stronger: it stops the program without its
cooperation. Use this form when the program wants to stop cleanly between its own steps.
"""
import os
import sys
import time

from sf_smartswitch import Agent, Halted


def step(i):
    print(f'step {i}', flush=True)
    time.sleep(1)


def main():
    url, fleet, agent_id = sys.argv[1:4]
    agent = Agent(url, os.environ.get('SMARTSWITCH_AGENT_TOKEN'), fleet, agent_id,
                  on_change=lambda s: print('switch:', s['code'], flush=True)).start()
    if not agent.wait_until_running(30):
        sys.exit(f'not starting: {agent.status()["code"]}')
    i = 0
    try:
        while True:
            agent.checkpoint()       # raises Halted when the switch says stop
            step(i)
            i += 1
    except Halted as e:
        print(f'stopped cleanly: {e.code}')
        sys.exit(75)
    finally:
        agent.stop()


if __name__ == '__main__':
    main()
