"""SmartSwitch: a quorum kill switch for fleets of AI agents.

No single keyholder can halt the fleet, and no single keyholder can stop a halt: every halt, resume
and keyholder change needs a quorum of Ed25519 signatures, every agent checks them itself, and every
step is in a hash-chained log. Agents that lose contact with the coordinator stop by themselves.
"""
from ._version import __version__
from .agent import Agent, Halted, run_guarded
from .agentview import AgentView
from .coordinator import Coordinator
from .protocol import State, SwitchError, apply, default_threshold, validate_fleet, verify_certificate

__all__ = ['__version__', 'Agent', 'AgentView', 'Coordinator', 'Halted', 'State', 'SwitchError', 'apply',
           'default_threshold', 'run_guarded', 'validate_fleet', 'verify_certificate']
