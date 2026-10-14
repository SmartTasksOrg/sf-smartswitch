"""Prometheus metrics in the text exposition format, with no dependency.

smartswitch_votes_total{result}             counter    votes received: accepted / rejected / duplicate
smartswitch_certificates_total{action}      counter    certificates applied (halt / resume / suspend / reinstate)
smartswitch_rejected_total{code}            counter    votes and certificates refused, by SW-* code
smartswitch_aggregation_ms                  histogram  quorum-completing vote received -> certificate written to the log
smartswitch_propagation_ms                  histogram  halt written -> every live agent instance has fetched it
smartswitch_watchdog_alerts_total{kind}     counter    aggregation-slow / aggregation-spike
smartswitch_replication_alerts_total{reason} counter   unknown-agent / too-many-instances
smartswitch_heartbeats_total{result}        counter    ok / refused
smartswitch_instances_live                  gauge      agent instances heard from within the offline timeout
smartswitch_halted                          gauge      1 while the whole fleet is halted
smartswitch_agents_halted                   gauge      agents halted one by one
smartswitch_log_entries                     gauge      entries in the log
smartswitch_log_mirror_ok                   gauge      1 if the last mirror check found both files identical, 0 if not, -1 no mirror
smartswitch_sign_verify_ms                  histogram  time to verify one certificate (all its signatures)
"""
from __future__ import annotations

import threading

LATENCY_MS_BUCKETS = (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 1000)
OVERRIDE_MS_BUCKETS = (10, 50, 100, 250, 500, 1000, 2500, 5000, 10000)
LOCK_S_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1, 5)


def _fmt(v: float) -> str:
    return repr(float(v)) if v != int(v) else str(int(v))


class Counter:
    def __init__(self, name, help_, labels=()):
        self.name, self.help, self.labels = name, help_, labels
        self._v: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def inc(self, amount=1, **labels):
        key = tuple(labels.get(k, '') for k in self.labels)
        with self._lock:
            self._v[key] = self._v.get(key, 0) + amount

    def value(self, **labels):
        return self._v.get(tuple(labels.get(k, '') for k in self.labels), 0)

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} counter']
        items = sorted(self._v.items())
        if not items and not self.labels:
            items = [((), 0)]
        for key, v in items:
            lab = ','.join(f'{k}="{x}"' for k, x in zip(self.labels, key))
            out.append(f'{self.name}{{{lab}}} {_fmt(v)}' if lab else f'{self.name} {_fmt(v)}')
        return out


class Histogram:
    def __init__(self, name, help_, buckets):
        self.name, self.help, self.buckets = name, help_, tuple(buckets)
        self._counts = [0] * len(self.buckets)
        self._sum, self._n = 0.0, 0
        self._obs: list[float] = []          # kept for percentiles in the benchmark (bounded)
        self._lock = threading.Lock()

    def observe(self, v):
        with self._lock:
            for i, b in enumerate(self.buckets):
                if v <= b:
                    self._counts[i] += 1
            self._sum += v
            self._n += 1
            if len(self._obs) < 200000:
                self._obs.append(v)

    @property
    def count(self):
        return self._n

    def percentile(self, q):
        with self._lock:
            xs = sorted(self._obs)
        if not xs:
            return 0.0
        return xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]

    def expose(self):
        out = [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} histogram']
        for b, c in zip(self.buckets, self._counts):
            out.append(f'{self.name}_bucket{{le="{_fmt(b)}"}} {c}')
        out.append(f'{self.name}_bucket{{le="+Inf"}} {self._n}')
        out.append(f'{self.name}_sum {_fmt(self._sum) if self._sum else 0}')
        out.append(f'{self.name}_count {self._n}')
        return out


class Gauge:
    def __init__(self, name, help_):
        self.name, self.help, self.v = name, help_, 0

    def set(self, v):
        self.v = v

    def expose(self):
        return [f'# HELP {self.name} {self.help}', f'# TYPE {self.name} gauge', f'{self.name} {_fmt(self.v)}']


AGG_MS_BUCKETS = (1, 2.5, 5, 10, 25, 50, 100, 150, 200, 250, 500, 1000)
PROP_MS_BUCKETS = (10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000)
VERIFY_MS_BUCKETS = (0.1, 0.25, 0.5, 1, 2, 5, 10, 25)


class Metrics:
    def __init__(self):
        self.votes = Counter('smartswitch_votes_total', 'Votes received, by result.', ('result',))
        self.certificates = Counter('smartswitch_certificates_total', 'Certificates applied, by action.', ('action',))
        self.rejected = Counter('smartswitch_rejected_total', 'Votes and certificates refused, by code.', ('code',))
        self.aggregation = Histogram('smartswitch_aggregation_ms', 'Quorum-completing vote to certificate in the log, in milliseconds.', AGG_MS_BUCKETS)
        self.propagation = Histogram('smartswitch_propagation_ms', 'Halt in the log to every live instance having fetched it, in milliseconds.', PROP_MS_BUCKETS)
        self.watchdog = Counter('smartswitch_watchdog_alerts_total', 'Watchdog alerts, by kind.', ('kind',))
        self.replication = Counter('smartswitch_replication_alerts_total', 'Replication alerts, by reason.', ('reason',))
        self.heartbeats = Counter('smartswitch_heartbeats_total', 'Heartbeats answered or refused.', ('result',))
        self.instances_live = Gauge('smartswitch_instances_live', 'Agent instances heard from within the offline timeout.')
        self.halted = Gauge('smartswitch_halted', '1 while the whole fleet is halted.')
        self.agents_halted = Gauge('smartswitch_agents_halted', 'Agents halted one by one.')
        self.log_entries = Gauge('smartswitch_log_entries', 'Entries in the log.')
        self.mirror_ok = Gauge('smartswitch_log_mirror_ok', '1 mirror identical, 0 mismatch, -1 no mirror.')
        self.mirror_ok.set(-1)
        self.verify_ms = Histogram('smartswitch_sign_verify_ms', 'Time to verify one certificate, in milliseconds.', VERIFY_MS_BUCKETS)

    def expose(self) -> str:
        lines = []
        for m in (self.votes, self.certificates, self.rejected, self.aggregation, self.propagation, self.watchdog,
                  self.replication, self.heartbeats, self.instances_live, self.halted, self.agents_halted,
                  self.log_entries, self.mirror_ok, self.verify_ms):
            lines += m.expose()
        return '\n'.join(lines) + '\n'
