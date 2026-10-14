package cloud.smarttasks.smartswitch;

import cloud.smarttasks.smartswitch.SmartSwitch.Replica;
import cloud.smarttasks.smartswitch.SmartSwitch.State;
import cloud.smarttasks.smartswitch.SmartSwitch.SwitchError;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What an agent believes, and whether it may run: the agent-side rules of SEMANTICS.md ("Agent"),
 * without any I/O. Times for heartbeats and status are the agent's own monotonic milliseconds; the time
 * for a delivered certificate is wall-clock milliseconds. Not thread-safe: {@link Agent}
 * serialises access.
 */
public final class AgentView {
    private static final Set<String> HEARTBEAT_FIELDS = Set.of("type", "fleet_hash", "agent_id", "instance_id", "nonce",
        "log_size", "head", "issued_ms", "sig");

    public final Map<String, Object> fleet;
    public final String fleetHash, agentId, instanceId;
    public final Replica replica;
    private Long lastOkMs;
    /** proposal hash -> seq of halts delivered directly that the log has not yet settled */
    private final Map<String, Long> provisional = new HashMap<>();
    private boolean fork;

    /** @param fleet the fleet document the agent was deployed with (validated by the caller, see Agent.loadFleet) */
    public AgentView(Map<String, Object> fleet, String agentId, String instanceId) {
        if (!SmartSwitch.isId(agentId) || !SmartSwitch.isId(instanceId)) {
            throw new IllegalArgumentException("agent_id and instance_id must match [A-Za-z0-9._-]{1,64}");
        }
        this.fleet = fleet;
        this.fleetHash = SmartSwitch.docHash(fleet);
        this.agentId = agentId;
        this.instanceId = instanceId;
        this.replica = new Replica(fleetHash);
    }

    private static Map<String, Object> res(String k1, Object v1, String k2, Object v2) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k1, v1);
        m.put(k2, v2);
        return m;
    }

    /** Entries that continue the local copy, appended one at a time: {ok, size} or {ok, code, size}
     *  (entries before the first bad one are kept). A provisional halt ends when the log applies that same
     *  proposal, or a later resume of "*" or of this agent; another certificate taking its seq does not end it. */
    public Map<String, Object> log(Object entries) {
        if (!(entries instanceof List<?> list)) return logFailed("SW-BAD-ENTRY");
        for (Object e : list) {
            try {
                replica.extend(Collections.singletonList(e));
            } catch (SwitchError err) {
                return logFailed(err.code);
            }
            Map<String, Object> entry = SmartSwitch.map(e);
            if (!provisional.isEmpty() && "certificate".equals(entry.get("kind"))) {
                Map<String, Object> p = SmartSwitch.map(SmartSwitch.map(entry.get("body")).get("proposal"));
                provisional.remove(SmartSwitch.proposalHash(p));
                Object t = p.get("target");
                if ("resume".equals(p.get("action")) && ("*".equals(t) || agentId.equals(t))) {
                    long seq = (Long) p.get("seq");
                    provisional.values().removeIf(q -> q < seq);
                }
            }
        }
        return res("ok", true, "size", (long) replica.size);
    }

    private Map<String, Object> logFailed(String code) {
        Map<String, Object> m = res("ok", false, "code", code);
        m.put("size", (long) replica.size);
        return m;
    }

    static byte[] heartbeatMessage(Map<String, Object> hb) {
        Map<String, Object> body = new LinkedHashMap<>(hb);
        body.remove("sig");
        return (SmartSwitch.HEARTBEAT_PREFIX + SmartSwitch.docHash(body)).getBytes(StandardCharsets.US_ASCII);
    }

    /** A heartbeat answering {@code nonce}, which the agent sent at {@code atMs}: {ok, code}. */
    public Map<String, Object> heartbeat(Object hb, String nonce, long atMs) {
        String code = checkHeartbeat(hb, nonce);
        if (code == null) {
            long size = (Long) SmartSwitch.map(hb).get("log_size");
            if (replica.size >= size) {
                if (!replica.hashAt((int) (size - 1)).equals(SmartSwitch.map(hb).get("head"))) {
                    fork = true;
                    code = "SW-FORK";
                }
            } else {
                code = "SW-BEHIND";
            }
        }
        if (code == null) {
            lastOkMs = lastOkMs == null ? atMs : Math.max(lastOkMs, atMs);
            return res("ok", true, "code", "SW-OK");
        }
        return res("ok", false, "code", code);
    }

    private String checkHeartbeat(Object o, String nonce) {
        if (!SmartSwitch.exactly(o, HEARTBEAT_FIELDS)) return "SW-BAD-HEARTBEAT";
        Map<String, Object> hb = SmartSwitch.map(o);
        if (!"smartswitch.heartbeat".equals(hb.get("type")) || !SmartSwitch.isInt(hb.get("log_size"), 1, SmartSwitch.MAX_INT)
            || !SmartSwitch.isKeyHex(hb.get("head")) || !SmartSwitch.isInt(hb.get("issued_ms"), 0, SmartSwitch.MAX_INT)) {
            return "SW-BAD-HEARTBEAT";
        }
        byte[] msg;
        try {
            msg = heartbeatMessage(hb);
        } catch (IllegalArgumentException e) {   // no canonical form: it cannot carry a valid signature
            return "SW-BAD-HEARTBEAT";
        }
        if (!SmartSwitch.verify(fleet.get("coordinator_key"), msg, hb.get("sig"))) return "SW-BAD-HEARTBEAT";
        if (!fleetHash.equals(hb.get("fleet_hash"))) return "SW-WRONG-FLEET";
        if (!agentId.equals(hb.get("agent_id")) || !instanceId.equals(hb.get("instance_id"))) return "SW-WRONG-AGENT";
        if (nonce == null || !SmartSwitch.NONCE.matcher(nonce).matches() || !nonce.equals(hb.get("nonce"))) return "SW-NONCE";
        return null;
    }

    /** A certificate delivered directly (not through the log), checked at WALL-CLOCK time {@code atMs}
     *  (it is compared with expires_ms): {ok, code}. Only a valid halt of this agent or of the whole fleet,
     *  newer than the local state, has an effect: a provisional halt (see {@link #log} for when it ends). */
    public Map<String, Object> certificate(Object cert, long atMs) {
        State st = replica.state;
        if (st == null) return res("ok", false, "code", "SW-NO-STATE");
        Map<String, Object> p;
        try {
            p = SmartSwitch.verifyCertificate(st, cert, atMs, true);
        } catch (SwitchError e) {
            return res("ok", false, "code", e.code);
        }
        Object t = p.get("target");
        if (!"halt".equals(p.get("action")) || !("*".equals(t) || agentId.equals(t))) return res("ok", false, "code", "SW-NOT-APPLICABLE");
        provisional.put(SmartSwitch.proposalHash(p), (Long) p.get("seq"));
        return res("ok", true, "code", "SW-PROVISIONAL-HALT");
    }

    /** {run, code}: the first matching reason in the order of SEMANTICS.md wins. */
    public Map<String, Object> status(long atMs) {
        State st = replica.state;
        String code;
        if (fork) code = "SW-FORK";
        else if (st != null && st.haltedAll) code = "SW-HALTED-FLEET";
        else if (st != null && st.isHalted(agentId)) code = "SW-HALTED-AGENT";
        else if (!provisional.isEmpty()) code = "SW-PROVISIONAL-HALT";
        else if (lastOkMs == null || st == null) code = "SW-NO-HEARTBEAT";
        else if (atMs - lastOkMs >= st.offlineTimeoutMs) code = "SW-OFFLINE";
        else return res("run", true, "code", "SW-RUN");
        return res("run", false, "code", code);
    }
}
