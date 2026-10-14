using System.Text;

namespace SmartSwitch;

/// <summary>What an agent believes, and whether it may run: the agent-side rules without any I/O
/// (spec/SEMANTICS.md, "Agent"). Times for heartbeats and status are the agent's own monotonic milliseconds; the
/// time for a delivered certificate is wall-clock milliseconds (it is compared with expires_ms).</summary>
public sealed class AgentView
{
    static readonly string[] HeartbeatFields = { "type", "fleet_hash", "agent_id", "instance_id", "nonce", "log_size", "head", "issued_ms", "sig" };

    public object? Fleet { get; }
    public string FleetHash { get; }
    public string CoordinatorKey { get; }
    public string AgentId { get; }
    public string InstanceId { get; }
    public Replica Replica { get; }
    public long? LastOkMs { get; private set; }
    /// <summary>Directly delivered halts not yet ended by the log: proposal hash -> seq.</summary>
    public SortedDictionary<string, long> Provisional { get; } = new(StringComparer.Ordinal);
    public bool Fork { get; private set; }

    /// <summary><paramref name="fleet"/> must be a valid fleet document; the ids must be ids.</summary>
    public AgentView(object? fleet, string agentId, string instanceId)
    {
        if (!Protocol.IsId(agentId) || !Protocol.IsId(instanceId)) throw new ArgumentException("agent_id and instance_id must match [A-Za-z0-9._-]{1,64}");
        Protocol.ValidateFleet(fleet);
        Fleet = fleet;
        FleetHash = Json.DocHash(fleet)!;
        CoordinatorKey = (string)Json.Get(fleet, "coordinator_key")!;
        AgentId = agentId;
        InstanceId = instanceId;
        Replica = new Replica(FleetHash);
    }

    /// <summary>The signed message of a heartbeat: prefix + doc_hash(heartbeat without "sig"); null without a canonical form.</summary>
    public static byte[]? HeartbeatMessage(object? hb)
    {
        if (Json.AsObj(hb) is not { } o) return null;
        var m = new SortedDictionary<string, object?>(o, StringComparer.Ordinal);
        m.Remove("sig");
        var h = Json.DocHash(m);
        return h == null ? null : Encoding.ASCII.GetBytes(Protocol.HeartbeatPrefix + h);
    }

    static SortedDictionary<string, object?> Res(bool ok, string code) => Json.Obj(("ok", ok), ("code", code));

    /// <summary>Entries that continue the local copy, appended one at a time: {ok: true, size} or {ok: false, code, size}
    /// (entries before the bad one are kept). A provisional halt ends when the log applies that same proposal, or a resume
    /// of "*" or of this agent with a higher seq; another certificate taking its seq does not end it.</summary>
    public SortedDictionary<string, object?> Log(IEnumerable<object?> entries)
    {
        foreach (var e in entries)
        {
            try { Replica.Extend(new[] { e }); }
            catch (SwitchError err) { return Json.Obj(("ok", false), ("code", err.Code), ("size", (long)Replica.Size)); }
            if (Provisional.Count > 0 && Json.Get(e, "kind") as string == "certificate")
            {
                // The entry was applied, so its proposal is well-formed.
                var p = Json.Get(Json.Get(e, "body"), "proposal");
                if (Protocol.ProposalHash(p) is { } ph) Provisional.Remove(ph);
                var target = Json.Get(p, "target") as string;
                if (Json.Get(p, "action") as string == "resume" && (target == "*" || target == AgentId) && Json.Get(p, "seq") is long seq)
                    foreach (var h in Provisional.Where(kv => kv.Value < seq).Select(kv => kv.Key).ToList()) Provisional.Remove(h);
            }
        }
        return Json.Obj(("ok", true), ("size", (long)Replica.Size));
    }

    /// <summary>A heartbeat answering <paramref name="nonce"/>, which the agent sent at <paramref name="atMs"/>: {ok, code}.</summary>
    public SortedDictionary<string, object?> Heartbeat(object? hb, string nonce, long atMs)
    {
        var code = CheckHeartbeat(hb, nonce);
        if (code == null)
        {
            var size = (long)Json.Get(hb, "log_size")!;
            if (Replica.Size >= size)
            {
                if (Replica.Hashes[(int)(size - 1)] != Json.Get(hb, "head") as string)
                {
                    Fork = true;
                    code = "SW-FORK";
                }
            }
            else code = "SW-BEHIND";
        }
        if (code != null) return Res(false, code);
        LastOkMs = LastOkMs == null ? atMs : Math.Max(LastOkMs.Value, atMs);
        return Res(true, "SW-OK");
    }

    string? CheckHeartbeat(object? hb, string nonce)
    {
        if (!Json.HasExactly(hb, HeartbeatFields) || Json.Get(hb, "type") as string != "smartswitch.heartbeat"
            || !Json.IntIn(Json.Get(hb, "log_size"), 1, Protocol.MaxInt) || !Ed25519.IsKeyHex(Json.Get(hb, "head"))
            || !Json.IntIn(Json.Get(hb, "issued_ms"), 0, Protocol.MaxInt))
            return "SW-BAD-HEARTBEAT";
        var msg = HeartbeatMessage(hb);
        if (msg == null || !Ed25519.Verify(CoordinatorKey, msg, Json.Get(hb, "sig") as string)) return "SW-BAD-HEARTBEAT";
        if (Json.Get(hb, "fleet_hash") as string != FleetHash) return "SW-WRONG-FLEET";
        if (Json.Get(hb, "agent_id") as string != AgentId || Json.Get(hb, "instance_id") as string != InstanceId) return "SW-WRONG-AGENT";
        if (!Ed25519.IsLowerHex(nonce, 32) || Json.Get(hb, "nonce") as string != nonce) return "SW-NONCE";
        return null;
    }

    /// <summary>A certificate delivered directly (not through the log), checked at wall-clock time <paramref name="atMs"/>:
    /// {ok, code}. Only a valid halt of this agent or of the whole fleet has an effect: a provisional halt (see
    /// <see cref="Log"/> for when it ends).</summary>
    public SortedDictionary<string, object?> Certificate(object? cert, long atMs)
    {
        if (Replica.State is not { } st) return Res(false, "SW-NO-STATE");
        Proposal p;
        try { p = Protocol.VerifyCertificate(st, cert, atMs, ahead: true); }
        catch (SwitchError e) { return Res(false, e.Code); }
        if (p.Action != "halt" || (p.Target != "*" && p.Target != AgentId)) return Res(false, "SW-NOT-APPLICABLE");
        Provisional[Protocol.ProposalHash(Json.Get(cert, "proposal"))!] = p.Seq;
        return Res(true, "SW-PROVISIONAL-HALT");
    }

    /// <summary>The status code at <paramref name="atMs"/>; the first matching reason wins. SW-RUN when the agent may run.</summary>
    public string StatusCode(long atMs)
    {
        var st = Replica.State;
        if (Fork) return "SW-FORK";
        if (st != null && st.HaltedAll) return "SW-HALTED-FLEET";
        if (st != null && st.Halted.Contains(AgentId)) return "SW-HALTED-AGENT";
        if (Provisional.Count > 0) return "SW-PROVISIONAL-HALT";
        if (LastOkMs == null || st == null) return "SW-NO-HEARTBEAT";
        if (atMs - LastOkMs.Value >= st.OfflineTimeoutMs) return "SW-OFFLINE";
        return "SW-RUN";
    }

    /// <summary>{run, code}.</summary>
    public SortedDictionary<string, object?> Status(long atMs)
    {
        var code = StatusCode(atMs);
        return Json.Obj(("run", code == "SW-RUN"), ("code", code));
    }
}
