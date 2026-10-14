using System.Text;

namespace SmartSwitch;

/// <summary>A broken rule; <see cref="Code"/> is the stable SW-* code of spec/SEMANTICS.md.</summary>
public sealed class SwitchError : Exception
{
    public string Code { get; }
    public SwitchError(string code, string message = "") : base(message.Length > 0 ? $"{code}: {message}" : code) { Code = code; Detail = message; }
    public string Detail { get; }
}

/// <summary>A proposal that passed the format check.</summary>
public sealed record Proposal(string FleetId, string FleetHash, long Seq, long Epoch, string Action, string Target,
    string? NewPublicKey, string Reason, long CreatedMs, long ExpiresMs);

/// <summary>The switch state (spec/SEMANTICS.md, "State"). Immutable: <see cref="Protocol.Apply"/> returns a new one.</summary>
public sealed record State
{
    public required string FleetId { get; init; }
    public required string FleetHash { get; init; }
    public required string CoordinatorKey { get; init; }
    public required int N { get; init; }
    public required long Threshold { get; init; }
    public required long MaxTtlMs { get; init; }
    public required long OfflineTimeoutMs { get; init; }
    /// <summary>keyholder id -> current public key</summary>
    public required SortedDictionary<string, string> Keys { get; init; }
    public SortedSet<string> Suspended { get; init; } = new(StringComparer.Ordinal);
    public long Seq { get; init; }
    public long Epoch { get; init; }
    public bool HaltedAll { get; init; }
    public SortedSet<string> Halted { get; init; } = new(StringComparer.Ordinal);
    /// <summary>agent id -> max_instances, or null without a roster</summary>
    public SortedDictionary<string, long>? Roster { get; init; }

    /// <summary>The state of a valid fleet before any certificate; throws SwitchError (SW-BAD-FLEET).</summary>
    public static State Genesis(object? fleet)
    {
        Protocol.ValidateFleet(fleet);
        var khs = Json.AsArr(Json.Get(fleet, "keyholders"))!;
        var keys = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var k in khs) keys[(string)Json.Get(k, "id")!] = (string)Json.Get(k, "public_key")!;
        SortedDictionary<string, long>? roster = null;
        if (Json.Get(fleet, "agents") is List<object?> agents)
        {
            roster = new SortedDictionary<string, long>(StringComparer.Ordinal);
            foreach (var a in agents) roster[(string)Json.Get(a, "id")!] = (long)Json.Get(a, "max_instances")!;
        }
        return new State
        {
            FleetId = (string)Json.Get(fleet, "fleet_id")!,
            FleetHash = Json.DocHash(fleet)!,
            CoordinatorKey = (string)Json.Get(fleet, "coordinator_key")!,
            N = khs.Count,
            Threshold = Json.Get(fleet, "threshold") is long t ? t : Protocol.DefaultThreshold(khs.Count),
            MaxTtlMs = (long)Json.Get(fleet, "proposal_max_ttl_ms")!,
            OfflineTimeoutMs = (long)Json.Get(fleet, "offline_timeout_ms")!,
            Keys = keys,
            Roster = roster,
        };
    }

    /// <summary>Keyholder ids that are not suspended, sorted.</summary>
    public List<string> Active => Keys.Keys.Where(k => !Suspended.Contains(k)).ToList();

    public bool MayRun(string agentId) => !HaltedAll && !Halted.Contains(agentId);

    /// <summary>The state as the vectors compare it.</summary>
    public SortedDictionary<string, object?> Summary()
    {
        List<object?> L(IEnumerable<string> s) => s.Select(x => (object?)x).ToList();
        var keys = Json.NewObj();
        foreach (var kv in Keys) keys[kv.Key] = kv.Value;
        return Json.Obj(("seq", Seq), ("epoch", Epoch), ("threshold", Threshold), ("halted_all", HaltedAll),
            ("halted", L(Halted)), ("active", L(Active)), ("suspended", L(Suspended)), ("keys", keys));
    }
}

/// <summary>The SmartSwitch protocol (spec/SEMANTICS.md): fleet validation, proposals, certificate checks and apply.
/// Deterministic: no clock, no randomness, no I/O; time comes in as at_ms.</summary>
public static class Protocol
{
    public const string VotePrefix = "smartswitch-vote-v1:";
    public const string HeartbeatPrefix = "smartswitch-heartbeat-v1:";
    public const int MaxKeyholders = 64;
    public const int MaxAgents = 100000;
    public const int MaxReasonBytes = 1000;
    public const long MaxInt = (1L << 53) - 1;

    static readonly string[] FleetFields = { "type", "version", "fleet_id", "keyholders", "threshold", "coordinator_key", "offline_timeout_ms", "proposal_max_ttl_ms", "agents" };
    static readonly string[] ProposalFields = { "type", "fleet_id", "fleet_hash", "seq", "epoch", "action", "target", "new_public_key", "reason", "created_ms", "expires_ms" };

    /// <summary>An id: 1 to 64 characters from A-Z a-z 0-9 . _ -</summary>
    public static bool IsId(object? v) => v is string s && s.Length is >= 1 and <= 64 &&
        s.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');

    /// <summary>2 for up to five keyholders; floor(n/2) + 1 above five.</summary>
    public static long DefaultThreshold(long n) => n <= 5 ? 2 : n / 2 + 1;

    /// <summary>Throws SwitchError (SW-BAD-FLEET) unless <paramref name="doc"/> is a valid fleet document.</summary>
    public static void ValidateFleet(object? doc)
    {
        static void Bad(string m) => throw new SwitchError("SW-BAD-FLEET", m);
        if (!Json.HasExactly(doc, FleetFields)) Bad("the fleet document must have exactly the fields of spec/SEMANTICS.md");
        if (Json.Get(doc, "type") as string != "smartswitch.fleet" || Json.Get(doc, "version") is not 1L) Bad("type must be \"smartswitch.fleet\" and version 1");
        if (!IsId(Json.Get(doc, "fleet_id"))) Bad("fleet_id must match [A-Za-z0-9._-]{1,64}");
        if (Json.Get(doc, "keyholders") is not List<object?> khs || khs.Count < 3 || khs.Count > MaxKeyholders) { Bad("keyholders must be a list of 3 to 64"); return; }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var kh in khs)
        {
            if (!Json.HasExactly(kh, "id", "public_key")) Bad("each keyholder must be {\"id\", \"public_key\"}");
            if (!IsId(Json.Get(kh, "id")) || !Ed25519.IsKeyHex(Json.Get(kh, "public_key"))) Bad("keyholder id must be an id and public_key 64 lower-case hex");
            var id = (string)Json.Get(kh, "id")!;
            var key = (string)Json.Get(kh, "public_key")!;
            if (ids.Contains(id) || keys.Contains(key)) Bad("keyholder ids and public keys must be unique");
            ids.Add(id);
            keys.Add(key);
        }
        var th = Json.Get(doc, "threshold");
        if (th != null && !Json.IntIn(th, 2, khs.Count - 1)) Bad("threshold must be null or an integer from 2 to n - 1");
        var ck = Json.Get(doc, "coordinator_key");
        if (!Ed25519.IsKeyHex(ck) || keys.Contains((string)ck!)) Bad("coordinator_key must be 64 lower-case hex and differ from every keyholder key");
        if (!Json.IntIn(Json.Get(doc, "offline_timeout_ms"), 1000, 3600000)) Bad("offline_timeout_ms must be an integer from 1000 to 3600000");
        if (!Json.IntIn(Json.Get(doc, "proposal_max_ttl_ms"), 1000, 86400000)) Bad("proposal_max_ttl_ms must be an integer from 1000 to 86400000");
        var agents = Json.Get(doc, "agents");
        if (agents == null) return;
        if (agents is not List<object?> al || al.Count > MaxAgents) { Bad("agents must be null or a list of at most 100000"); return; }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in al)
        {
            if (!Json.HasExactly(a, "id", "max_instances")) Bad("each agent must be {\"id\", \"max_instances\"}");
            var id = Json.Get(a, "id");
            if (!IsId(id) || !Json.IntIn(Json.Get(a, "max_instances"), 1, 1000) || seen.Contains((string)id!)) Bad("agent ids must be unique ids and max_instances 1 to 1000");
            seen.Add((string)id!);
        }
    }

    /// <summary>Throws SwitchError (SW-BAD-PROPOSAL) unless <paramref name="p"/> is a well-formed proposal.</summary>
    public static Proposal CheckProposalFormat(object? p)
    {
        static SwitchError Bad(string m) => new("SW-BAD-PROPOSAL", m);
        if (!Json.HasExactly(p, ProposalFields)) throw Bad("a proposal must have exactly the fields of spec/SEMANTICS.md");
        if (Json.Get(p, "type") as string != "smartswitch.proposal") throw Bad("type must be \"smartswitch.proposal\"");
        if (!IsId(Json.Get(p, "fleet_id")) || !Ed25519.IsKeyHex(Json.Get(p, "fleet_hash"))) throw Bad("fleet_id or fleet_hash is malformed");
        if (!Json.IntIn(Json.Get(p, "seq"), 1, MaxInt) || !Json.IntIn(Json.Get(p, "epoch"), 0, MaxInt)) throw Bad("seq must be an integer >= 1 and epoch >= 0");
        if (Json.Get(p, "action") is not ("halt" or "resume" or "suspend" or "reinstate")) throw Bad("action must be halt, resume, suspend or reinstate");
        var action = (string)Json.Get(p, "action")!;
        if (Json.Get(p, "target") is not string target) throw Bad("target must be a string");
        var nk = Json.Get(p, "new_public_key");
        if (action == "reinstate")
        {
            if (!Ed25519.IsKeyHex(nk)) throw Bad("reinstate needs new_public_key (64 lower-case hex)");
        }
        else if (nk != null) throw Bad("new_public_key must be null unless the action is reinstate");
        if (Json.Get(p, "reason") is not string reason || Encoding.UTF8.GetByteCount(reason) > MaxReasonBytes) throw Bad("reason must be a string of at most 1000 UTF-8 bytes");
        if (!Json.IntIn(Json.Get(p, "created_ms"), 0, MaxInt) || !Json.IntIn(Json.Get(p, "expires_ms"), 0, MaxInt)) throw Bad("created_ms and expires_ms must be integers >= 0");
        var created = (long)Json.Get(p, "created_ms")!;
        var expires = (long)Json.Get(p, "expires_ms")!;
        if (expires <= created) throw Bad("expires_ms must be after created_ms");
        return new Proposal((string)Json.Get(p, "fleet_id")!, (string)Json.Get(p, "fleet_hash")!, (long)Json.Get(p, "seq")!,
            (long)Json.Get(p, "epoch")!, action, target, nk as string, reason, created, expires);
    }

    /// <summary>doc_hash of a proposal (any JSON value; null when it has no canonical form).</summary>
    public static string? ProposalHash(object? p) => Json.DocHash(p);

    public static byte[] VoteMessage(string proposalHash) => Encoding.ASCII.GetBytes(VotePrefix + proposalHash);

    static void CheckCertificateFormat(object? c)
    {
        static SwitchError Bad(string m) => new("SW-BAD-CERTIFICATE", m);
        if (!Json.HasExactly(c, "type", "proposal", "votes")) throw Bad("a certificate must be {\"type\", \"proposal\", \"votes\"}");
        if (Json.Get(c, "type") as string != "smartswitch.certificate") throw Bad("type must be \"smartswitch.certificate\"");
        if (Json.Get(c, "votes") is not List<object?> votes || votes.Count < 1 || votes.Count > MaxKeyholders) throw Bad("votes must be a list of 1 to 64");
        foreach (var v in votes)
            if (!Json.HasExactly(v, "keyholder", "sig") || Json.Get(v, "keyholder") is not string || Json.Get(v, "sig") is not string)
                throw Bad("each vote must be {\"keyholder\": string, \"sig\": string}");
    }

    /// <summary>Check <paramref name="cert"/> against <paramref name="st"/> at <paramref name="atMs"/> (spec/SEMANTICS.md,
    /// "Certificate checks"); throws SwitchError with the first failing check's code. <paramref name="ahead"/> accepts any
    /// seq above the state's (a certificate delivered directly).</summary>
    public static Proposal VerifyCertificate(State st, object? cert, long atMs, bool ahead = false)
    {
        CheckCertificateFormat(cert);
        var pv = Json.Get(cert, "proposal");
        var p = CheckProposalFormat(pv);
        if (p.FleetId != st.FleetId || p.FleetHash != st.FleetHash) throw new SwitchError("SW-WRONG-FLEET", "the proposal is for another fleet");
        if (p.Seq <= st.Seq) throw new SwitchError("SW-STALE-SEQ", $"seq {p.Seq} is not after the current seq {st.Seq}");
        if (!ahead && p.Seq != st.Seq + 1) throw new SwitchError("SW-SEQ-GAP", $"seq {p.Seq} is not the next seq {st.Seq + 1}");
        if (p.Epoch != st.Epoch) throw new SwitchError("SW-WRONG-EPOCH", $"epoch {p.Epoch} is not the current epoch {st.Epoch}");
        if (p.ExpiresMs - p.CreatedMs > st.MaxTtlMs) throw new SwitchError("SW-BAD-PROPOSAL", "the proposal is valid for longer than proposal_max_ttl_ms");
        if (atMs >= p.ExpiresMs) throw new SwitchError("SW-EXPIRED", "the proposal has expired");
        CheckTarget(st, p);
        var msg = VoteMessage(ProposalHash(pv)!);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var v in (List<object?>)Json.Get(cert, "votes")!)
        {
            var kh = (string)Json.Get(v, "keyholder")!;
            if (!st.Keys.TryGetValue(kh, out var key)) throw new SwitchError("SW-UNKNOWN-KEYHOLDER", $"'{kh}' is not a keyholder of this fleet");
            if (!seen.Add(kh)) throw new SwitchError("SW-DUPLICATE-VOTE", $"'{kh}' voted twice");
            if (st.Suspended.Contains(kh)) throw new SwitchError("SW-SUSPENDED-KEYHOLDER", $"'{kh}' is suspended");
            if (p.Action == "suspend" && kh == p.Target) throw new SwitchError("SW-TARGET-VOTE", "a keyholder cannot vote on its own suspension");
            if (!Ed25519.Verify(key, msg, (string)Json.Get(v, "sig")!)) throw new SwitchError("SW-BAD-SIGNATURE", $"the signature of '{kh}' does not verify");
        }
        if (seen.Count < st.Threshold) throw new SwitchError("SW-NO-QUORUM", $"{seen.Count} valid votes, {st.Threshold} needed");
        return p;
    }

    static void CheckTarget(State st, Proposal p)
    {
        var t = p.Target;
        switch (p.Action)
        {
            case "halt":
            case "resume":
                if (t != "*" && !IsId(t)) throw new SwitchError("SW-BAD-TARGET", "target must be \"*\" or an agent id");
                break;
            case "suspend":
                if (!st.Keys.ContainsKey(t) || st.Suspended.Contains(t)) throw new SwitchError("SW-BAD-TARGET", "target must be an active keyholder");
                if (st.Active.Count - 1 < st.Threshold) throw new SwitchError("SW-QUORUM-IMPOSSIBLE", "suspending would leave fewer active keyholders than the threshold");
                break;
            default:
                if (!st.Suspended.Contains(t)) throw new SwitchError("SW-BAD-TARGET", "target must be a suspended keyholder");
                if (st.Keys.Values.Contains(p.NewPublicKey) || p.NewPublicKey == st.CoordinatorKey) throw new SwitchError("SW-BAD-TARGET", "new_public_key must be a key not used in this fleet");
                break;
        }
    }

    /// <summary>Verify <paramref name="cert"/> (seq must be st.Seq + 1) and return the next state; <paramref name="st"/> is not changed.</summary>
    public static State Apply(State st, object? cert, long atMs)
    {
        var p = VerifyCertificate(st, cert, atMs);
        var t = p.Target;
        var halted = new SortedSet<string>(st.Halted, StringComparer.Ordinal);
        var suspended = new SortedSet<string>(st.Suspended, StringComparer.Ordinal);
        var keys = new SortedDictionary<string, string>(st.Keys, StringComparer.Ordinal);
        var next = st with { Seq = st.Seq + 1 };
        switch (p.Action)
        {
            case "halt":
                if (t == "*") next = next with { HaltedAll = true };
                else halted.Add(t);
                break;
            case "resume":
                if (t == "*") { next = next with { HaltedAll = false }; halted.Clear(); }
                else halted.Remove(t);
                break;
            case "suspend":
                suspended.Add(t);
                next = next with { Epoch = st.Epoch + 1 };
                break;
            default:
                suspended.Remove(t);
                keys[t] = p.NewPublicKey!;
                next = next with { Epoch = st.Epoch + 1 };
                break;
        }
        return next with { Halted = halted, Suspended = suspended, Keys = keys };
    }
}
