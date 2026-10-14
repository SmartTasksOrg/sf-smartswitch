namespace SmartSwitch;

/// <summary>A verified copy of a log (spec/SEMANTICS.md, "Log"). <see cref="Extend"/> checks entries one by one and
/// applies certificates; on the first bad entry it throws SwitchError and keeps everything before it.</summary>
public sealed class Replica
{
    public const string GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000";
    static readonly string[] EntryFields = { "n", "ts_ms", "kind", "body", "prev", "hash" };

    /// <summary>null: accept any genesis.</summary>
    public string? Pinned { get; }
    public State? State { get; private set; }
    public int Size { get; private set; }
    public string Head { get; private set; } = GenesisPrev;
    /// <summary>Every entry's hash, to compare with heartbeats.</summary>
    public List<string> Hashes { get; } = new();

    public Replica(string? pinned = null) { Pinned = pinned; }

    /// <summary>doc_hash of the entry without its "hash" field; null when it has no canonical form.</summary>
    public static string? EntryHash(object? e)
    {
        if (Json.AsObj(e) is not { } o) return null;
        var m = new SortedDictionary<string, object?>(o, StringComparer.Ordinal);
        m.Remove("hash");
        return Json.DocHash(m);
    }

    public int Extend(IEnumerable<object?> entries)
    {
        foreach (var e in entries) One(e);
        return Size;
    }

    void One(object? e)
    {
        var i = Size;
        var kind = Json.Get(e, "kind") as string;
        if (!Json.HasExactly(e, EntryFields) || kind is not ("genesis" or "certificate" or "event") || Json.Get(e, "body") is not SortedDictionary<string, object?> body
            || Json.Get(e, "n") is not long n || Json.Get(e, "ts_ms") is not long ts || ts < 0)
            throw new SwitchError("SW-BAD-ENTRY", $"entry {i} is malformed");
        // ts_ms is the coordinator's unsigned wall clock and need not increase (spec/SEMANTICS.md, "Log").
        if (n != i) throw new SwitchError("SW-LOG-ORDER", $"entry {i}: n is {n}");
        var hash = Json.Get(e, "hash") as string;
        if (Json.Get(e, "prev") as string != Head || hash == null || EntryHash(e) != hash)
            throw new SwitchError("SW-LOG-CHAIN", $"entry {i}: the hash chain is broken");
        var next = State;
        if (i == 0)
        {
            if (kind != "genesis") throw new SwitchError("SW-BAD-ENTRY", "entry 0 must be the genesis");
            try { Protocol.ValidateFleet(body); }
            catch (SwitchError err) { throw new SwitchError("SW-BAD-FLEET", "entry 0: " + err.Detail); }
            if (Pinned != null && Json.DocHash(body) != Pinned) throw new SwitchError("SW-WRONG-FLEET", "entry 0 is not the pinned fleet");
            next = State.Genesis(body);
        }
        else if (kind == "genesis") throw new SwitchError("SW-BAD-ENTRY", $"entry {i}: only entry 0 can be a genesis");
        else if (kind == "certificate") next = Protocol.Apply(State!, body, ts);
        State = next;
        Size++;
        Head = hash;
        Hashes.Add(hash);
    }
}

public static class Log
{
    /// <summary>{"ok": true, "size", "head", "state"} or {"ok": false, "index", "code"} (the vectors' form).</summary>
    public static SortedDictionary<string, object?> Replay(IEnumerable<object?> entries, string? pinned = null)
    {
        var r = new Replica(pinned);
        try { r.Extend(entries); }
        catch (SwitchError e) { return Json.Obj(("ok", false), ("index", (long)r.Size), ("code", e.Code)); }
        if (r.Size == 0) return Json.Obj(("ok", false), ("index", 0L), ("code", "SW-BAD-ENTRY"));
        return Json.Obj(("ok", true), ("size", (long)r.Size), ("head", r.Head), ("state", r.State!.Summary()));
    }
}
