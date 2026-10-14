using System.Text;
using SmartSwitch;

// Runs spec/conformance against the .NET port: dotnet run -c Release --project Conformance -- <vectors dir>
// Prints each failure and a last line "csharp: N/N vectors passed"; exit 1 on any failure.
// With --time it also prints the time of one Ed25519 verify.
var dir = args.FirstOrDefault(a => a != "--time") ?? "../../spec/conformance";
object? Load(string n) => Json.Parse(File.ReadAllText(Path.Combine(dir, n)));
List<object?> Cases(object? v) => (List<object?>)Json.Get(v, "cases")!;
string S(object? v, string k) => (string)Json.Get(v, k)!;
long I(object? v, string k) => (long)Json.Get(v, k)!;
string Show(object? v)
{
    string t;
    try { t = Json.Canonical(v); } catch (ArgumentException) { t = v?.ToString() ?? "null"; }
    return t.Length > 300 ? t[..300] : t;
}
SortedDictionary<string, object?> Pick(object? c, params string[] keys)
{
    var o = Json.NewObj();
    foreach (var k in keys) if (Json.AsObj(c)!.TryGetValue(k, out var x)) o[k] = x;
    return o;
}
SortedDictionary<string, object?> Err(string code) => Json.Obj(("ok", false), ("code", code));

var total = 0;
var fails = new List<string>();
void Check(string name, object? got, object? want)
{
    total++;
    if (!Json.DeepEquals(got, want)) fails.Add($"{name}: got {Show(got)}, want {Show(want)}");
}

foreach (var c in Cases(Load("canonical.json")))
{
    object? got;
    try
    {
        var text = Json.Canonical(Json.Get(c, "input"));
        got = new List<object?> { text, Json.Sha256Hex(Encoding.UTF8.GetBytes(text)) };
    }
    catch (ArgumentException e) { got = "error: " + e.Message; }
    Check("canonical/" + S(c, "name"), got, new List<object?> { Json.Get(c, "canonical"), Json.Get(c, "sha256") });
}

foreach (var c in Cases(Load("ed25519.json")))
    Check("ed25519/" + S(c, "name"), Ed25519.Verify(S(c, "public_key"), Convert.FromHexString(S(c, "message_hex")), S(c, "sig")), Json.Get(c, "valid"));

var fleets = Load("fleets.json");
foreach (var c in (List<object?>)Json.Get(fleets, "default_thresholds")!)
    Check($"fleets/default threshold n={I(c, "n")}", Protocol.DefaultThreshold(I(c, "n")), Json.Get(c, "k"));
foreach (var c in Cases(fleets))
{
    var fleet = Json.Get(c, "fleet");
    object got;
    try
    {
        Protocol.ValidateFleet(fleet);
        got = Json.Obj(("ok", true), ("fleet_hash", Json.DocHash(fleet)), ("threshold", State.Genesis(fleet).Threshold));
    }
    catch (SwitchError e) { got = Err(e.Code); }
    Check("fleets/" + S(c, "name"), got, Pick(c, "ok", "fleet_hash", "threshold", "code"));
}

var certs = Load("certificates.json");
foreach (var c in Cases(certs))
{
    var name = S(c, "name");
    var st = State.Genesis(Json.Get(Json.Get(certs, "fleets"), S(c, "fleet")));
    foreach (var s in (List<object?>)Json.Get(c, "setup")!) st = Protocol.Apply(st, Json.Get(s, "certificate"), I(s, "at_ms"));
    var cert = Json.Get(c, "certificate");
    var ph = Json.AsObj(cert) is { } co && co.TryGetValue("proposal", out var pv) ? Protocol.ProposalHash(pv) : null;
    Check($"certificates/{name} (proposal hash)", ph, Json.Get(c, "proposal_hash"));
    object got;
    try
    {
        if (Json.Get(c, "ahead") is true)
        {
            Protocol.VerifyCertificate(st, cert, I(c, "at_ms"), ahead: true);
            got = Json.Obj(("ok", true), ("state", null));
        }
        else got = Json.Obj(("ok", true), ("state", Protocol.Apply(st, cert, I(c, "at_ms")).Summary()));
    }
    catch (SwitchError e) { got = Err(e.Code); }
    Check("certificates/" + name, got, Pick(c, "ok", "state", "code"));
}

foreach (var c in Cases(Load("logs.json")))
    Check("logs/" + S(c, "name"), Log.Replay((List<object?>)Json.Get(c, "entries")!, Json.Get(c, "pinned") as string), Json.Get(c, "result"));

var agent = Load("agent.json");
foreach (var c in Cases(agent))
{
    var view = new AgentView(Json.Get(agent, "fleet"), S(c, "agent_id"), S(c, "instance_id"));
    var steps = (List<object?>)Json.Get(c, "steps")!;
    for (var i = 0; i < steps.Count; i++)
    {
        var s = steps[i];
        var op = S(s, "op");
        var got = op switch
        {
            "log" => view.Log((List<object?>)Json.Get(s, "entries")!),
            "heartbeat" => view.Heartbeat(Json.Get(s, "heartbeat"), S(s, "nonce"), I(s, "at_ms")),
            "certificate" => view.Certificate(Json.Get(s, "certificate"), I(s, "at_ms")),
            _ => view.Status(I(s, "at_ms")),
        };
        Check($"agent/{S(c, "name")} step {i} ({op})", got, Json.Get(s, "expect"));
    }
}

if (args.Contains("--time"))
{
    var c = Cases(Load("ed25519.json")).First(x => S(x, "name") == "rfc8032 test 3");
    var msg = Convert.FromHexString(S(c, "message_hex"));
    for (var i = 0; i < 20; i++) Ed25519.Verify(S(c, "public_key"), msg, S(c, "sig"));
    var sw = System.Diagnostics.Stopwatch.StartNew();
    const int n = 200;
    for (var i = 0; i < n; i++) Ed25519.Verify(S(c, "public_key"), msg, S(c, "sig"));
    Console.WriteLine($"one Ed25519 verify: {sw.Elapsed.TotalMilliseconds / n:F3} ms");
}

foreach (var f in fails) Console.WriteLine("FAIL " + f);
if (fails.Count > 0) { Console.WriteLine($"csharp: {fails.Count} of {total} vectors failed"); return 1; }
Console.WriteLine($"csharp: {total}/{total} vectors passed");
return 0;
