using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace SmartSwitch;

/// <summary>The agent may not run; <see cref="Code"/> says why (SW-HALTED-FLEET, SW-OFFLINE, ...).</summary>
public sealed class HaltedException : Exception
{
    public string Code { get; }
    public HaltedException(string code) : base($"SmartSwitch: this agent may not run ({code})") { Code = code; }
}

/// <summary>The coordinator answered with an HTTP error status.</summary>
public sealed class CoordinatorError : Exception
{
    public int Status { get; }
    public CoordinatorError(int status, string body) : base($"HTTP {status}: {body}") { Status = status; }
}

/// <summary>
/// The networked agent (spec/PORTING.md, item 8): every <see cref="PollMs"/> it sends GET /v1/heartbeat with a fresh
/// random nonce, fetches and verifies the log when behind, and checks the same heartbeat again. Network errors change
/// nothing; the dead-man rule (offline_timeout_ms) does the rest. Thread-safe.
/// <code>
/// var agent = new Agent("https://switch.example:8720", token, Agent.LoadFleet("fleet.json"), "planner-1");
/// agent.Start();
/// while (agent.MayRun()) { DoOneStep(); agent.Checkpoint(); }
/// </code>
/// </summary>
public sealed class Agent : IDisposable
{
    readonly object gate = new();
    readonly AgentView view;
    readonly HttpClient http;
    readonly string url;
    readonly string? token;
    readonly Stopwatch clock = Stopwatch.StartNew();
    CancellationTokenSource? cts;
    Thread? thread;

    public int PollMs { get; set; } = 1000;
    public string AgentId => view.AgentId;
    public string InstanceId => view.InstanceId;
    /// <summary>The last round's problem (a network error or a heartbeat code), or null.</summary>
    public string? LastError { get; private set; }

    public Agent(string url, string? token, object? fleet, string agentId, string? instanceId = null, TimeSpan? timeout = null)
    {
        if (!url.StartsWith("http://", StringComparison.Ordinal) && !url.StartsWith("https://", StringComparison.Ordinal))
            throw new ArgumentException("the coordinator URL must start with http:// or https://");
        this.url = url.TrimEnd('/');
        this.token = string.IsNullOrEmpty(token) ? null : token;
        view = new AgentView(fleet, agentId, instanceId ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant());
        http = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(2) };
    }

    /// <summary>Read and validate a fleet document (throws SwitchError SW-BAD-FLEET).</summary>
    public static object? LoadFleet(string path)
    {
        var fleet = Json.Parse(File.ReadAllText(path));
        Protocol.ValidateFleet(fleet);
        return fleet;
    }

    /// <summary>This agent's monotonic clock in milliseconds (for heartbeats and status).</summary>
    public long NowMs() => clock.ElapsedMilliseconds;

    public static string NewNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    object? Get(string path, params (string Key, string Value)[] query)
    {
        var q = string.Join("&", query.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        using var req = new HttpRequestMessage(HttpMethod.Get, url + path + (q.Length > 0 ? "?" + q : ""));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        // One connection per request: a kept-alive connection could still be answered by a coordinator that has
        // stopped accepting new connections, and every heartbeat should prove that the coordinator is reachable now.
        req.Headers.ConnectionClose = true;
        if (token != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var res = http.Send(req);
        using var reader = new StreamReader(res.Content.ReadAsStream());
        var text = reader.ReadToEnd();
        if ((int)res.StatusCode >= 300) throw new CoordinatorError((int)res.StatusCode, text.Length > 300 ? text[..300] : text);
        return Json.Parse(text);
    }

    /// <summary>One round: heartbeat, catch up on the log if behind, check the same heartbeat again. Returns the status code.</summary>
    public string PollOnce()
    {
        try
        {
            var nonce = NewNonce();
            var sent = NowMs();
            var hb = Get("/v1/heartbeat", ("agent_id", AgentId), ("instance_id", InstanceId), ("nonce", nonce));
            SortedDictionary<string, object?> r;
            lock (gate) r = view.Heartbeat(hb, nonce, sent);
            if (r["code"] as string == "SW-BEHIND")
            {
                CatchUp((long)Json.Get(hb, "log_size")!);
                lock (gate) r = view.Heartbeat(hb, nonce, sent);
            }
            LastError = r["ok"] is true ? null : r["code"] as string;
        }
        catch (Exception e)
        {
            // Network errors, refusals and unusable answers change nothing; the dead-man rule does the rest.
            LastError = e.GetType().Name + ": " + e.Message;
        }
        return Status();
    }

    void CatchUp(long size)
    {
        while (true)
        {
            int have;
            lock (gate) have = view.Replica.Size;
            if (have >= size) return;
            var page = Get("/v1/log", ("from", have.ToString()), ("limit", "1000"), ("agent_id", AgentId), ("instance_id", InstanceId));
            if (Json.Get(page, "entries") is not List<object?> entries) throw new InvalidOperationException("the log answer has no entries");
            if (entries.Count == 0) return;
            SortedDictionary<string, object?> r;
            lock (gate) r = view.Log(entries);
            if (r["ok"] is not true) throw new InvalidOperationException($"the coordinator log does not verify ({r["code"]} at entry {r["size"]})");
        }
    }

    /// <summary>Wall-clock milliseconds since the Unix epoch (proposal expiry is wall-clock time).</summary>
    public static long WallMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    /// <summary>A certificate that reached this agent some other way than the coordinator: {ok, code}. It is checked at
    /// wall-clock time, since it is compared with the proposal's expires_ms.</summary>
    public SortedDictionary<string, object?> Deliver(object? certificate)
    {
        lock (gate) return view.Certificate(certificate, WallMs());
    }

    /// <summary>The status code now (SW-RUN when the agent may run).</summary>
    public string Status()
    {
        lock (gate) return view.StatusCode(NowMs());
    }

    public bool MayRun() => Status() == "SW-RUN";

    /// <summary>Throws <see cref="HaltedException"/> when the agent may not run.</summary>
    public void Checkpoint()
    {
        var code = Status();
        if (code != "SW-RUN") throw new HaltedException(code);
    }

    /// <summary>Poll every <see cref="PollMs"/> on a background thread until <see cref="Stop"/>.</summary>
    public Agent Start()
    {
        if (thread != null) return this;
        cts = new CancellationTokenSource();
        var token = cts.Token;
        thread = new Thread(() =>
        {
            while (!token.IsCancellationRequested)
            {
                PollOnce();
                token.WaitHandle.WaitOne(PollMs);
            }
        }) { IsBackground = true, Name = "smartswitch-agent" };
        thread.Start();
        return this;
    }

    public void Stop()
    {
        cts?.Cancel();
        thread?.Join(TimeSpan.FromSeconds(5));
        thread = null;
    }

    public void Dispose()
    {
        Stop();
        http.Dispose();
        cts?.Dispose();
    }
}
