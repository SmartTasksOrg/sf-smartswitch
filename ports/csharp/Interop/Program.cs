using SmartSwitch;

// The interop agent for ports/conformance/interop.py:
//     dotnet Interop.dll URL FLEET_FILE AGENT_ID INSTANCE_ID     (token in SMARTSWITCH_AGENT_TOKEN)
// Polls every 100 ms and prints "STATUS <code>" whenever the status code changes; exits when standard
// input closes or after 60 s.
if (args.Length != 4)
{
    Console.Error.WriteLine("usage: Interop URL FLEET_FILE AGENT_ID INSTANCE_ID");
    return 2;
}
using var agent = new Agent(args[0], Environment.GetEnvironmentVariable("SMARTSWITCH_AGENT_TOKEN"), Agent.LoadFleet(args[1]),
    args[2], args[3], TimeSpan.FromSeconds(1));
var done = new ManualResetEventSlim(false);
new Thread(() =>
{
    try { Console.OpenStandardInput().CopyTo(Stream.Null); } catch (IOException) { }
    done.Set();
}) { IsBackground = true }.Start();
var end = DateTime.UtcNow.AddSeconds(60);
string? last = null;
while (!done.IsSet && DateTime.UtcNow < end)
{
    var code = agent.PollOnce();
    if (code != last)
    {
        Console.WriteLine("STATUS " + code);
        Console.Out.Flush();
        last = code;
    }
    done.Wait(100);
}
return 0;
