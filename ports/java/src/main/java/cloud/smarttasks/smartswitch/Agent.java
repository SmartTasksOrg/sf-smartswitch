package cloud.smarttasks.smartswitch;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The networked agent: asks the coordinator for a signed heartbeat every {@code pollMs}, fetches and verifies
 * the log when behind, and answers whether this agent may run (rules in {@link AgentView}).
 *
 * <pre>
 * Agent agent = new Agent(url, System.getenv("SMARTSWITCH_AGENT_TOKEN"), Agent.loadFleet(Path.of("fleet.json")),
 *                         "planner-1", "i1", 1000, Duration.ofSeconds(2)).start();
 * while (agent.mayRun()) { doOneStep(); agent.checkpoint(); }   // checkpoint throws Agent.Halted
 * </pre>
 *
 * Network errors change nothing: with no valid heartbeat for the fleet's offline_timeout_ms the agent
 * stops by itself (SW-OFFLINE).
 */
public final class Agent {
    /** Thrown by {@link #checkpoint} when the agent may not run. */
    public static final class Halted extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String code;

        public Halted(String code) {
            super("SmartSwitch: this agent may not run (" + code + ")");
            this.code = code;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long T0 = System.nanoTime();

    public final Map<String, Object> fleet;
    public final AgentView view;
    public final long pollMs;
    private final Client client;
    private final Object lock = new Object();
    private volatile Consumer<Map<String, Object>> onChange;
    private Map<String, Object> last;
    private volatile String lastError;
    private volatile Thread thread;

    public Agent(String url, String token, Map<String, Object> fleet, String agentId, String instanceId, long pollMs, Duration timeout) {
        this.fleet = SmartSwitch.validateFleet(fleet);
        this.view = new AgentView(this.fleet, agentId, instanceId);
        this.client = new Client(url, token, timeout);
        this.pollMs = pollMs;
    }

    /** Read and validate a fleet document (throws SwitchError SW-BAD-FLEET, IOException). */
    public static Map<String, Object> loadFleet(Path file) throws IOException {
        Object doc = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
        return SmartSwitch.validateFleet(doc);
    }

    /** The agent's monotonic clock in milliseconds (heartbeats and status). */
    public static long monoMs() { return (System.nanoTime() - T0) / 1_000_000; }

    /** Wall-clock milliseconds (delivered certificates: compared with expires_ms). */
    public static long wallMs() { return System.currentTimeMillis(); }

    /** Called with the new status whenever it changes. */
    public Agent onChange(Consumer<Map<String, Object>> c) { this.onChange = c; return this; }

    public String lastError() { return lastError; }

    /** One round: heartbeat (and log fetch when behind). Returns the status afterwards. */
    public Map<String, Object> pollOnce() {
        byte[] nb = new byte[16];
        RANDOM.nextBytes(nb);
        String nonce = HexFormat.of().formatHex(nb);
        long sent = monoMs();
        try {
            Object hb = client.heartbeat(view.agentId, view.instanceId, nonce);
            Map<String, Object> r;
            synchronized (lock) { r = view.heartbeat(hb, nonce, sent); }
            if ("SW-BEHIND".equals(r.get("code"))) {
                catchUp((Long) SmartSwitch.map(hb).get("log_size"));
                synchronized (lock) { r = view.heartbeat(hb, nonce, sent); }
            }
            lastError = Boolean.TRUE.equals(r.get("ok")) ? null : (String) r.get("code");
        } catch (Exception | StackOverflowError e) {   // any error changes nothing (the dead-man rule takes over)
            lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        return status();
    }

    private void catchUp(long size) throws IOException {
        while (true) {
            int have;
            synchronized (lock) { have = view.replica.size; }
            if (have >= size) return;
            Object body = client.log(have, 1000, view.agentId, view.instanceId);
            if (!(body instanceof Map<?, ?> m) || !(m.get("entries") instanceof List<?> page)) {
                throw new IOException("the coordinator answered /v1/log without entries");
            }
            if (page.isEmpty()) return;
            Map<String, Object> r;
            synchronized (lock) { r = view.log(page); }
            if (!Boolean.TRUE.equals(r.get("ok"))) {
                throw new IOException("the coordinator log does not verify (" + r.get("code") + " at entry " + r.get("size") + ")");
            }
        }
    }

    /** A certificate that reached this agent some other way than the coordinator. */
    public Map<String, Object> deliver(Object certificate) {
        Map<String, Object> r;
        synchronized (lock) { r = view.certificate(certificate, wallMs()); }
        status();
        return r;
    }

    /** {run, code} now. */
    public Map<String, Object> status() {
        Map<String, Object> s;
        boolean changed;
        synchronized (lock) {
            s = view.status(monoMs());
            changed = !s.equals(last);
            if (changed) last = s;
        }
        Consumer<Map<String, Object>> c = onChange;
        if (changed && c != null) {
            try {
                c.accept(s);
            } catch (RuntimeException e) {
                System.err.println("smartswitch: onChange failed: " + e);
            }
        }
        return s;
    }

    public boolean mayRun() { return Boolean.TRUE.equals(status().get("run")); }

    /** Throws {@link Halted} when the agent may not run. */
    public void checkpoint() {
        Map<String, Object> s = status();
        if (!Boolean.TRUE.equals(s.get("run"))) throw new Halted((String) s.get("code"));
    }

    /** Poll in a background (daemon) thread every pollMs. */
    public synchronized Agent start() {
        if (thread == null) {
            Thread t = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        pollOnce();
                    } catch (Throwable e) {   // the loop must survive anything; the dead-man rule covers the gap
                        lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
                        System.err.println("smartswitch: poll failed: " + lastError);
                    }
                    try {
                        Thread.sleep(pollMs);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }, "smartswitch-agent");
            t.setDaemon(true);
            thread = t;
            t.start();
        }
        return this;
    }

    public synchronized void stop() {
        Thread t = thread;
        thread = null;
        if (t != null) {
            t.interrupt();
            try {
                t.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
