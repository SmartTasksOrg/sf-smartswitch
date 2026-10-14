package cloud.smarttasks.smartswitch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The agent's calls to the coordinator (java.net.HttpURLConnection). Any answer other than 2xx is an
 * IOException. Every request uses a new connection ("Connection: close"), as the Python reference does:
 * a heartbeat must come from the coordinator as it is now, not from a connection kept open from before.
 */
public final class Client {
    /** The largest answer read; a longer one is an error. */
    public static final int MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
    public final String url;
    private final String token;
    private final int timeoutMs;

    public Client(String url, String token, Duration timeout) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw new IllegalArgumentException("the coordinator URL must start with http:// or https://");
        }
        this.url = url.replaceAll("/+$", "");
        this.token = token;
        this.timeoutMs = (int) Math.max(1, timeout.toMillis());
    }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    private static String readAll(InputStream in) throws IOException {
        if (in == null) return "";
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) >= 0) {
                if (out.size() + n > MAX_RESPONSE_BYTES) throw new IOException("the answer is longer than " + MAX_RESPONSE_BYTES + " bytes");
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /** GET {@code path} with the query parameters; returns the parsed JSON body. */
    public Object get(String path, Map<String, String> query) throws IOException {
        StringBuilder u = new StringBuilder(url).append(path);
        char sep = '?';
        for (Map.Entry<String, String> e : query.entrySet()) {
            u.append(sep).append(enc(e.getKey())).append('=').append(enc(e.getValue()));
            sep = '&';
        }
        HttpURLConnection c = (HttpURLConnection) URI.create(u.toString()).toURL().openConnection();
        try {
            c.setRequestMethod("GET");
            c.setConnectTimeout(timeoutMs);
            c.setReadTimeout(timeoutMs);
            c.setUseCaches(false);
            c.setInstanceFollowRedirects(false);
            c.setRequestProperty("Accept", "application/json");
            c.setRequestProperty("Connection", "close");
            if (token != null && !token.isEmpty()) c.setRequestProperty("Authorization", "Bearer " + token);
            int status = c.getResponseCode();
            if (status < 200 || status >= 300) {
                String body = readAll(c.getErrorStream());
                throw new IOException("HTTP " + status + ": " + (body.length() > 300 ? body.substring(0, 300) : body));
            }
            String body = readAll(c.getInputStream());
            try {
                return Json.parse(body);
            } catch (IllegalArgumentException e) {
                throw new IOException("the coordinator answered with invalid JSON: " + e.getMessage(), e);
            }
        } finally {
            c.disconnect();
        }
    }

    public Object heartbeat(String agentId, String instanceId, String nonce) throws IOException {
        Map<String, String> q = new LinkedHashMap<>();
        q.put("agent_id", agentId);
        q.put("instance_id", instanceId);
        q.put("nonce", nonce);
        return get("/v1/heartbeat", q);
    }

    public Object log(long from, int limit, String agentId, String instanceId) throws IOException {
        Map<String, String> q = new LinkedHashMap<>();
        q.put("from", Long.toString(from));
        q.put("limit", Integer.toString(limit));
        q.put("agent_id", agentId);
        q.put("instance_id", instanceId);
        return get("/v1/log", q);
    }
}
