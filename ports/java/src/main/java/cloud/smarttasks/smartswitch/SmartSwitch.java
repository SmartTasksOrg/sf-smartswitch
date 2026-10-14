package cloud.smarttasks.smartswitch;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The SmartSwitch protocol (spec/SEMANTICS.md): signatures, fleet document, proposals, certificates,
 * the switch state and log replay. Deterministic: no clock, no randomness, no I/O.
 *
 * <p>Documents are the values {@link Json#parse} returns (Map, List, Long, String, Boolean, null).
 */
public final class SmartSwitch {
    private SmartSwitch() {}

    public static final long MAX_INT = 9007199254740991L; // 2^53 - 1
    public static final int MAX_KEYHOLDERS = 64;
    public static final int MAX_AGENTS = 100000;
    public static final int MAX_REASON_BYTES = 1000;
    public static final String GENESIS_PREV = "0".repeat(64);
    static final String VOTE_PREFIX = "smartswitch-vote-v1:";
    static final String HEARTBEAT_PREFIX = "smartswitch-heartbeat-v1:";

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern HEX128 = Pattern.compile("[0-9a-f]{128}");
    static final Pattern NONCE = Pattern.compile("[0-9a-f]{32}");
    private static final List<String> ACTIONS = List.of("halt", "resume", "suspend", "reinstate");
    private static final List<String> KINDS = List.of("genesis", "certificate", "event");
    private static final Set<String> FLEET_FIELDS = Set.of("type", "version", "fleet_id", "keyholders", "threshold",
        "coordinator_key", "offline_timeout_ms", "proposal_max_ttl_ms", "agents");
    private static final Set<String> PROPOSAL_FIELDS = Set.of("type", "fleet_id", "fleet_hash", "seq", "epoch",
        "action", "target", "new_public_key", "reason", "created_ms", "expires_ms");
    private static final Set<String> ENTRY_FIELDS = Set.of("n", "ts_ms", "kind", "body", "prev", "hash");

    /** A rule was broken; {@code code} is the stable SW-* code. */
    public static final class SwitchError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String code;

        public SwitchError(String code, String message) {
            super(message == null || message.isEmpty() ? code : code + ": " + message);
            this.code = code;
        }
    }

    // ------------------------------------------------------------ helpers

    public static boolean isId(Object v) { return v instanceof String s && ID.matcher(s).matches(); }

    public static boolean isKeyHex(Object v) { return v instanceof String s && HEX64.matcher(s).matches(); }

    static boolean isInt(Object v, long lo, long hi) { return v instanceof Long l && l >= lo && l <= hi; }

    static boolean exactly(Object o, Set<String> fields) { return o instanceof Map<?, ?> m && m.keySet().equals(fields); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** sha256 of the canonical form; throws IllegalArgumentException when the value has no canonical form. */
    public static String docHash(Object v) { return sha256Hex(Json.canonicalBytes(v)); }

    // ------------------------------------------------------------ Ed25519

    static final BigInteger L = BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    /** Strict Ed25519 verify (SEMANTICS.md, "Signatures"): lower-case hex of the right lengths, S < L,
     *  then the JDK's Ed25519. Any library error is false. */
    public static boolean verify(Object publicHex, byte[] message, Object sigHex) {
        if (!isKeyHex(publicHex) || !(sigHex instanceof String sh) || !HEX128.matcher(sh).matches()) return false;
        byte[] sig = HexFormat.of().parseHex(sh);
        byte[] be = new byte[32];
        for (int k = 0; k < 32; k++) be[k] = sig[63 - k];          // S is little-endian
        if (new BigInteger(1, be).compareTo(L) >= 0) return false;
        byte[] raw = HexFormat.of().parseHex((String) publicHex);
        byte[] der = new byte[SPKI_PREFIX.length + 32];
        System.arraycopy(SPKI_PREFIX, 0, der, 0, SPKI_PREFIX.length);
        System.arraycopy(raw, 0, der, SPKI_PREFIX.length, 32);
        try {
            PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(pk);
            v.update(message);
            return v.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    // ------------------------------------------------------------ fleet

    /** 2 for up to five keyholders; floor(n/2) + 1 above five. */
    public static int defaultThreshold(int n) { return n <= 5 ? 2 : n / 2 + 1; }

    /** Returns the fleet document as a map, or throws SwitchError("SW-BAD-FLEET"). */
    public static Map<String, Object> validateFleet(Object doc) {
        if (!exactly(doc, FLEET_FIELDS)) throw badFleet("the fleet document must have exactly the fields " + new TreeSet<>(FLEET_FIELDS));
        Map<String, Object> d = map(doc);
        if (!"smartswitch.fleet".equals(d.get("type")) || !(d.get("version") instanceof Long ver && ver == 1)) {
            throw badFleet("type must be \"smartswitch.fleet\" and version 1");
        }
        if (!isId(d.get("fleet_id"))) throw badFleet("fleet_id must match [A-Za-z0-9._-]{1,64}");
        if (!(d.get("keyholders") instanceof List<?> khs) || khs.size() < 3 || khs.size() > MAX_KEYHOLDERS) {
            throw badFleet("keyholders must be a list of 3 to " + MAX_KEYHOLDERS);
        }
        Set<Object> ids = new HashSet<>(), keys = new HashSet<>();
        for (Object kh : khs) {
            if (!exactly(kh, Set.of("id", "public_key"))) throw badFleet("each keyholder must be {\"id\", \"public_key\"}");
            Map<String, Object> k = map(kh);
            if (!isId(k.get("id")) || !isKeyHex(k.get("public_key"))) {
                throw badFleet("keyholder id must match [A-Za-z0-9._-]{1,64} and public_key be 64 lower-case hex");
            }
            if (ids.contains(k.get("id")) || keys.contains(k.get("public_key"))) throw badFleet("keyholder ids and public keys must be unique");
            ids.add(k.get("id"));
            keys.add(k.get("public_key"));
        }
        int n = khs.size();
        if (d.get("threshold") != null && !isInt(d.get("threshold"), 2, n - 1)) {
            throw badFleet("threshold must be null or an integer from 2 to " + (n - 1));
        }
        if (!isKeyHex(d.get("coordinator_key")) || keys.contains(d.get("coordinator_key"))) {
            throw badFleet("coordinator_key must be 64 lower-case hex and differ from every keyholder key");
        }
        if (!isInt(d.get("offline_timeout_ms"), 1000, 3600000)) throw badFleet("offline_timeout_ms must be an integer from 1000 to 3600000");
        if (!isInt(d.get("proposal_max_ttl_ms"), 1000, 86400000)) throw badFleet("proposal_max_ttl_ms must be an integer from 1000 to 86400000");
        Object agents = d.get("agents");
        if (agents != null) {
            if (!(agents instanceof List<?> as) || as.size() > MAX_AGENTS) throw badFleet("agents must be null or a list of at most " + MAX_AGENTS);
            Set<Object> seen = new HashSet<>();
            for (Object a : as) {
                if (!exactly(a, Set.of("id", "max_instances"))) throw badFleet("each agent must be {\"id\", \"max_instances\"}");
                Map<String, Object> m = map(a);
                if (!isId(m.get("id")) || !isInt(m.get("max_instances"), 1, 1000) || seen.contains(m.get("id"))) {
                    throw badFleet("agent id must match [A-Za-z0-9._-]{1,64}, be unique, and max_instances be 1 to 1000");
                }
                seen.add(m.get("id"));
            }
        }
        return d;
    }

    private static SwitchError badFleet(String msg) { return new SwitchError("SW-BAD-FLEET", msg); }

    public static int fleetThreshold(Map<String, Object> fleet) {
        Object t = fleet.get("threshold");
        return t == null ? defaultThreshold(((List<?>) fleet.get("keyholders")).size()) : ((Long) t).intValue();
    }

    // ------------------------------------------------------------ proposals and certificates

    public static Map<String, Object> checkProposalFormat(Object o) {
        if (!exactly(o, PROPOSAL_FIELDS)) throw badProposal("a proposal must have exactly the fields " + new TreeSet<>(PROPOSAL_FIELDS));
        Map<String, Object> p = map(o);
        if (!"smartswitch.proposal".equals(p.get("type"))) throw badProposal("type must be \"smartswitch.proposal\"");
        if (!isId(p.get("fleet_id")) || !isKeyHex(p.get("fleet_hash"))) throw badProposal("fleet_id or fleet_hash is malformed");
        if (!isInt(p.get("seq"), 1, MAX_INT) || !isInt(p.get("epoch"), 0, MAX_INT)) throw badProposal("seq must be an integer >= 1 and epoch >= 0");
        if (!ACTIONS.contains(p.get("action"))) throw badProposal("action must be one of " + String.join(", ", ACTIONS));
        if (!(p.get("target") instanceof String)) throw badProposal("target must be a string");
        if ("reinstate".equals(p.get("action"))) {
            if (!isKeyHex(p.get("new_public_key"))) throw badProposal("reinstate needs new_public_key (64 lower-case hex)");
        } else if (p.get("new_public_key") != null) {
            throw badProposal("new_public_key must be null unless the action is reinstate");
        }
        if (!(p.get("reason") instanceof String r) || !Json.validText(r) || r.getBytes(StandardCharsets.UTF_8).length > MAX_REASON_BYTES) {
            throw badProposal("reason must be a string of at most " + MAX_REASON_BYTES + " UTF-8 bytes");
        }
        if (!isInt(p.get("created_ms"), 0, MAX_INT) || !isInt(p.get("expires_ms"), 0, MAX_INT)) {
            throw badProposal("created_ms and expires_ms must be integers >= 0");
        }
        if ((Long) p.get("expires_ms") <= (Long) p.get("created_ms")) throw badProposal("expires_ms must be after created_ms");
        return p;
    }

    private static SwitchError badProposal(String msg) { return new SwitchError("SW-BAD-PROPOSAL", msg); }

    public static String proposalHash(Object p) { return docHash(p); }

    static byte[] voteMessage(String proposalHash) { return (VOTE_PREFIX + proposalHash).getBytes(StandardCharsets.US_ASCII); }

    public static Map<String, Object> checkCertificateFormat(Object o) {
        if (!exactly(o, Set.of("type", "proposal", "votes"))) throw badCert("a certificate must be {\"type\", \"proposal\", \"votes\"}");
        Map<String, Object> c = map(o);
        if (!"smartswitch.certificate".equals(c.get("type"))) throw badCert("type must be \"smartswitch.certificate\"");
        if (!(c.get("votes") instanceof List<?> votes) || votes.isEmpty() || votes.size() > MAX_KEYHOLDERS) {
            throw badCert("votes must be a list of 1 to " + MAX_KEYHOLDERS);
        }
        for (Object v : votes) {
            if (!exactly(v, Set.of("keyholder", "sig")) || !(map(v).get("keyholder") instanceof String)
                || !(map(v).get("sig") instanceof String)) {
                throw badCert("each vote must be {\"keyholder\": string, \"sig\": string}");
            }
        }
        return c;
    }

    private static SwitchError badCert(String msg) { return new SwitchError("SW-BAD-CERTIFICATE", msg); }

    // ------------------------------------------------------------ state

    /** The switch state; treat as immutable ({@link #apply} returns a new one). */
    public static final class State {
        public final String fleetId, fleetHash, coordinatorKey;
        public final int n, threshold;
        public final long maxTtlMs, offlineTimeoutMs;
        final TreeMap<String, String> keys;
        final TreeSet<String> suspended, halted;
        public final long seq, epoch;
        public final boolean haltedAll;

        private State(String fleetId, String fleetHash, String coordinatorKey, int n, int threshold, long maxTtlMs,
                      long offlineTimeoutMs, TreeMap<String, String> keys, TreeSet<String> suspended, long seq, long epoch,
                      boolean haltedAll, TreeSet<String> halted) {
            this.fleetId = fleetId;
            this.fleetHash = fleetHash;
            this.coordinatorKey = coordinatorKey;
            this.n = n;
            this.threshold = threshold;
            this.maxTtlMs = maxTtlMs;
            this.offlineTimeoutMs = offlineTimeoutMs;
            this.keys = keys;
            this.suspended = suspended;
            this.seq = seq;
            this.epoch = epoch;
            this.haltedAll = haltedAll;
            this.halted = halted;
        }

        public static State genesis(Object fleetDoc) {
            Map<String, Object> f = validateFleet(fleetDoc);
            TreeMap<String, String> keys = new TreeMap<>();
            for (Object kh : (List<?>) f.get("keyholders")) keys.put((String) map(kh).get("id"), (String) map(kh).get("public_key"));
            return new State((String) f.get("fleet_id"), docHash(f), (String) f.get("coordinator_key"), keys.size(),
                fleetThreshold(f), (Long) f.get("proposal_max_ttl_ms"), (Long) f.get("offline_timeout_ms"), keys,
                new TreeSet<>(), 0, 0, false, new TreeSet<>());
        }

        public List<String> active() {
            List<String> out = new ArrayList<>();
            for (String k : keys.keySet()) if (!suspended.contains(k)) out.add(k);
            return out;
        }

        public boolean isHalted(String agentId) { return halted.contains(agentId); }

        public boolean mayRun(String agentId) { return !haltedAll && !halted.contains(agentId); }

        /** The state as the vectors compare it. */
        public Map<String, Object> summary() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seq", seq);
            m.put("epoch", epoch);
            m.put("threshold", (long) threshold);
            m.put("halted_all", haltedAll);
            m.put("halted", new ArrayList<>(halted));
            m.put("active", active());
            m.put("suspended", new ArrayList<>(suspended));
            m.put("keys", new TreeMap<>(keys));
            return m;
        }
    }

    /** Check {@code cert} against {@code st} at {@code atMs}; return its proposal or throw SwitchError.
     *  The checks run in the order of SEMANTICS.md, "Certificate checks". */
    public static Map<String, Object> verifyCertificate(State st, Object cert, long atMs, boolean ahead) {
        Map<String, Object> c = checkCertificateFormat(cert);
        Map<String, Object> p = checkProposalFormat(c.get("proposal"));
        if (!st.fleetId.equals(p.get("fleet_id")) || !st.fleetHash.equals(p.get("fleet_hash"))) {
            throw new SwitchError("SW-WRONG-FLEET", "the proposal is for another fleet");
        }
        long seq = (Long) p.get("seq");
        if (seq <= st.seq) throw new SwitchError("SW-STALE-SEQ", "seq " + seq + " is not after the current seq " + st.seq);
        if (!ahead && seq != st.seq + 1) throw new SwitchError("SW-SEQ-GAP", "seq " + seq + " is not the next seq " + (st.seq + 1));
        if ((Long) p.get("epoch") != st.epoch) throw new SwitchError("SW-WRONG-EPOCH", "epoch " + p.get("epoch") + " is not the current epoch " + st.epoch);
        long created = (Long) p.get("created_ms"), expires = (Long) p.get("expires_ms");
        if (expires - created > st.maxTtlMs) throw new SwitchError("SW-BAD-PROPOSAL", "the proposal is valid for longer than " + st.maxTtlMs + " ms");
        if (atMs >= expires) throw new SwitchError("SW-EXPIRED", "the proposal has expired");
        checkTarget(st, p);
        byte[] msg = voteMessage(proposalHash(p));
        String action = (String) p.get("action");
        Set<String> seen = new HashSet<>();
        for (Object o : (List<?>) c.get("votes")) {
            String kh = (String) map(o).get("keyholder");
            if (!st.keys.containsKey(kh)) throw new SwitchError("SW-UNKNOWN-KEYHOLDER", kh + " is not a keyholder of this fleet");
            if (!seen.add(kh)) throw new SwitchError("SW-DUPLICATE-VOTE", kh + " voted twice");
            if (st.suspended.contains(kh)) throw new SwitchError("SW-SUSPENDED-KEYHOLDER", kh + " is suspended");
            if (action.equals("suspend") && kh.equals(p.get("target"))) {
                throw new SwitchError("SW-TARGET-VOTE", "a keyholder cannot vote on its own suspension");
            }
            if (!verify(st.keys.get(kh), msg, map(o).get("sig"))) throw new SwitchError("SW-BAD-SIGNATURE", "the signature of " + kh + " does not verify");
        }
        if (seen.size() < st.threshold) throw new SwitchError("SW-NO-QUORUM", seen.size() + " valid votes, " + st.threshold + " needed");
        return p;
    }

    private static void checkTarget(State st, Map<String, Object> p) {
        String a = (String) p.get("action"), t = (String) p.get("target");
        switch (a) {
            case "halt", "resume" -> {
                if (!t.equals("*") && !isId(t)) throw new SwitchError("SW-BAD-TARGET", "target must be \"*\" or an agent id");
            }
            case "suspend" -> {
                if (!st.keys.containsKey(t) || st.suspended.contains(t)) throw new SwitchError("SW-BAD-TARGET", "target must be an active keyholder");
                if (st.active().size() - 1 < st.threshold) {
                    throw new SwitchError("SW-QUORUM-IMPOSSIBLE", "suspending this keyholder would leave fewer active keyholders than the threshold " + st.threshold);
                }
            }
            default -> {
                if (!st.suspended.contains(t)) throw new SwitchError("SW-BAD-TARGET", "target must be a suspended keyholder");
                Object k = p.get("new_public_key");
                if (st.keys.containsValue(k) || st.coordinatorKey.equals(k)) {
                    throw new SwitchError("SW-BAD-TARGET", "new_public_key must be a key not used in this fleet");
                }
            }
        }
    }

    /** Verify {@code cert} (seq must be st.seq + 1) and return the next state; {@code st} is unchanged. */
    public static State apply(State st, Object cert, long atMs) {
        Map<String, Object> p = verifyCertificate(st, cert, atMs, false);
        String a = (String) p.get("action"), t = (String) p.get("target");
        TreeMap<String, String> keys = st.keys;
        TreeSet<String> suspended = st.suspended, halted = st.halted;
        boolean haltedAll = st.haltedAll;
        long epoch = st.epoch;
        switch (a) {
            case "halt" -> {
                if (t.equals("*")) haltedAll = true;
                else { halted = new TreeSet<>(halted); halted.add(t); }
            }
            case "resume" -> {
                if (t.equals("*")) { haltedAll = false; halted = new TreeSet<>(); }
                else { halted = new TreeSet<>(halted); halted.remove(t); }
            }
            case "suspend" -> {
                suspended = new TreeSet<>(suspended);
                suspended.add(t);
                epoch++;
            }
            default -> {
                suspended = new TreeSet<>(suspended);
                suspended.remove(t);
                keys = new TreeMap<>(keys);
                keys.put(t, (String) p.get("new_public_key"));
                epoch++;
            }
        }
        return new State(st.fleetId, st.fleetHash, st.coordinatorKey, st.n, st.threshold, st.maxTtlMs, st.offlineTimeoutMs,
            keys, suspended, st.seq + 1, epoch, haltedAll, halted);
    }

    // ------------------------------------------------------------ log

    static String entryHash(Map<String, Object> e) {
        Map<String, Object> body = new LinkedHashMap<>(e);
        body.remove("hash");
        return docHash(body);
    }

    /** A verified copy of a log. {@link #extend} checks entries one by one and applies certificates; on the
     *  first bad entry it throws SwitchError and keeps everything before it. */
    public static final class Replica {
        public final String pinned;
        public State state;
        public int size;
        public String head = GENESIS_PREV;
        final List<String> hashes = new ArrayList<>();

        /** @param fleetHash the fleet hash entry 0 must have, or null to accept any genesis */
        public Replica(String fleetHash) { this.pinned = fleetHash; }

        public int extend(List<?> entries) {
            for (Object e : entries) one(e);
            return size;
        }

        public String hashAt(int index) { return hashes.get(index); }

        private void one(Object o) {
            if (!exactly(o, ENTRY_FIELDS)) throw new SwitchError("SW-BAD-ENTRY", "entry " + size + " is malformed");
            Map<String, Object> e = map(o);
            if (!KINDS.contains(e.get("kind")) || !(e.get("body") instanceof Map) || !(e.get("n") instanceof Long n)
                || !(e.get("ts_ms") instanceof Long ts) || ts < 0) {
                throw new SwitchError("SW-BAD-ENTRY", "entry " + size + " is malformed");
            }
            // ts_ms is the coordinator's unsigned wall clock: it need not increase (SEMANTICS.md, "Log")
            if (n != size) throw new SwitchError("SW-LOG-ORDER", "entry " + size + ": n is " + n);
            boolean chained;
            try {
                chained = head.equals(e.get("prev")) && entryHash(e).equals(e.get("hash"));
            } catch (IllegalArgumentException x) {       // no canonical form (a float, an unpaired surrogate): cannot match
                chained = false;
            }
            if (!chained) throw new SwitchError("SW-LOG-CHAIN", "entry " + size + ": the hash chain is broken");
            Object kind = e.get("kind");
            if (size == 0) {
                if (!"genesis".equals(kind)) throw new SwitchError("SW-BAD-ENTRY", "entry 0 must be the genesis");
                try {
                    validateFleet(e.get("body"));
                } catch (SwitchError err) {
                    throw new SwitchError("SW-BAD-FLEET", "entry 0: " + err.getMessage());
                }
                if (pinned != null && !docHash(e.get("body")).equals(pinned)) throw new SwitchError("SW-WRONG-FLEET", "entry 0 is not the pinned fleet");
                state = State.genesis(e.get("body"));
            } else if ("genesis".equals(kind)) {
                throw new SwitchError("SW-BAD-ENTRY", "entry " + size + ": only entry 0 can be a genesis");
            } else if ("certificate".equals(kind)) {
                state = apply(state, e.get("body"), ts);
            }
            size++;
            head = (String) e.get("hash");
            hashes.add(head);
        }
    }

    /** {"ok": true, "size", "head", "state"} or {"ok": false, "index", "code"} (the vectors' form). */
    public static Map<String, Object> replay(List<?> entries, String fleetHash) {
        Replica r = new Replica(fleetHash);
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            r.extend(entries);
        } catch (SwitchError e) {
            out.put("ok", false);
            out.put("index", (long) r.size);
            out.put("code", e.code);
            return out;
        }
        if (r.size == 0) {
            out.put("ok", false);
            out.put("index", 0L);
            out.put("code", "SW-BAD-ENTRY");
            return out;
        }
        out.put("ok", true);
        out.put("size", (long) r.size);
        out.put("head", r.head);
        out.put("state", r.state.summary());
        return out;
    }
}
