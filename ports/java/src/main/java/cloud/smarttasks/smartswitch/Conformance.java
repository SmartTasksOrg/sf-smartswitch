package cloud.smarttasks.smartswitch;

import cloud.smarttasks.smartswitch.SmartSwitch.State;
import cloud.smarttasks.smartswitch.SmartSwitch.SwitchError;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Runs spec/conformance/*.json against the Java port, exactly as the Python runner does.
 *  Usage: java -cp build/classes cloud.smarttasks.smartswitch.Conformance DIR */
public final class Conformance {
    private int total;
    private final List<String> fails = new ArrayList<>();

    private static String c(Object v) {
        try {
            return Json.canonical(v);
        } catch (IllegalArgumentException e) {
            return "<not canonical: " + e.getMessage() + ">";
        }
    }

    private void check(String name, Object got, Object want) {
        total++;
        String g = c(got), w = c(want);
        if (!g.equals(w)) fails.add(name + ": got " + cut(g) + ", want " + cut(w));
    }

    private static String cut(String s) { return s.length() > 300 ? s.substring(0, 300) : s; }

    private static Map<String, Object> load(String dir, String name) throws Exception {
        return SmartSwitch.map(Json.parse(Files.readString(Path.of(dir, name), StandardCharsets.UTF_8)));
    }

    private static List<?> list(Object o) { return (List<?>) o; }

    private static Map<String, Object> pick(Map<String, Object> c, String... keys) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : keys) if (c.containsKey(k)) out.put(k, c.get(k));
        return out;
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int k = 0; k < kv.length; k += 2) out.put((String) kv[k], kv[k + 1]);
        return out;
    }

    void run(String dir) throws Exception {
        for (Object o : list(load(dir, "canonical.json").get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            String text = c(cs.get("input"));
            check("canonical/" + cs.get("name"), List.of(text, SmartSwitch.sha256Hex(text.getBytes(StandardCharsets.UTF_8))),
                List.of(cs.get("canonical"), cs.get("sha256")));
        }

        for (Object o : list(load(dir, "ed25519.json").get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            byte[] msg = HexFormat.of().parseHex((String) cs.get("message_hex"));
            check("ed25519/" + cs.get("name"), SmartSwitch.verify(cs.get("public_key"), msg, cs.get("sig")), cs.get("valid"));
        }

        Map<String, Object> fleets = load(dir, "fleets.json");
        for (Object o : list(fleets.get("default_thresholds"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            long n = (Long) cs.get("n");
            check("fleets/default threshold n=" + n, (long) SmartSwitch.defaultThreshold((int) n), cs.get("k"));
        }
        for (Object o : list(fleets.get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            Object got;
            try {
                SmartSwitch.validateFleet(cs.get("fleet"));
                got = obj("ok", true, "fleet_hash", SmartSwitch.docHash(cs.get("fleet")), "threshold", (long) State.genesis(cs.get("fleet")).threshold);
            } catch (SwitchError e) {
                got = obj("ok", false, "code", e.code);
            }
            check("fleets/" + cs.get("name"), got, pick(cs, "ok", "fleet_hash", "threshold", "code"));
        }

        Map<String, Object> certs = load(dir, "certificates.json");
        Map<String, Object> certFleets = SmartSwitch.map(certs.get("fleets"));
        for (Object o : list(certs.get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            State st = State.genesis(certFleets.get((String) cs.get("fleet")));
            for (Object s : list(cs.get("setup"))) {
                st = SmartSwitch.apply(st, SmartSwitch.map(s).get("certificate"), (Long) SmartSwitch.map(s).get("at_ms"));
            }
            Object cert = cs.get("certificate");
            String ph = null;
            if (cert instanceof Map<?, ?> m && m.containsKey("proposal")) {
                try {
                    ph = SmartSwitch.proposalHash(m.get("proposal"));
                } catch (IllegalArgumentException e) {
                    ph = null;
                }
            }
            check("certificates/" + cs.get("name") + " (proposal hash)", ph, cs.get("proposal_hash"));
            long at = (Long) cs.get("at_ms");
            Object got;
            try {
                if (Boolean.TRUE.equals(cs.get("ahead"))) {
                    SmartSwitch.verifyCertificate(st, cert, at, true);
                    got = obj("ok", true, "state", null);
                } else {
                    got = obj("ok", true, "state", SmartSwitch.apply(st, cert, at).summary());
                }
            } catch (SwitchError e) {
                got = obj("ok", false, "code", e.code);
            }
            check("certificates/" + cs.get("name"), got, pick(cs, "ok", "state", "code"));
        }

        for (Object o : list(load(dir, "logs.json").get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            check("logs/" + cs.get("name"), SmartSwitch.replay(list(cs.get("entries")), (String) cs.get("pinned")), cs.get("result"));
        }

        Map<String, Object> agent = load(dir, "agent.json");
        Map<String, Object> fleet = SmartSwitch.map(agent.get("fleet"));
        for (Object o : list(agent.get("cases"))) {
            Map<String, Object> cs = SmartSwitch.map(o);
            AgentView view = new AgentView(fleet, (String) cs.get("agent_id"), (String) cs.get("instance_id"));
            List<?> steps = list(cs.get("steps"));
            for (int i = 0; i < steps.size(); i++) {
                Map<String, Object> s = SmartSwitch.map(steps.get(i));
                String op = (String) s.get("op");
                Object got = switch (op) {
                    case "log" -> view.log(list(s.get("entries")));
                    case "heartbeat" -> view.heartbeat(s.get("heartbeat"), (String) s.get("nonce"), (Long) s.get("at_ms"));
                    case "certificate" -> view.certificate(s.get("certificate"), (Long) s.get("at_ms"));
                    default -> view.status((Long) s.get("at_ms"));
                };
                check("agent/" + cs.get("name") + " step " + i + " (" + op + ")", got, s.get("expect"));
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String dir = args.length > 0 ? args[0] : "../../spec/conformance";
        Conformance r = new Conformance();
        r.run(dir);
        for (String f : r.fails) System.out.println("FAIL " + f);
        if (!r.fails.isEmpty()) {
            System.out.println("java: " + r.fails.size() + " of " + r.total + " vectors FAILED");
            System.exit(1);
        }
        System.out.println("java: " + r.total + "/" + r.total + " vectors passed");
    }
}
