package cloud.smarttasks.smartswitch;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** The interop agent for ports/conformance/interop.py: URL FLEET_FILE AGENT_ID INSTANCE_ID, token in
 *  SMARTSWITCH_AGENT_TOKEN. Polls every 100 ms and prints "STATUS code" on every change; exits when
 *  standard input closes or after 60 s. */
public final class Interop {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: Interop URL FLEET_FILE AGENT_ID INSTANCE_ID");
            System.exit(2);
        }
        Agent ag = new Agent(args[0], System.getenv("SMARTSWITCH_AGENT_TOKEN"), Agent.loadFleet(Path.of(args[1])),
            args[2], args[3], 100, Duration.ofSeconds(1));
        CountDownLatch done = new CountDownLatch(1);
        Thread reader = new Thread(() -> {
            InputStream in = System.in;
            byte[] buf = new byte[4096];
            try {
                while (in.read(buf) >= 0) { /* discard */ }
            } catch (IOException e) {
                // treat as closed
            }
            done.countDown();
        }, "stdin");
        reader.setDaemon(true);
        reader.start();
        long end = System.nanoTime() + 60_000_000_000L;
        String last = null;
        while (done.getCount() > 0 && System.nanoTime() < end) {
            String code;
            try {
                code = (String) ag.pollOnce().get("code");
            } catch (Throwable e) {   // survive anything: the status alone decides
                System.err.println("poll failed: " + e);
                code = (String) ag.status().get("code");
            }
            if (!code.equals(last)) {
                System.out.println("STATUS " + code);
                System.out.flush();
                last = code;
            }
            done.await(100, TimeUnit.MILLISECONDS);
        }
        System.exit(0);
    }
}
