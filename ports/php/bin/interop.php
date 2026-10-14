<?php
// The interop agent for ports/conformance/interop.py: php bin/interop.php URL FLEET_FILE AGENT_ID INSTANCE_ID,
// token in SMARTSWITCH_AGENT_TOKEN. Polls every 100 ms and prints "STATUS code" on every change; exits when
// standard input closes or after 60 s.
declare(strict_types=1);
require __DIR__ . '/../src/SmartSwitch.php';

use SmartTasks\SmartSwitch\Agent;
use function SmartTasks\SmartSwitch\load_fleet;

if ($argc !== 5) {
    fwrite(STDERR, "usage: php bin/interop.php URL FLEET_FILE AGENT_ID INSTANCE_ID\n");
    exit(2);
}
[, $url, $fleetFile, $agentId, $instanceId] = $argv;
$token = getenv('SMARTSWITCH_AGENT_TOKEN');
$ag = new Agent($url, $token === false ? null : $token, load_fleet($fleetFile), $agentId, $instanceId, 100, 1.0);

stream_set_blocking(STDIN, false);
$end = hrtime(true) + 60_000_000_000;
$last = null;
while (hrtime(true) < $end) {
    $code = $ag->pollOnce()['code'];
    if ($code !== $last) {
        echo "STATUS $code\n";
        fflush(STDOUT);
        $last = $code;
    }
    $r = [STDIN];
    $w = null;
    $x = null;
    if (@stream_select($r, $w, $x, 0, 100000) > 0) {
        $data = fread(STDIN, 8192);
        if (($data === '' || $data === false) && feof(STDIN)) break;
    }
}
