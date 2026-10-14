<?php
// php bin/conformance.php DIR: runs spec/conformance/*.json against the PHP port, as the Python runner does.
declare(strict_types=1);
require __DIR__ . '/../src/SmartSwitch.php';

use SmartTasks\SmartSwitch\{AgentView, State, SwitchError};
use function SmartTasks\SmartSwitch\{apply, canonical, decode, default_threshold, doc_hash, proposal_hash, replay, sha256_hex,
    validate_fleet, verify, verify_certificate};

$dir = $argv[1] ?? __DIR__ . '/../../../spec/conformance';
$load = fn (string $n) => decode(file_get_contents("$dir/$n"));
$c = function (mixed $v): string {
    try {
        return canonical($v);
    } catch (\InvalidArgumentException $e) {
        return '<not canonical: ' . $e->getMessage() . '>';
    }
};
$total = 0;
$fails = [];
$check = function (string $name, mixed $got, mixed $want) use (&$total, &$fails, $c): void {
    $total++;
    $g = $c($got);
    $w = $c($want);
    if ($g !== $w) $fails[] = "$name: got " . substr($g, 0, 300) . ', want ' . substr($w, 0, 300);
};
$pick = function (\stdClass $cs, array $keys): array {
    $out = [];
    foreach ($keys as $k) if (property_exists($cs, $k)) $out[$k] = $cs->{$k};
    return $out;
};

foreach ($load('canonical.json')->cases as $cs) {
    $text = $c($cs->input);
    $check("canonical/{$cs->name}", [$text, sha256_hex($text)], [$cs->canonical, $cs->sha256]);
}

foreach ($load('ed25519.json')->cases as $cs) {
    $check("ed25519/{$cs->name}", verify($cs->public_key, hex2bin($cs->message_hex), $cs->sig), $cs->valid);
}

$v = $load('fleets.json');
foreach ($v->default_thresholds as $cs) $check("fleets/default threshold n={$cs->n}", default_threshold($cs->n), $cs->k);
foreach ($v->cases as $cs) {
    try {
        validate_fleet($cs->fleet);
        $got = ['ok' => true, 'fleet_hash' => doc_hash($cs->fleet), 'threshold' => State::genesis($cs->fleet)->threshold];
    } catch (SwitchError $e) {
        $got = ['ok' => false, 'code' => $e->swCode];
    }
    $check("fleets/{$cs->name}", $got, $pick($cs, ['ok', 'fleet_hash', 'threshold', 'code']));
}

$v = $load('certificates.json');
foreach ($v->cases as $cs) {
    $st = State::genesis($v->fleets->{$cs->fleet});
    foreach ($cs->setup as $s) $st = apply($st, $s->certificate, $s->at_ms);
    $ph = null;
    if ($cs->certificate instanceof \stdClass && property_exists($cs->certificate, 'proposal')) {
        try {
            $ph = proposal_hash($cs->certificate->proposal);
        } catch (\InvalidArgumentException) {
            $ph = null;
        }
    }
    $check("certificates/{$cs->name} (proposal hash)", $ph, $cs->proposal_hash);
    try {
        if ($cs->ahead) {
            verify_certificate($st, $cs->certificate, $cs->at_ms, true);
            $got = ['ok' => true, 'state' => null];
        } else {
            $got = ['ok' => true, 'state' => apply($st, $cs->certificate, $cs->at_ms)->summary()];
        }
    } catch (SwitchError $e) {
        $got = ['ok' => false, 'code' => $e->swCode];
    }
    $check("certificates/{$cs->name}", $got, $pick($cs, ['ok', 'state', 'code']));
}

foreach ($load('logs.json')->cases as $cs) $check("logs/{$cs->name}", replay($cs->entries, $cs->pinned), $cs->result);

$v = $load('agent.json');
foreach ($v->cases as $cs) {
    $view = new AgentView($v->fleet, $cs->agent_id, $cs->instance_id);
    foreach ($cs->steps as $i => $s) {
        $got = match ($s->op) {
            'log' => $view->log($s->entries),
            'heartbeat' => $view->heartbeat($s->heartbeat, $s->nonce, $s->at_ms),
            'certificate' => $view->certificate($s->certificate, $s->at_ms),
            default => $view->status($s->at_ms),
        };
        $check("agent/{$cs->name} step $i ({$s->op})", $got, $s->expect);
    }
}

foreach ($fails as $f) echo "FAIL $f\n";
if ($fails) {
    echo 'php: ' . count($fails) . " of $total vectors FAILED\n";
    exit(1);
}
echo "php: $total/$total vectors passed\n";
