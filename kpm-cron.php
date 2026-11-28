<?php
// KPM: hourly job (Hostinger cron, command line only; blocked from the web by .htaccess).
// Car-moving reminders to the owner's phone: 7 PM for tomorrow's pickups, 7 AM for today's pickups.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
date_default_timezone_set('Asia/Kolkata');
require_once __DIR__ . '/kpm-push-lib.php';
$dir = kpm_data_dir();
$read = function ($f) use ($dir) { $p = "$dir/$f"; return is_file($p) ? (json_decode((string)file_get_contents($p), true) ?: []) : []; };
$write = function ($f, $v) use ($dir) { file_put_contents("$dir/$f", json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)); chmod("$dir/$f", 0600); };

$hour = (int)date('G'); $force = in_array('--now', $argv ?? [], true);
if (!$force && $hour !== 7 && $hour !== 19) exit(0);
$when = ($hour >= 12 || ($force && $hour >= 12)) ? 'tomorrow' : 'today';
$day = date('Y-m-d', strtotime($when));
$sentKey = $day . '-' . $when;
$sent = $read('reminders-sent.json');
if (!empty($sent[$sentKey]) && !$force) exit(0);

$list = array_values(array_filter($read('moves.json'), function ($m) use ($day) { return ($m['date'] ?? '') === $day; }));
$sent[$sentKey] = date('c'); $sent = array_slice($sent, -60, null, true); $write('reminders-sent.json', $sent);
if (!$list) exit(0);

$lines = array_map(function ($m) {
  $bal = (int)($m['price'] ?? 0) - (int)($m['advance'] ?? 0);
  return trim($m['from'] . ' → ' . $m['to'] . ($m['car'] ? ', ' . $m['car'] : '') . (!empty($m['name']) ? ', ' . $m['name'] : '') . (!empty($m['phone']) ? ' ' . $m['phone'] : '') . ($bal > 0 ? ', balance ₹' . number_format($bal) : ''));
}, $list);
$title = ($when === 'tomorrow' ? '🚚 Tomorrow: ' : '🚚 Today: ') . count($list) . ' car pickup' . (count($list) > 1 ? 's' : '');
$write('notice.json', ['t' => time(), 'title' => $title, 'body' => implode("\n", $lines)]);
[$ok, $bad] = kpm_push_all();
echo date('c') . " $title: sent $ok, failed $bad\n";
