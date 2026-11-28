<?php
// KPM Car Transportation: public "recent car moves" + live offers, as JSON for the website.
// Only date, route and car model are ever sent. Names and phone numbers stay in ../kpm-data/ (see kpm-admin.php).
date_default_timezone_set('Asia/Kolkata');
if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'HEAD') { http_response_code(405); exit; }
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: public, max-age=300');
header('X-Robots-Tag: noindex');
$dir = dirname(__DIR__) . '/kpm-data';
$read = function ($f) use ($dir) { $p = "$dir/$f"; if (!is_file($p)) return []; $j = json_decode((string)file_get_contents($p), true); return is_array($j) ? $j : []; };
$today = date('Y-m-d');

$moves = [];
foreach ($read('moves.json') as $m) {
  if (empty($m['show']) || ($m['date'] ?? '') > $today) continue;
  $moves[] = ['date' => (string)$m['date'], 'from' => (string)$m['from'], 'to' => (string)$m['to'], 'car' => (string)($m['car'] ?? '')];
}
usort($moves, function ($a, $b) { return strcmp($b['date'], $a['date']); });

$offers = [];
foreach ($read('offers.json') as $o) {
  if (($o['start'] ?? '') > $today || ($o['end'] ?? '') < $today) continue;
  $offers[] = ['pct' => (int)$o['pct'], 'title' => (string)$o['title'], 'route' => (string)($o['route'] ?? ''), 'end' => (string)$o['end']];
}
echo json_encode(['moves' => array_slice($moves, 0, 60), 'offers' => $offers, 'total' => count($moves)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
