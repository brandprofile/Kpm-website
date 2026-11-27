<?php
// KPM Car Transportation: Google Ads visit logger (to spot repeat clicks from the same IP).
// POST (beacon from our pages, only when the URL has gclid/gbraid/wbraid): stores IP, time, page, click ID, browser as one CSV row outside public_html.
// GET ?k=<secret>: returns all rows as CSV for the Google Sheet (=IMPORTDATA). Only the SHA-256 of the secret is stored here.
const KEY_HASH = 'dc136895ca2ffa6cc42b134c787aed0d74a7c44439acc60a0659c24021ba1efe';
$dir = dirname(__DIR__) . '/kpm-data';
$file = $dir . '/ad-visits.csv';
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $k = isset($_GET['k']) ? (string)$_GET['k'] : '';
  if (!hash_equals(KEY_HASH, hash('sha256', $k))) { http_response_code(404); exit; }
  header('Content-Type: text/csv; charset=utf-8');
  echo "Time (IST),IP,Forwarded IP,Click ID type,Click ID,Page,Campaign,Keyword,Referrer,Browser\n";
  if (is_file($file)) readfile($file);
  exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }

$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
if ($origin !== '' && !preg_match('#^https://(www\.)?cartransportation\.co\.in(/|$)#', $origin)) { http_response_code(403); exit; }
$raw = file_get_contents('php://input', false, null, 0, 4096);
$d = json_decode($raw ?: '{}', true);
if (!is_array($d)) { http_response_code(400); exit; }
$g = function ($k) use ($d) { $v = $d[$k] ?? ''; return is_scalar($v) ? trim((string)$v) : ''; };
$idType = $g('gclid') !== '' ? 'gclid' : ($g('gbraid') !== '' ? 'gbraid' : ($g('wbraid') !== '' ? 'wbraid' : ''));
if ($idType === '') { http_response_code(204); exit; }

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$fwd = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? ($_SERVER['HTTP_X_REAL_IP'] ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
$fwd = trim(explode(',', $fwd)[0]);
$dt = new DateTime('now', new DateTimeZone('Asia/Kolkata'));
$row = [$dt->format('d-M-Y H:i:s'), $ip, $fwd === $ip ? '' : $fwd, $idType, $g($idType), $g('page'), $g('utm_campaign'), $g('utm_term'), $g('ref'), $_SERVER['HTTP_USER_AGENT'] ?? ''];
$row = array_map(function ($c) { $c = preg_replace('/[\r\n\t]+/', ' ', (string)$c); $c = substr($c, 0, 300); return preg_match('/^[=@+\-]/', $c) ? ' ' . $c : $c; }, $row);
if (!is_dir($dir)) { mkdir($dir, 0700, true); file_put_contents($dir . '/.htaccess', "Require all denied\n"); }
$fh = fopen($file, 'a');
if ($fh && flock($fh, LOCK_EX)) { fputcsv($fh, $row); flock($fh, LOCK_UN); }
if ($fh) fclose($fh);
http_response_code(204);
