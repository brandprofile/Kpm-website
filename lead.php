<?php
// KPM Car Transportation: lead logger.
// POST (from the website): stores one lead / WhatsApp / call click as a CSV row outside public_html.
// GET ?k=<secret>: returns all rows as CSV for the Google Sheet (=IMPORTDATA). Only the SHA-256 of the secret is stored here.
const KEY_HASH = 'f26fc2c70fe8679bfc0023af4a7cd94c6e0a5717f8ac22508551f727c050358d';
$dir = dirname(__DIR__) . '/kpm-data';
$file = $dir . '/leads.csv';
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $k = isset($_GET['k']) ? (string)$_GET['k'] : '';
  if (!hash_equals(KEY_HASH, hash('sha256', $k))) { http_response_code(404); exit; }
  header('Content-Type: text/csv; charset=utf-8');
  if (is_file($file)) readfile($file);
  exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }

// Only accept posts sent by our own pages
$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
if ($origin !== '' && !preg_match('#^https://(www\.)?cartransportation\.co\.in(/|$)#', $origin)) { http_response_code(403); exit; }
$raw = file_get_contents('php://input', false, null, 0, 8192);
$d = json_decode($raw ?: '{}', true);
if (!is_array($d)) { http_response_code(400); exit; }

$labels = ['quote_form' => 'Quote form', 'entry_popup' => 'Call-back pop-up', 'routebar' => 'Route search', 'pricing_form' => 'Price check',
  'track_form' => 'Track my car', 'whatsapp_click' => 'WhatsApp button click', 'call_click' => 'Call button click'];
$g = function ($k) use ($d) { $v = $d[$k] ?? ''; return is_scalar($v) ? trim((string)$v) : ''; };
$type = $g('lead_type') ?: $g('form_name');
$used = ['access_key','time','lead_type','form_name','lead_id','Name','Phone','From','To','route_from','route_to','Car','Carrier','Date','page','lead_source','utm_campaign','utm_term','gclid','subject'];
$other = [];
foreach ($d as $k => $v) if (!in_array($k, $used, true) && is_scalar($v) && $v !== '') $other[] = $k . ': ' . $v;
$dt = new DateTime('now', new DateTimeZone('Asia/Kolkata'));
$row = [$dt->format('d-M-Y H:i:s'), $labels[$type] ?? $type, $g('lead_id'), $g('Name'), $g('Phone'),
  $g('From') ?: $g('route_from'), $g('To') ?: $g('route_to'), $g('Car'), $g('Carrier'), $g('Date'),
  $g('page'), $g('lead_source'), $g('utm_campaign'), $g('utm_term'), $g('gclid'), implode(' | ', $other)];
// Block spreadsheet formula injection and keep cells short
$row = array_map(function ($c) { $c = preg_replace('/[\r\n\t]+/', ' ', $c); $c = function_exists('mb_substr') ? mb_substr($c, 0, 300) : substr($c, 0, 300); return preg_match('/^[=@]/', $c) ? ' ' . $c : $c; }, $row);
if (!is_dir($dir)) { mkdir($dir, 0700, true); file_put_contents($dir . '/.htaccess', "Require all denied\n"); }
$fh = fopen($file, 'a');
if ($fh && flock($fh, LOCK_EX)) { fputcsv($fh, $row); flock($fh, LOCK_UN); }
if ($fh) fclose($fh);
http_response_code(204);
