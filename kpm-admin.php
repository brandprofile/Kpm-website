<?php
// KPM Car Transportation: private owner page.
//   - Daily website leads (read from ../kpm-data/leads.csv, written by lead.php)
//   - Mark a lead as "Converted" (or add a phone booking by hand) -> shows on the site as a "recent car move"
//     with only date, route and car model. Customer name and phone never leave this page.
//   - Offers (percent off, with a real start and end date) -> shown on the site only while active.
// All data stays in ../kpm-data/ (outside public_html, blocked by its own .htaccess).
// Login: one password. Only its bcrypt hash is here; a changed password is stored as a hash in ../kpm-data/admin.json.

const DEFAULT_PASS_HASH = '$2y$12$iiXPGlXCPWAgIx.payxQyeOO1aIwLGY.fff3CmozIbW7dLvmKuEBe';
const COOKIE = 'kpm_admin';
const SESSION_DAYS = 30;
const MAX_FAILS = 5;          // wrong passwords allowed per IP ...
const LOCK_MINUTES = 15;      // ... within this many minutes
const ADS_TOKEN_HASH = '8188300d8eb1182bea06cd32d49af1e38140a1d6635d1587ba94639d6f1cd1f4'; // Google Ads Script posts daily spend with this token (only its hash is here)

date_default_timezone_set('Asia/Kolkata');
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Referrer-Policy: same-origin'); // no-referrer would make browsers send Origin: null on our own POSTs
header('X-Frame-Options: DENY');

$DIR = dirname(__DIR__) . '/kpm-data';
if (!is_dir($DIR)) { mkdir($DIR, 0700, true); }
if (!is_file($DIR . '/.htaccess')) file_put_contents($DIR . '/.htaccess', "Require all denied\n");

function jread($f, $def) { global $DIR; $p = "$DIR/$f"; if (!is_file($p)) return $def; $j = json_decode((string)file_get_contents($p), true); return is_array($j) ? $j : $def; }
function jwrite($f, $v) { global $DIR; $p = "$DIR/$f"; $t = "$p.tmp" . bin2hex(random_bytes(3)); file_put_contents($t, json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX); chmod($t, 0600); rename($t, $p); }
function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function clean($s, $n = 80) { $s = trim(preg_replace('/[\x00-\x1F\x7F<>"`]+/u', ' ', (string)$s)); $s = preg_replace('/\s+/u', ' ', $s); return function_exists('mb_substr') ? mb_substr($s, 0, $n) : substr($s, 0, $n); }
function okdate($s) { return preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$s) && strtotime($s) ? $s : ''; }

// ---------- secret + password ----------
$secretFile = "$DIR/admin-secret";
if (!is_file($secretFile)) { file_put_contents($secretFile, bin2hex(random_bytes(32))); chmod($secretFile, 0600); }
$SECRET = trim((string)file_get_contents($secretFile));
$cfg = jread('admin.json', []);
$PASS_HASH = $cfg['pass_hash'] ?? DEFAULT_PASS_HASH;
$PASS_VER = substr(hash('sha256', $PASS_HASH), 0, 12); // changing the password logs out every device

function sign($exp) { global $SECRET, $PASS_VER; return hash_hmac('sha256', $exp . '|' . $PASS_VER, $SECRET); }
function logged_in() {
  $c = $_COOKIE[COOKIE] ?? '';
  if (!preg_match('/^(\d{10})\.([a-f0-9]{64})$/', $c, $m)) return false;
  return (int)$m[1] > time() && hash_equals(sign($m[1]), $m[2]);
}
// Lax, not Strict: Strict cookies are not sent when the page is opened from the home-screen app, a notification
// or a WhatsApp link, which made it ask for the password every time. POSTs stay protected by the CSRF token + Origin check.
function set_cookie($val, $exp) {
  setcookie(COOKIE, $val, ['expires' => $exp, 'path' => '/kpm-admin.php', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
}
function csrf() { global $SECRET; return hash_hmac('sha256', 'csrf|' . ($_COOKIE[COOKIE] ?? ''), $SECRET); }
function ip() { return $_SERVER['REMOTE_ADDR'] ?? '0'; }

$self = '/kpm-admin.php';
$msg = '';

// ---------- newest lead for the phone notification (service worker, owner cookie required) ----------
function newest_lead() {
  global $DIR; $fh = @fopen("$DIR/leads.csv", 'r'); if (!$fh) return null; $last = null;
  while (($line = fgets($fh)) !== false) { $r = str_getcsv($line); if (count($r) >= 7 && stripos($r[1], 'click') === false) $last = $r; }
  fclose($fh); return $last;
}
if (isset($_GET['latest'])) {
  header('Content-Type: application/json');
  if (!logged_in()) { http_response_code(401); exit('{"error":"login"}'); }
  $test = jread('push-test.json', []);
  if (($test['t'] ?? 0) > time() - 120) { jwrite('push-test.json', []); exit('{"test":true}'); }
  $n = jread('notice.json', []);   // car-moving reminders queued by kpm-cron.php
  if (($n['t'] ?? 0) > time() - 300) { jwrite('notice.json', []); exit(json_encode(['notice' => ['title' => $n['title'], 'body' => $n['body']]], JSON_UNESCAPED_UNICODE)); }
  $r = newest_lead();
  exit(json_encode(['lead' => $r ? ['time' => substr($r[0], 12, 5), 'type' => trim($r[1]), 'name' => trim($r[3]), 'phone' => trim($r[4]), 'from' => $r[5], 'to' => $r[6], 'car' => $r[7]] : null], JSON_UNESCAPED_UNICODE));
}

// ---------- POST actions ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  if ($origin !== '' && !preg_match('#^https://(www\.)?cartransportation\.co\.in$#', $origin)) { http_response_code(403); exit('Forbidden'); }
  $a = $_POST['a'] ?? '';

  if ($a === 'ads_in') {   // from the Google Ads Script in KPM's ad account (no login cookie, token instead)
    header('Content-Type: application/json');
    if (!hash_equals(ADS_TOKEN_HASH, hash('sha256', (string)($_POST['k'] ?? '')))) { http_response_code(403); exit('{"ok":false}'); }
    $in = json_decode((string)($_POST['rows'] ?? '[]'), true); $ads = jread('ads-daily.json', []); $n = 0;
    if (is_array($in)) foreach ($in as $r) {
      $d = okdate($r['date'] ?? ''); if (!$d) continue;
      $ads[$d] = ['cost' => round((float)($r['cost'] ?? 0), 2), 'clicks' => (int)($r['clicks'] ?? 0), 'impr' => (int)($r['impr'] ?? 0), 'conv' => round((float)($r['conv'] ?? 0), 1), 'calls' => (int)($r['calls'] ?? 0)]; $n++;
    }
    ksort($ads); $ads['_updated'] = date('c'); jwrite('ads-daily.json', $ads);
    exit(json_encode(['ok' => true, 'days' => $n]));
  }
  if ($a === 'login') {
    $fails = jread('login-fails.json', []);
    $now = time();
    foreach ($fails as $k => $v) if ($v['t'] < $now - LOCK_MINUTES * 60) unset($fails[$k]);
    $key = hash('sha256', ip());
    if (($fails[$key]['n'] ?? 0) >= MAX_FAILS) { $msg = 'Too many wrong tries. Wait ' . LOCK_MINUTES . ' minutes.'; }
    elseif (password_verify((string)($_POST['p'] ?? ''), $PASS_HASH)) {
      unset($fails[$key]); jwrite('login-fails.json', $fails);
      $exp = time() + SESSION_DAYS * 86400; set_cookie($exp . '.' . sign($exp), $exp);
      header("Location: $self"); exit;
    } else {
      $fails[$key] = ['n' => ($fails[$key]['n'] ?? 0) + 1, 't' => $now]; jwrite('login-fails.json', $fails);
      usleep(700000); $msg = 'Wrong password.';
    }
  } elseif (logged_in() && hash_equals(csrf(), (string)($_POST['t'] ?? ''))) {
    $back = $self . '?' . http_build_query(array_intersect_key($_GET, ['tab' => 1, 'd' => 1, 'all' => 1, 'from' => 1, 'to' => 1, 'g' => 1]));
    if ($a === 'push_sub' || $a === 'push_test') {
      header('Content-Type: application/json');
      require_once __DIR__ . '/kpm-push-lib.php';
      if ($a === 'push_sub') {
        $sub = json_decode((string)($_POST['sub'] ?? ''), true);
        $ep = is_array($sub) ? (string)($sub['endpoint'] ?? '') : '';
        if (!preg_match('#^https://[a-z0-9.-]+/#i', $ep) || strlen($ep) > 600) exit('{"ok":false}');
        $subs = array_values(array_filter(jread('push-subs.json', []), function ($x) use ($ep) { return ($x['endpoint'] ?? '') !== $ep; }));
        $subs[] = ['endpoint' => $ep, 'added' => date('c'), 'ua' => clean($_SERVER['HTTP_USER_AGENT'] ?? '', 120)];
        jwrite('push-subs.json', array_slice($subs, -10));
        exit(json_encode(['ok' => true, 'phones' => count($subs)]));
      }
      jwrite('push-test.json', ['t' => time()]);
      [$ok, $bad] = kpm_push_all();
      exit(json_encode(['ok' => $ok > 0, 'sent' => $ok, 'failed' => $bad]));
    }
    if ($a === 'logout') { set_cookie('', time() - 3600); header("Location: $self"); exit; }
    if ($a === 'convert' || $a === 'addmove') {
      $moves = jread('moves.json', []);
      $m = ['id' => bin2hex(random_bytes(6)), 'lead' => preg_replace('/[^a-f0-9]/', '', (string)($_POST['lead'] ?? '')),
        'date' => okdate($_POST['date'] ?? '') ?: date('Y-m-d'), 'from' => clean($_POST['from'] ?? '', 40), 'to' => clean($_POST['to'] ?? '', 40),
        'car' => clean($_POST['car'] ?? '', 40), 'show' => !empty($_POST['show']), 'added' => date('c'),
        'name' => clean($_POST['name'] ?? '', 60), 'phone' => preg_replace('/[^0-9+ ]/', '', (string)($_POST['phone'] ?? '')),
        'price' => max(0, (int)($_POST['price'] ?? 0)), 'advance' => max(0, (int)($_POST['advance'] ?? 0)), 'note' => clean($_POST['note'] ?? '', 120)];
      if ($m['from'] !== '' && $m['to'] !== '') { array_unshift($moves, $m); jwrite('moves.json', $moves); }
      header("Location: $back"); exit;
    }
    if ($a === 'lead_hide' || $a === 'lead_unhide') {
      $k = preg_replace('/[^a-f0-9]/', '', (string)($_POST['lead'] ?? ''));
      $hid = jread('hidden-leads.json', []);
      if ($a === 'lead_hide' && strlen($k) === 40) $hid[$k] = date('c'); else unset($hid[$k]);
      jwrite('hidden-leads.json', $hid); header("Location: $back"); exit;
    }
    if ($a === 'move_pay') {
      $id = (string)($_POST['id'] ?? ''); $moves = jread('moves.json', []);
      foreach ($moves as $i => $m) if ($m['id'] === $id) {
        $moves[$i]['price'] = max(0, (int)($_POST['price'] ?? 0)); $moves[$i]['advance'] = max(0, (int)($_POST['advance'] ?? 0));
        $moves[$i]['date'] = okdate($_POST['date'] ?? '') ?: $m['date']; $moves[$i]['note'] = clean($_POST['note'] ?? '', 120);
      }
      jwrite('moves.json', $moves); header("Location: $back"); exit;
    }
    if ($a === 'move_toggle' || $a === 'move_del') {
      $id = (string)($_POST['id'] ?? ''); $moves = jread('moves.json', []);
      foreach ($moves as $i => $m) if ($m['id'] === $id) { if ($a === 'move_del') unset($moves[$i]); else $moves[$i]['show'] = !$m['show']; }
      jwrite('moves.json', array_values($moves)); header("Location: $back"); exit;
    }
    if ($a === 'offer_add') {
      $o = ['id' => bin2hex(random_bytes(6)), 'pct' => max(1, min(50, (int)($_POST['pct'] ?? 0))), 'title' => clean($_POST['title'] ?? '', 70),
        'route' => clean($_POST['route'] ?? '', 60), 'start' => okdate($_POST['start'] ?? '') ?: date('Y-m-d'), 'end' => okdate($_POST['end'] ?? ''), 'added' => date('c')];
      if ($o['end'] !== '' && $o['end'] >= $o['start']) { $offers = jread('offers.json', []); array_unshift($offers, $o); jwrite('offers.json', $offers); }
      header("Location: $back"); exit;
    }
    if ($a === 'offer_del') {
      $id = (string)($_POST['id'] ?? ''); $offers = array_values(array_filter(jread('offers.json', []), function ($o) use ($id) { return $o['id'] !== $id; }));
      jwrite('offers.json', $offers); header("Location: $back"); exit;
    }
    if ($a === 'pass') {
      $old = (string)($_POST['old'] ?? ''); $new = (string)($_POST['new'] ?? '');
      if (!password_verify($old, $PASS_HASH)) $msg = 'Old password is wrong.';
      elseif (strlen($new) < 10) $msg = 'New password must be at least 10 characters.';
      else { $cfg['pass_hash'] = password_hash($new, PASSWORD_DEFAULT); jwrite('admin.json', $cfg); set_cookie('', time() - 3600); header("Location: $self?changed=1"); exit; }
    }
  } else {
    if (in_array($a, ['push_sub', 'push_test'], true)) { header('Content-Type: application/json'); http_response_code(401); exit('{"ok":false,"error":"login"}'); }
    $msg = 'Session expired. Please log in again.';
  }
}

// ---------- page ----------
$in = logged_in();
// Keep the owner logged in: every visit renews the 30 days (and upgrades old cookies to Lax).
if ($in && $_SERVER['REQUEST_METHOD'] === 'GET') { $exp = time() + SESSION_DAYS * 86400; set_cookie($exp . '.' . sign($exp), $exp); $_COOKIE[COOKIE] = $exp . '.' . sign($exp); }
$tab = in_array($_GET['tab'] ?? '', ['leads', 'moves', 'reports', 'offers', 'settings'], true) ? $_GET['tab'] : 'leads';
$days = in_array($_GET['d'] ?? '', ['1', '7', '30', 'all'], true) ? $_GET['d'] : ($tab === 'reports' ? '30' : '7');
$all = !empty($_GET['all']);
$from = okdate($_GET['from'] ?? ''); $to = okdate($_GET['to'] ?? '');
if ($from || $to) { $days = 'custom'; if (!$from) $from = '2026-11-01'; if (!$to) $to = date('Y-m-d'); if ($to < $from) [$from, $to] = [$to, $from]; }
$grp = in_array($_GET['g'] ?? '', ['day', 'week', 'month'], true) ? $_GET['g'] : 'day';
// Selected period as [start timestamp, end timestamp]
$range = $days === 'custom' ? [strtotime($from), strtotime($to) + 86399] : ($days === 'all' ? [0, PHP_INT_MAX] : [strtotime('today') - ((int)$days - 1) * 86400, PHP_INT_MAX]);
$q = function ($extra) use ($tab, $days, $all, $from, $to, $grp) {
  $base = ['tab' => $tab, 'd' => $days === 'custom' ? null : $days, 'all' => $all ? 1 : null, 'from' => $days === 'custom' ? $from : null, 'to' => $days === 'custom' ? $to : null, 'g' => $grp !== 'day' ? $grp : null];
  if (isset($extra['d'])) { $base['from'] = null; $base['to'] = null; }
  return '?' . http_build_query(array_merge($base, $extra));
};
function inr($n) { $n = (int)round($n); $s = (string)abs($n); if (strlen($s) > 3) { $l = substr($s, -3); $s = substr($s, 0, -3); $s = preg_replace('/\B(?=(\d{2})+(?!\d))/', ',', $s) . ',' . $l; } return ($n < 0 ? '-' : '') . '₹' . $s; }
function read_leads() {
  global $DIR; $rows = []; $fh = @fopen("$DIR/leads.csv", 'r');
  if ($fh) { while (($line = fgets($fh)) !== false) { $r = str_getcsv($line); if (count($r) < 7) continue; $r['key'] = sha1(rtrim($line, "\r\n"));
    $r['ts'] = strtotime(str_replace('-', ' ', substr($r[0], 0, 11)) . ' ' . substr($r[0], 12)); $r['click'] = stripos($r[1], 'click') !== false;
    $r['ads'] = ($r[14] ?? '') !== '' || stripos($r[11] ?? '', 'google') !== false; $rows[] = $r; } fclose($fh); }
  return $rows;
}
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>KPM Owner Login</title>
<link rel="manifest" href="/kpm-admin.webmanifest"><meta name="theme-color" content="#0e1a2e"><link rel="icon" href="/kpm-admin-192.png"><link rel="apple-touch-icon" href="/kpm-admin-192.png">
<style>
:root{--navy:#0e1a2e;--red:#d42a3c;--bg:#f3f5f9;--card:#fff;--line:#e2e6ee;--mut:#5d6778;--ok:#11823b}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--navy)}
header{background:var(--navy);color:#fff;padding:12px 16px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:5}
header b{flex:1}header form{margin:0}
.wrap{max-width:860px;margin:0 auto;padding:14px 16px 60px}
nav{display:flex;gap:6px;overflow-x:auto;margin-bottom:12px}nav a{padding:8px 14px;border-radius:99px;background:#fff;border:1px solid var(--line);color:var(--navy);text-decoration:none;white-space:nowrap;font-weight:600}
nav a.on{background:var(--red);border-color:var(--red);color:#fff}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:0 0 12px}.bar a{font-size:13px;padding:5px 10px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--navy);text-decoration:none}.bar a.on{background:var(--navy);color:#fff}
h2{font-size:15px;margin:18px 0 8px;display:flex;justify-content:space-between;color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:8px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.grow{flex:1;min-width:0}
.t{font-size:12px;color:var(--mut)}.nm{font-weight:700}.rt{font-weight:600}
.tag{font-size:11px;padding:2px 8px;border-radius:99px;background:#eef1f6;color:var(--mut);font-weight:600}.tag.ads{background:#fff3d6;color:#8a5a00}.tag.ok{background:#e2f6e9;color:var(--ok)}
.btn,button{font:inherit;font-weight:600;border:0;border-radius:9px;padding:8px 12px;cursor:pointer;background:var(--navy);color:#fff;text-decoration:none;display:inline-block}
.btn.g{background:#1faa53}.btn.l,button.l{background:#eef1f6;color:var(--navy)}button.r{background:var(--red)}
details summary{list-style:none;cursor:pointer}details summary::-webkit-details-marker{display:none}
.f{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}.f label{font-size:12px;color:var(--mut);display:flex;flex-direction:column;gap:3px}.f .full{grid-column:1/-1}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line);border-radius:8px;width:100%;background:#fff}
input[type=checkbox]{width:auto}
.msg{background:#fde8ea;color:#8b1424;padding:10px 12px;border-radius:9px;margin-bottom:10px}
.login{max-width:340px;margin:12vh auto;padding:0 16px}.login .card{padding:20px}
.empty{color:var(--mut);text-align:center;padding:30px 0}
[hidden]{display:none!important}
.dr input{width:auto;flex:1;min-width:0;padding:6px 8px;font-size:14px}.dr button{padding:6px 12px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;margin-bottom:10px}.kpi{background:#fff;border:1px solid var(--line);border-radius:12px;padding:10px 12px}.kpi b{display:block;font-size:20px}.kpi span{font-size:12px;color:var(--mut)}
.tw{overflow-x:auto;background:#fff;border:1px solid var(--line);border-radius:12px}table.rp{border-collapse:collapse;width:100%;font-size:13px;white-space:nowrap}.rp th,.rp td{padding:8px 10px;text-align:right;border-bottom:1px solid var(--line)}.rp th:first-child,.rp td:first-child{text-align:left;position:sticky;left:0;background:#fff}.rp th{font-size:11px;color:var(--mut);font-weight:600}.rp tr.tot td{font-weight:700;background:#f7f8fb}
.barv{display:inline-block;height:8px;border-radius:4px;background:var(--red);vertical-align:middle;margin-left:6px}
@media(max-width:520px){.f{grid-template-columns:1fr}}
</style></head><body>
<?php if (!$in): ?>
<div class="login"><div class="card">
  <h1 style="font-size:20px;margin:0 0 4px">KPM owner login</h1><p class="t" style="margin:0 0 14px">Private page. Leads, recent moves and offers.</p>
  <?php if (!empty($_GET['changed'])): ?><div class="msg" style="background:#e2f6e9;color:#11823b">Password changed. Log in with the new one.</div><?php endif; ?>
  <?php if ($msg): ?><div class="msg"><?= h($msg) ?></div><?php endif; ?>
  <form method="post" action="<?= $self ?>"><input type="hidden" name="a" value="login">
    <input type="password" name="p" placeholder="Password" autocomplete="current-password" required autofocus>
    <button style="width:100%;margin-top:10px">Log in</button></form>
</div></div>
<?php else:
  $t = h(csrf());
  $hid = function ($a) use ($t) { return '<input type="hidden" name="a" value="' . $a . '"><input type="hidden" name="t" value="' . $t . '">'; };
  $dateBar = function () use ($q, $days, $from, $to, $tab, $all, $grp) {
    $o = '<div class="bar">';
    foreach (['1' => 'Today', '7' => '7 days', '30' => '30 days', 'all' => 'All'] as $k => $v) $o .= '<a href="' . h($q(['d' => $k])) . '" class="' . ($days === (string)$k ? 'on' : '') . '">' . $v . '</a>';
    $o .= '</div><form method="get" class="bar dr"><input type="hidden" name="tab" value="' . h($tab) . '">' . ($all ? '<input type="hidden" name="all" value="1">' : '') . ($grp !== 'day' ? '<input type="hidden" name="g" value="' . h($grp) . '">' : '')
      . '<input type="date" name="from" value="' . h($from) . '" aria-label="From date"><span class="t">to</span><input type="date" name="to" value="' . h($to ?: date('Y-m-d')) . '" aria-label="To date"><button class="' . ($days === 'custom' ? '' : 'l') . '">Show</button></form>';
    return $o;
  };
  $moves = jread('moves.json', []);
  $convertedLeads = []; foreach ($moves as $m) if (!empty($m['lead'])) $convertedLeads[$m['lead']] = $m;
?>
<header><b>KPM Owner</b><form method="post" action="<?= $self ?>"><?= $hid('logout') ?><button class="l">Log out</button></form></header>
<div class="wrap">
<?php if ($msg): ?><div class="msg"><?= h($msg) ?></div><?php endif; ?>
<nav>
  <a href="?tab=leads" class="<?= $tab === 'leads' ? 'on' : '' ?>">Leads</a>
  <a href="?tab=moves" class="<?= $tab === 'moves' ? 'on' : '' ?>">Bookings (<?= count($moves) ?>)</a>
  <a href="?tab=reports" class="<?= $tab === 'reports' ? 'on' : '' ?>">Reports</a>
  <a href="?tab=offers" class="<?= $tab === 'offers' ? 'on' : '' ?>">Offers</a>
  <a href="?tab=settings" class="<?= $tab === 'settings' ? 'on' : '' ?>">Password</a>
</nav>

<?php if ($tab === 'leads'): ?>
  <div class="card" id="alerts" style="background:#fff8e6;border-color:#f1dca4">
    <b>🔔 New lead alerts</b><div class="t" id="al-st" style="margin:2px 0 10px">Get a phone notification with sound for every new form lead.</div>
    <div class="row"><button type="button" id="al-on">Turn on alerts</button><button type="button" class="l" id="al-test" hidden>Send test alert</button></div>
  </div>
<?php
  $rows = read_leads();
  $hidden = jread('hidden-leads.json', []);
  // One time (mark, 2026-11-28): remove his own test leads named "Manu". They stay under "Removed leads" and can be restored.
  if (empty($cfg['hid_manu'])) {
    foreach ($rows as $r) if (preg_match('/\bmanu\b/i', $r[3])) $hidden[$r['key']] = date('c');
    jwrite('hidden-leads.json', $hidden); $cfg['hid_manu'] = 1; jwrite('admin.json', $cfg);
  }
  $hiddenRows = array_values(array_filter($rows, function ($r) use ($hidden) { return isset($hidden[$r['key']]); }));
  $rows = array_values(array_filter($rows, function ($r) use ($hidden) { return !isset($hidden[$r['key']]); }));
  $rows = array_reverse($rows);
  $groups = [];
  foreach ($rows as $r) {
    $ts = $r['ts'];
    if ($ts === false || $ts < $range[0] || $ts > $range[1]) continue;
    if ($r['click'] && !$all) continue;
    $groups[date('Y-m-d', $ts)][] = $r;
  }
  krsort($groups);
  foreach ($groups as &$gl) usort($gl, function ($a, $b) { return $b['ts'] <=> $a['ts']; });
  unset($gl);
?>
  <?= $dateBar() ?>
  <div class="bar"><a href="<?= h($q(['all' => $all ? null : 1])) ?>" class="<?= $all ? 'on' : '' ?>"><?= $all ? '✓ ' : '' ?>Show WhatsApp / call taps</a></div>
  <?php if (!$groups): ?><div class="empty">No leads in this period.</div><?php endif; ?>
  <?php foreach ($groups as $day => $list): ?>
    <h2><span><?= date('D, j M Y', strtotime($day)) ?></span><span><?= count($list) ?></span></h2>
    <?php foreach ($list as $r):
      $phone = preg_replace('/[^0-9+]/', '', $r[4]); $wa = preg_replace('/\D/', '', $phone); if (strlen($wa) === 10) $wa = '91' . $wa;
      $conv = $convertedLeads[$r['key']] ?? null; $ads = $r[14] !== '' || stripos($r[11], 'google') !== false || stripos($r[12], 'KPM') !== false;
      $route = trim($r[5] . ($r[6] !== '' ? ' → ' . $r[6] : ''));
    ?>
    <div class="card">
      <div class="row">
        <div class="grow">
          <div class="row"><span class="t"><?= date('g:i A', $r['ts']) ?></span><span class="tag"><?= h($r[1]) ?></span><?php if ($ads): ?><span class="tag ads">Google Ads</span><?php endif; ?><?php if ($conv): ?><span class="tag ok">✓ Converted</span><?php endif; ?></div>
          <?php if ($r[3] !== '' || $phone !== ''): ?><div class="nm"><?= h($r[3] ?: 'No name') ?> <?php if ($phone): ?><span class="t"><?= h($r[4]) ?></span><?php endif; ?></div><?php endif; ?>
          <?php if ($route): ?><div class="rt"><?= h($route) ?></div><?php endif; ?>
          <div class="t"><?= h(implode(' · ', array_filter([$r[7], $r[8], $r[9] ? 'Date: ' . $r[9] : '', $r[13] ? 'Searched: ' . $r[13] : '', $r[10]]))) ?></div>
        </div>
        <?php if ($phone): ?><a class="btn l" href="tel:<?= h($phone) ?>">Call</a><a class="btn g" href="https://wa.me/<?= h($wa) ?>" target="_blank" rel="noopener">WhatsApp</a><?php endif; ?>
      </div>
      <form method="post" action="<?= h($self . $q([])) ?>" onsubmit="return confirm('Remove this lead from the list? (test / spam)')" style="float:right;margin-top:8px"><?= $hid('lead_hide') ?><input type="hidden" name="lead" value="<?= h($r['key']) ?>"><button class="l" style="font-size:13px;padding:6px 10px">Remove</button></form>
      <?php if (!$conv && !$r['click']): ?>
      <details><summary class="btn l" style="margin-top:8px">Mark converted</summary>
        <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('convert') ?><input type="hidden" name="lead" value="<?= h($r['key']) ?>">
          <label>From<input name="from" value="<?= h($r[5]) ?>" required maxlength="40"></label>
          <label>To<input name="to" value="<?= h($r[6]) ?>" required maxlength="40"></label>
          <label>Car model<input name="car" value="<?= h($r[7]) ?>" maxlength="40" placeholder="e.g. Hyundai Creta"></label>
          <label>Pickup date<input type="date" name="date" value="<?= h(okdate($r[9]) ?: date('Y-m-d')) ?>"></label>
          <label>Total price ₹<input type="number" name="price" inputmode="numeric" min="0" placeholder="e.g. 18000"></label>
          <label>Advance received ₹<input type="number" name="advance" inputmode="numeric" min="0" placeholder="e.g. 3000"></label>
          <input type="hidden" name="name" value="<?= h($r[3]) ?>"><input type="hidden" name="phone" value="<?= h($r[4]) ?>">
          <label class="full" style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="show" value="1" checked> Show on website (only date, route and car; never name, phone or price)</label>
          <button class="full">Save as converted</button>
        </form></details>
      <?php endif; ?>
    </div>
    <?php endforeach; ?>
  <?php endforeach; ?>

  <?php if ($hiddenRows): ?>
  <details style="margin-top:18px"><summary class="t">Removed leads (<?= count($hiddenRows) ?>) · tap to see / restore</summary>
    <?php foreach (array_reverse($hiddenRows) as $r): ?>
      <div class="card row" style="opacity:.7"><div class="grow"><span class="t"><?= h($r[0]) ?></span> <b><?= h($r[3] ?: 'No name') ?></b> <span class="t"><?= h($r[4]) ?> <?= h(trim($r[5] . ' → ' . $r[6], ' →')) ?></span></div>
        <form method="post" action="<?= h($self . $q([])) ?>"><?= $hid('lead_unhide') ?><input type="hidden" name="lead" value="<?= h($r['key']) ?>"><button class="l">Restore</button></form></div>
    <?php endforeach; ?>
  </details>
  <?php endif; ?>

<?php elseif ($tab === 'moves'):
  $today = date('Y-m-d'); $up = array_filter($moves, function ($m) use ($today) { return $m['date'] >= $today; });
  $sumP = 0; $sumA = 0; foreach ($moves as $m) { $sumP += $m['price'] ?? 0; $sumA += $m['advance'] ?? 0; }
  usort($moves, function ($a, $b) use ($today) { $fa = $a['date'] >= $today; $fb = $b['date'] >= $today; if ($fa !== $fb) return $fa ? -1 : 1; return $fa ? strcmp($a['date'], $b['date']) : strcmp($b['date'], $a['date']); });
?>
  <div class="kpis"><div class="kpi"><b><?= count($up) ?></b><span>Upcoming pickups</span></div><div class="kpi"><b><?= inr($sumP) ?></b><span>Total booked</span></div><div class="kpi"><b><?= inr($sumA) ?></b><span>Advance received</span></div><div class="kpi"><b><?= inr($sumP - $sumA) ?></b><span>Balance to collect</span></div></div>
  <details class="card"><summary class="btn">+ Add a booking (phone / walk-in)</summary>
    <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('addmove') ?>
      <label>Customer name<input name="name" maxlength="60"></label>
      <label>Phone<input name="phone" inputmode="tel" maxlength="20"></label>
      <label>From<input name="from" required maxlength="40" placeholder="Kozhikode"></label>
      <label>To<input name="to" required maxlength="40" placeholder="Bangalore"></label>
      <label>Car model<input name="car" maxlength="40" placeholder="Toyota Innova"></label>
      <label>Pickup date<input type="date" name="date" value="<?= $today ?>"></label>
      <label>Total price ₹<input type="number" name="price" inputmode="numeric" min="0"></label>
      <label>Advance received ₹<input type="number" name="advance" inputmode="numeric" min="0"></label>
      <label class="full" style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="show" value="1" checked> Show on website (only date, route and car)</label>
      <button class="full">Add booking</button>
    </form></details>
  <p class="t">Upcoming pickups first. 🔔 You get a phone reminder the evening before and on the morning of each pickup. Price, advance, name and phone are private; the website shows only date, route and car.</p>
  <?php if (!$moves): ?><div class="empty">No bookings yet. Mark a lead as converted, or add one above.</div><?php endif; ?>
  <?php foreach ($moves as $m): $p = (int)($m['price'] ?? 0); $ad = (int)($m['advance'] ?? 0); $soon = $m['date'] >= $today; ?>
    <div class="card"<?= $soon ? ' style="border-left:4px solid var(--red)"' : '' ?>>
      <div class="row"><div class="grow"><div class="rt"><?= h($m['from']) ?> → <?= h($m['to']) ?></div>
        <div class="t"><?= $soon ? '<b style="color:var(--red)">Pickup ' . h(date('D, j M', strtotime($m['date']))) . '</b>' : h(date('j M Y', strtotime($m['date']))) ?><?= $m['car'] ? ' · ' . h($m['car']) : '' ?> · <?= $m['show'] ? '<span class="tag ok">On website</span>' : '<span class="tag">Hidden</span>' ?></div>
        <?php if (!empty($m['name']) || !empty($m['phone'])): ?><div class="t"><?= h($m['name'] ?? '') ?> <?php if (!empty($m['phone'])): ?><a href="tel:<?= h(preg_replace('/[^0-9+]/', '', $m['phone'])) ?>"><?= h($m['phone']) ?></a><?php endif; ?></div><?php endif; ?>
        <div class="t" style="margin-top:3px"><?= $p ? 'Price <b>' . inr($p) . '</b> · Advance <b>' . inr($ad) . '</b> · Balance <b style="color:' . ($p - $ad > 0 ? 'var(--red)' : 'var(--ok)') . '">' . inr($p - $ad) . '</b>' : 'No price added' ?><?= !empty($m['note']) ? ' · ' . h($m['note']) : '' ?></div>
      </div></div>
      <div class="row" style="margin-top:8px">
        <details class="grow"><summary class="btn l" style="font-size:13px;padding:6px 10px">Edit payment / date</summary>
          <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('move_pay') ?><input type="hidden" name="id" value="<?= h($m['id']) ?>">
            <label>Total price ₹<input type="number" name="price" min="0" value="<?= $p ?: '' ?>"></label>
            <label>Advance received ₹<input type="number" name="advance" min="0" value="<?= $ad ?: '' ?>"></label>
            <label>Pickup date<input type="date" name="date" value="<?= h($m['date']) ?>"></label>
            <label>Note<input name="note" maxlength="120" value="<?= h($m['note'] ?? '') ?>" placeholder="e.g. advance by GPay"></label>
            <button class="full">Save</button></form></details>
        <form method="post" action="<?= h($self . $q([])) ?>"><?= $hid('move_toggle') ?><input type="hidden" name="id" value="<?= h($m['id']) ?>"><button class="l" style="font-size:13px;padding:6px 10px"><?= $m['show'] ? 'Hide' : 'Show' ?></button></form>
        <form method="post" action="<?= h($self . $q([])) ?>" onsubmit="return confirm('Delete this booking?')"><?= $hid('move_del') ?><input type="hidden" name="id" value="<?= h($m['id']) ?>"><button class="r" style="font-size:13px;padding:6px 10px">Delete</button></form>
      </div>
    </div>
  <?php endforeach; ?>

<?php elseif ($tab === 'reports'):
  $hidden = jread('hidden-leads.json', []);
  $leads = array_filter(read_leads(), function ($r) use ($hidden, $range) { return !isset($hidden[$r['key']]) && $r['ts'] && $r['ts'] >= $range[0] && $r['ts'] <= $range[1]; });
  $ads = jread('ads-daily.json', []); $adsUpd = $ads['_updated'] ?? ''; unset($ads['_updated']);
  $bk = function ($ts) use ($grp) { return $grp === 'month' ? date('Y-m', $ts) : ($grp === 'week' ? date('o-\\WW', $ts) : date('Y-m-d', $ts)); };
  $lab = function ($k) use ($grp) { if ($grp === 'month') return date('M Y', strtotime($k . '-01')); if ($grp === 'week') { [$y, $w] = explode('-W', $k); return 'Week of ' . date('j M', strtotime($y . 'W' . $w)); } return date('D j M', strtotime($k)); };
  $B = []; $z = ['forms' => 0, 'adsForms' => 0, 'taps' => 0, 'book' => 0, 'value' => 0, 'adv' => 0, 'spend' => 0, 'clicks' => 0, 'impr' => 0];
  foreach ($leads as $r) { $k = $bk($r['ts']); $B[$k] = $B[$k] ?? $z; if ($r['click']) $B[$k]['taps']++; else { $B[$k]['forms']++; if ($r['ads']) $B[$k]['adsForms']++; } }
  foreach ($moves as $m) { $ts = strtotime(substr($m['added'] ?? $m['date'], 0, 10)); if ($ts < $range[0] || $ts > $range[1]) continue; $k = $bk($ts); $B[$k] = $B[$k] ?? $z; $B[$k]['book']++; $B[$k]['value'] += $m['price'] ?? 0; $B[$k]['adv'] += $m['advance'] ?? 0; }
  foreach ($ads as $d => $a) { $ts = strtotime($d); if ($ts < $range[0] || $ts > $range[1]) continue; $k = $bk($ts); $B[$k] = $B[$k] ?? $z; $B[$k]['spend'] += $a['cost']; $B[$k]['clicks'] += $a['clicks']; $B[$k]['impr'] += $a['impr']; }
  krsort($B); $T = $z; foreach ($B as $b) foreach ($b as $k => $v) $T[$k] += $v;
  $maxF = 1; foreach ($B as $b) $maxF = max($maxF, $b['forms']);
  $cpl = $T['forms'] ? $T['spend'] / $T['forms'] : 0;
?>
  <?= $dateBar() ?>
  <div class="bar"><?php foreach (['day' => 'Daily', 'week' => 'Weekly', 'month' => 'Monthly'] as $k => $v): ?><a href="<?= h($q(['g' => $k === 'day' ? null : $k])) ?>" class="<?= $grp === $k ? 'on' : '' ?>"><?= $v ?></a><?php endforeach; ?></div>
  <div class="kpis">
    <div class="kpi"><b><?= $T['forms'] ?></b><span>Form leads</span></div>
    <div class="kpi"><b><?= $T['taps'] ?></b><span>Call / WhatsApp taps</span></div>
    <div class="kpi"><b><?= $T['book'] ?></b><span>Bookings<?= $T['forms'] ? ' · ' . round($T['book'] * 100 / $T['forms']) . '%' : '' ?></span></div>
    <div class="kpi"><b><?= inr($T['value']) ?></b><span>Booked value</span></div>
    <div class="kpi"><b><?= inr($T['adv']) ?></b><span>Advance received</span></div>
    <div class="kpi"><b><?= $ads ? inr($T['spend']) : '–' ?></b><span>Google Ads spend</span></div>
    <div class="kpi"><b><?= $ads && $T['forms'] ? inr($cpl) : '–' ?></b><span>Cost per lead</span></div>
    <div class="kpi"><b><?= $ads && $T['book'] ? inr($T['spend'] / $T['book']) : '–' ?></b><span>Ad cost per booking</span></div>
  </div>
  <?php if (!$ads): ?><div class="card t">Google Ads spend will show here once the Google Ads link is set up (one-time step).</div><?php else: ?><p class="t">Google Ads data updated <?= h(date('j M, g:i A', strtotime($adsUpd))) ?>.</p><?php endif; ?>
  <div class="tw"><table class="rp"><tr><th><?= $grp === 'day' ? 'Day' : ($grp === 'week' ? 'Week' : 'Month') ?></th><th>Leads</th><th>From ads</th><th>Taps</th><th>Bookings</th><th>Value</th><th>Advance</th><th>Ad spend</th><th>Clicks</th><th>Cost/lead</th></tr>
    <?php foreach ($B as $k => $b): ?><tr><td><?= h($lab($k)) ?></td><td><?= $b['forms'] ?><span class="barv" style="width:<?= round(40 * $b['forms'] / $maxF) ?>px"></span></td><td><?= $b['adsForms'] ?></td><td><?= $b['taps'] ?></td><td><?= $b['book'] ?></td><td><?= $b['value'] ? inr($b['value']) : '' ?></td><td><?= $b['adv'] ? inr($b['adv']) : '' ?></td><td><?= $b['spend'] ? inr($b['spend']) : '' ?></td><td><?= $b['clicks'] ?: '' ?></td><td><?= $b['spend'] && $b['forms'] ? inr($b['spend'] / $b['forms']) : '' ?></td></tr><?php endforeach; ?>
    <tr class="tot"><td>Total</td><td><?= $T['forms'] ?></td><td><?= $T['adsForms'] ?></td><td><?= $T['taps'] ?></td><td><?= $T['book'] ?></td><td><?= inr($T['value']) ?></td><td><?= inr($T['adv']) ?></td><td><?= $T['spend'] ? inr($T['spend']) : '' ?></td><td><?= $T['clicks'] ?: '' ?></td><td><?= $T['spend'] && $T['forms'] ? inr($cpl) : '' ?></td></tr>
  </table></div>
  <?php if (!$B): ?><div class="empty">No data in this period.</div><?php endif; ?>

<?php elseif ($tab === 'offers'): $offers = jread('offers.json', []); $today = date('Y-m-d'); ?>
  <div class="card"><b>New offer</b>
    <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('offer_add') ?>
      <label>Discount %<select name="pct"><?php foreach ([5, 10, 15, 20] as $p): ?><option value="<?= $p ?>"><?= $p ?>%</option><?php endforeach; ?></select></label>
      <label>Route (optional)<input name="route" maxlength="60" placeholder="Kerala → Bangalore, or leave empty for all"></label>
      <label class="full">Offer text<input name="title" maxlength="70" placeholder="e.g. Weekend booking offer" required></label>
      <label>Starts<input type="date" name="start" value="<?= $today ?>"></label>
      <label>Ends (last day)<input type="date" name="end" value="<?= date('Y-m-d', strtotime('+6 days')) ?>" required></label>
      <button class="full">Publish offer</button>
    </form></div>
  <p class="t">An offer shows on the website only between its start and end dates, with the real end date. Only publish offers you will honour.</p>
  <?php foreach ($offers as $o): $st = $o['end'] < $today ? 'Ended' : ($o['start'] > $today ? 'Starts ' . date('j M', strtotime($o['start'])) : 'Live now'); ?>
    <div class="card row"><div class="grow"><div class="rt"><?= (int)$o['pct'] ?>% off · <?= h($o['title']) ?></div>
      <div class="t"><?= h($o['route'] ?: 'All routes') ?> · <?= date('j M', strtotime($o['start'])) ?> to <?= date('j M Y', strtotime($o['end'])) ?> · <span class="tag <?= $st === 'Live now' ? 'ok' : '' ?>"><?= h($st) ?></span></div></div>
      <form method="post" action="<?= h($self . $q([])) ?>" onsubmit="return confirm('Delete this offer?')"><?= $hid('offer_del') ?><input type="hidden" name="id" value="<?= h($o['id']) ?>"><button class="r">Delete</button></form>
    </div>
  <?php endforeach; ?>

<?php else: ?>
  <div class="card"><b>Change password</b>
    <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('pass') ?>
      <label class="full">Current password<input type="password" name="old" required autocomplete="current-password"></label>
      <label class="full">New password (10+ characters)<input type="password" name="new" required minlength="10" autocomplete="new-password"></label>
      <button class="full">Change password</button>
    </form>
    <p class="t">Changing it logs out every phone and computer.</p></div>
<?php endif; ?>
</div>
<?php endif; ?>
<?php if ($in): ?>
<script>
(function () {
  var T = <?= json_encode(csrf()) ?>, KEY = <?= json_encode((function () { require_once __DIR__ . '/kpm-push-lib.php'; $v = kpm_vapid(); return $v ? $v['pub'] : ''; })()) ?>;
  var st = document.getElementById('al-st'), on = document.getElementById('al-on'), test = document.getElementById('al-test');
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/kpm-sw.js', { scope: '/kpm-admin.php' });
  if (!st) return;
  if (!('PushManager' in window) || !KEY) { st.textContent = 'This browser cannot show alerts. Open this page in Chrome on your phone.'; on.hidden = true; return; }
  var post = function (data) { var f = new FormData(); f.append('t', T); for (var k in data) f.append(k, data[k]); return fetch(location.pathname, { method: 'POST', body: f, credentials: 'same-origin' }).then(function (r) { return r.json(); }); };
  var u8 = function (b) { b = b.replace(/-/g, '+').replace(/_/g, '/'); var s = atob(b + '==='.slice((b.length + 3) % 4)), a = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; };
  var ready = function () { st.textContent = 'Alerts are ON on this phone. Every new form lead will ring.'; on.hidden = true; test.hidden = false; };
  navigator.serviceWorker.ready.then(function (reg) { return reg.pushManager.getSubscription(); }).then(function (s) { if (s && Notification.permission === 'granted') { post({ a: 'push_sub', sub: JSON.stringify(s) }); ready(); } });
  on.onclick = function () {
    on.disabled = true; st.textContent = 'Tap "Allow" when your phone asks…';
    Notification.requestPermission().then(function (p) {
      if (p !== 'granted') throw new Error('Notifications are blocked. Allow them in Chrome settings for this site, then try again.');
      return navigator.serviceWorker.ready;
    }).then(function (reg) { return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8(KEY) }); })
      .then(function (s) { return post({ a: 'push_sub', sub: JSON.stringify(s) }); })
      .then(function (j) { if (!j.ok) throw new Error('Could not save. Please log in again.'); ready(); })
      .catch(function (e) { st.textContent = e.message || 'Could not turn on alerts.'; on.disabled = false; });
  };
  test.onclick = function () {
    test.disabled = true; st.textContent = 'Sending a test alert…';
    post({ a: 'push_test' }).then(function (j) { st.textContent = j.ok ? 'Test sent. Your phone should ring in a few seconds.' : 'Test failed. Turn alerts on again.'; if (!j.ok) on.hidden = false; })
      .catch(function () { st.textContent = 'Test failed.'; }).then(function () { test.disabled = false; });
  };
})();
</script>
<?php endif; ?>
</body></html>
