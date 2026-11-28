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
function set_cookie($val, $exp) {
  setcookie(COOKIE, $val, ['expires' => $exp, 'path' => '/kpm-admin.php', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
}
function csrf() { global $SECRET; return hash_hmac('sha256', 'csrf|' . ($_COOKIE[COOKIE] ?? ''), $SECRET); }
function ip() { return $_SERVER['REMOTE_ADDR'] ?? '0'; }

$self = '/kpm-admin.php';
$msg = '';

// ---------- POST actions ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  if ($origin !== '' && !preg_match('#^https://(www\.)?cartransportation\.co\.in$#', $origin)) { http_response_code(403); exit('Forbidden'); }
  $a = $_POST['a'] ?? '';

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
    $back = $self . '?' . http_build_query(array_intersect_key($_GET, ['tab' => 1, 'd' => 1, 'all' => 1]));
    if ($a === 'logout') { set_cookie('', time() - 3600); header("Location: $self"); exit; }
    if ($a === 'convert' || $a === 'addmove') {
      $moves = jread('moves.json', []);
      $m = ['id' => bin2hex(random_bytes(6)), 'lead' => preg_replace('/[^a-f0-9]/', '', (string)($_POST['lead'] ?? '')),
        'date' => okdate($_POST['date'] ?? '') ?: date('Y-m-d'), 'from' => clean($_POST['from'] ?? '', 40), 'to' => clean($_POST['to'] ?? '', 40),
        'car' => clean($_POST['car'] ?? '', 40), 'show' => !empty($_POST['show']), 'added' => date('c')];
      if ($m['from'] !== '' && $m['to'] !== '') { array_unshift($moves, $m); jwrite('moves.json', $moves); }
      header("Location: $back"); exit;
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
  } else { $msg = 'Session expired. Please log in again.'; }
}

// ---------- page ----------
$in = logged_in();
$tab = in_array($_GET['tab'] ?? '', ['leads', 'moves', 'offers', 'settings'], true) ? $_GET['tab'] : 'leads';
$days = in_array($_GET['d'] ?? '', ['1', '7', '30', 'all'], true) ? $_GET['d'] : '7';
$all = !empty($_GET['all']);
$q = function ($extra) use ($tab, $days, $all) { return '?' . http_build_query(array_merge(['tab' => $tab, 'd' => $days, 'all' => $all ? 1 : null], $extra)); };
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>KPM Owner Login</title>
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
  $moves = jread('moves.json', []);
  $convertedLeads = []; foreach ($moves as $m) if (!empty($m['lead'])) $convertedLeads[$m['lead']] = $m;
?>
<header><b>KPM Owner</b><form method="post" action="<?= $self ?>"><?= $hid('logout') ?><button class="l">Log out</button></form></header>
<div class="wrap">
<?php if ($msg): ?><div class="msg"><?= h($msg) ?></div><?php endif; ?>
<nav>
  <a href="?tab=leads" class="<?= $tab === 'leads' ? 'on' : '' ?>">Leads</a>
  <a href="?tab=moves" class="<?= $tab === 'moves' ? 'on' : '' ?>">Recent moves (<?= count($moves) ?>)</a>
  <a href="?tab=offers" class="<?= $tab === 'offers' ? 'on' : '' ?>">Offers</a>
  <a href="?tab=settings" class="<?= $tab === 'settings' ? 'on' : '' ?>">Password</a>
</nav>

<?php if ($tab === 'leads'):
  $rows = [];
  $fh = @fopen("$DIR/leads.csv", 'r');
  if ($fh) { while (($line = fgets($fh)) !== false) { $r = str_getcsv($line); if (count($r) < 7) continue; $r['key'] = sha1(rtrim($line, "\r\n")); $rows[] = $r; } fclose($fh); }
  $rows = array_reverse($rows);
  $cut = $days === 'all' ? 0 : strtotime('today') - ((int)$days - 1) * 86400;
  $groups = [];
  foreach ($rows as $r) {
    $ts = strtotime(str_replace('-', ' ', substr($r[0], 0, 11)) . ' ' . substr($r[0], 12));
    if ($ts === false || $ts < $cut) continue;
    $isClick = stripos($r[1], 'click') !== false;
    if ($isClick && !$all) continue;
    $groups[date('Y-m-d', $ts)][] = $r + ['ts' => $ts, 'click' => $isClick];
  }
  krsort($groups);
  foreach ($groups as &$gl) usort($gl, function ($a, $b) { return $b['ts'] <=> $a['ts']; });
  unset($gl);
?>
  <div class="bar">
    <?php foreach (['1' => 'Today', '7' => '7 days', '30' => '30 days', 'all' => 'All'] as $k => $v): ?><a href="<?= h($q(['d' => $k])) ?>" class="<?= $days === (string)$k ? 'on' : '' ?>"><?= $v ?></a><?php endforeach; ?>
    <a href="<?= h($q(['all' => $all ? null : 1])) ?>" class="<?= $all ? 'on' : '' ?>"><?= $all ? '✓ ' : '' ?>Show WhatsApp / call taps</a>
  </div>
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
      <?php if (!$conv && !$r['click']): ?>
      <details><summary class="btn l" style="margin-top:8px">Mark converted</summary>
        <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('convert') ?><input type="hidden" name="lead" value="<?= h($r['key']) ?>">
          <label>From<input name="from" value="<?= h($r[5]) ?>" required maxlength="40"></label>
          <label>To<input name="to" value="<?= h($r[6]) ?>" required maxlength="40"></label>
          <label>Car model<input name="car" value="<?= h($r[7]) ?>" maxlength="40" placeholder="e.g. Hyundai Creta"></label>
          <label>Move date<input type="date" name="date" value="<?= date('Y-m-d') ?>"></label>
          <label class="full" style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="show" value="1" checked> Show on website (only date, route and car; never name or phone)</label>
          <button class="full">Save as converted</button>
        </form></details>
      <?php endif; ?>
    </div>
    <?php endforeach; ?>
  <?php endforeach; ?>

<?php elseif ($tab === 'moves'): ?>
  <details class="card"><summary class="btn">+ Add a move (phone / walk-in booking)</summary>
    <form method="post" action="<?= h($self . $q([])) ?>" class="f"><?= $hid('addmove') ?>
      <label>From<input name="from" required maxlength="40" placeholder="Kozhikode"></label>
      <label>To<input name="to" required maxlength="40" placeholder="Bangalore"></label>
      <label>Car model<input name="car" maxlength="40" placeholder="Toyota Innova"></label>
      <label>Move date<input type="date" name="date" value="<?= date('Y-m-d') ?>"></label>
      <label class="full" style="flex-direction:row;align-items:center;gap:8px"><input type="checkbox" name="show" value="1" checked> Show on website</label>
      <button class="full">Add move</button>
    </form></details>
  <p class="t">These show on the website as "Recent car moves" (date, route, car). Use Hide for any you don't want public.</p>
  <?php if (!$moves): ?><div class="empty">No moves yet. Mark a lead as converted, or add one above.</div><?php endif; ?>
  <?php foreach ($moves as $m): ?>
    <div class="card row"><div class="grow"><div class="rt"><?= h($m['from']) ?> → <?= h($m['to']) ?></div>
      <div class="t"><?= h(date('j M Y', strtotime($m['date']))) ?><?= $m['car'] ? ' · ' . h($m['car']) : '' ?> · <?= $m['show'] ? '<span class="tag ok">On website</span>' : '<span class="tag">Hidden</span>' ?></div></div>
      <form method="post" action="<?= h($self . $q([])) ?>"><?= $hid('move_toggle') ?><input type="hidden" name="id" value="<?= h($m['id']) ?>"><button class="l"><?= $m['show'] ? 'Hide' : 'Show' ?></button></form>
      <form method="post" action="<?= h($self . $q([])) ?>" onsubmit="return confirm('Delete this move?')"><?= $hid('move_del') ?><input type="hidden" name="id" value="<?= h($m['id']) ?>"><button class="r">Delete</button></form>
    </div>
  <?php endforeach; ?>

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
</body></html>
