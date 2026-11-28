<?php
// KPM: Web Push sender with no libraries (included by lead.php and kpm-admin.php; blocked from the web by .htaccess).
// Sends an empty push (no payload, so no payload encryption is needed) signed with VAPID (ES256).
// The service worker /kpm-sw.js then fetches the newest lead from /kpm-admin.php (needs the owner's login cookie)
// and shows the notification. Keys and phone subscriptions live in ../kpm-data/ (outside public_html).
if (!defined('KPM_PUSH')) {
define('KPM_PUSH', 1);

function kpm_b64u($s) { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function kpm_data_dir() { return dirname(__DIR__) . '/kpm-data'; }

/** Returns ['pem' => private key PEM, 'pub' => base64url raw public key], creating it once. */
function kpm_vapid() {
  $f = kpm_data_dir() . '/vapid.json';
  if (is_file($f)) { $j = json_decode((string)file_get_contents($f), true); if (!empty($j['pem']) && !empty($j['pub'])) return $j; }
  $k = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
  if (!$k) return null;
  openssl_pkey_export($k, $pem);
  $d = openssl_pkey_get_details($k);
  $pub = "\x04" . str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT);
  $j = ['pem' => $pem, 'pub' => kpm_b64u($pub)];
  if (!is_dir(kpm_data_dir())) mkdir(kpm_data_dir(), 0700, true);
  file_put_contents($f, json_encode($j)); chmod($f, 0600);
  return $j;
}

/** DER ECDSA signature -> raw 64-byte r||s (JWS ES256). */
function kpm_der2raw($der) {
  $o = 2; if (ord($der[1]) & 0x80) $o += ord($der[1]) & 0x7f;
  $out = '';
  for ($i = 0; $i < 2; $i++) {
    $len = ord($der[$o + 1]); $v = substr($der, $o + 2, $len); $o += 2 + $len;
    $v = ltrim($v, "\0"); $out .= str_pad($v, 32, "\0", STR_PAD_LEFT);
  }
  return $out;
}

function kpm_vapid_header($endpoint, $v) {
  $p = parse_url($endpoint); $aud = $p['scheme'] . '://' . $p['host'];
  $h = kpm_b64u(json_encode(['typ' => 'JWT', 'alg' => 'ES256']));
  $b = kpm_b64u(json_encode(['aud' => $aud, 'exp' => time() + 12 * 3600, 'sub' => 'https://www.cartransportation.co.in/']));
  if (!openssl_sign("$h.$b", $sig, $v['pem'], OPENSSL_ALGO_SHA256)) return null;
  return 'vapid t=' . "$h.$b." . kpm_b64u(kpm_der2raw($sig)) . ', k=' . $v['pub'];
}

/** Push to every saved phone. Removes phones whose subscription has expired. Returns [sent, failed, details]. */
function kpm_push_all() {
  $f = kpm_data_dir() . '/push-subs.json';
  $subs = is_file($f) ? (json_decode((string)file_get_contents($f), true) ?: []) : [];
  $v = kpm_vapid(); if (!$v || !$subs || !function_exists('curl_init')) return [0, count($subs), []];
  $ok = 0; $bad = 0; $keep = []; $log = [];
  foreach ($subs as $s) {
    $ep = $s['endpoint'] ?? '';
    if (!preg_match('#^https://#', $ep)) continue;
    $auth = kpm_vapid_header($ep, $v);
    $c = curl_init($ep);
    curl_setopt_array($c, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => '', CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8,
      CURLOPT_HTTPHEADER => ['Authorization: ' . $auth, 'TTL: 86400', 'Urgency: high', 'Content-Length: 0']]);
    $body = curl_exec($c); $code = (int)curl_getinfo($c, CURLINFO_HTTP_CODE); curl_close($c);
    $log[] = $code . ' ' . substr((string)$body, 0, 120);
    if ($code >= 200 && $code < 300) { $ok++; $keep[] = $s; }
    elseif ($code === 404 || $code === 410) { $bad++; }        // phone unsubscribed: drop it
    else { $bad++; $keep[] = $s; }
  }
  file_put_contents($f, json_encode($keep, JSON_UNESCAPED_SLASHES)); chmod($f, 0600);
  return [$ok, $bad, $log];
}
}
