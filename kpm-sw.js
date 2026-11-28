// KPM owner app: shows a phone notification for every new website lead.
// The push itself is empty; the newest lead is fetched from the owner page with the owner's login cookie.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (e) => {
  e.waitUntil((async () => {
    let title = 'New KPM lead', body = 'Open to see the details and call back.';
    try {
      const r = await fetch('/kpm-admin.php?latest=1', { credentials: 'include', cache: 'no-store' });
      if (r.ok) {
        const j = await r.json();
        if (j.test) { title = 'KPM alerts are working ✅'; body = 'You will get an alert like this for every new lead.'; }
        else if (j.lead) {
          const l = j.lead;
          title = 'New lead: ' + (l.name || 'No name') + (l.phone ? ' · ' + l.phone : '');
          body = [l.from && l.to ? l.from + ' → ' + l.to : (l.from || l.to || ''), l.car, l.type, l.time].filter(Boolean).join(' · ');
        }
      }
    } catch (err) {}
    await self.registration.showNotification(title, {
      body, icon: '/kpm-admin-192.png', badge: '/kpm-admin-192.png', tag: 'kpm-lead-' + Date.now(),
      renotify: true, requireInteraction: true, silent: false, vibrate: [300, 120, 300, 120, 300],
    });
  })());
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) if (c.url.includes('/kpm-admin.php')) { await c.navigate('/kpm-admin.php?tab=leads&d=1'); return c.focus(); }
    return self.clients.openWindow('/kpm-admin.php?tab=leads&d=1');
  })());
});
