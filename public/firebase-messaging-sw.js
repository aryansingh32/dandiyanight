/* Shows chat notifications while the site is closed. These values are the public web-app settings, not secrets. */
importScripts('https://www.gstatic.com/firebasejs/11.0.2/firebase-app-compat.js', 'https://www.gstatic.com/firebasejs/11.0.2/firebase-messaging-compat.js');
firebase.initializeApp({ apiKey: 'YOUR_API_KEY', authDomain: 'YOUR_PROJECT.firebaseapp.com', projectId: 'YOUR_PROJECT', appId: 'YOUR_APP_ID', messagingSenderId: 'YOUR_SENDER_ID' });
const messaging = firebase.messaging();
messaging.onBackgroundMessage(payload => {
  const n = payload.notification || {};
  self.registration.showNotification(n.title || 'Dandiya Night Community', { body: n.body || 'New messages in the community', icon: '/favicon.svg', badge: '/favicon.svg', data: { link: '/community' } });
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => { for (const c of list) if ('focus' in c) { c.navigate('/community'); return c.focus(); } return self.clients.openWindow('/community'); }));
});
