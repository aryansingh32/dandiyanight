// Firebase, optional. Without credentials every method is a harmless no-op and the chat runs on the database alone.
//   • Sign-in tokens from Firebase Auth can be verified with just the project id (no secret needed).
//   • Live delivery (Realtime Database) and push notifications (FCM) need a service-account key.
const LIVE_KEEP = 120;

export async function makeFirebase(env = process.env) {
  const projectId = env.FIREBASE_PROJECT_ID ?? '';
  const dbUrl = env.FIREBASE_DATABASE_URL ?? '';
  let sa = null;
  if (env.FIREBASE_SERVICE_ACCOUNT_B64) { try { sa = JSON.parse(Buffer.from(env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8')); } catch { console.warn('[firebase] FIREBASE_SERVICE_ACCOUNT_B64 is not valid base64 JSON'); } }
  const none = { authEnabled: false, liveEnabled: false, pushEnabled: false, saveFile: async () => null, readFile: async () => null, hasFile: async () => false, verifyIdToken: async () => null, pushMessages: async () => undefined, resetLive: async () => undefined, setStatus: async () => undefined, prune: async () => undefined, sendPush: async () => undefined, subscribe: async () => undefined };
  if (!projectId) return none;

  let admin;
  try { admin = (await import('firebase-admin')).default; } catch { console.warn('[firebase] firebase-admin is not installed'); return none; }
  const app = admin.apps.length ? admin.app() : admin.initializeApp({ projectId, ...(sa ? { credential: admin.credential.cert(sa), databaseURL: dbUrl || undefined } : {}) });
  const live = !!(sa && dbUrl);
  const db = () => admin.database(app);
  const swallow = label => e => console.warn(`[firebase] ${label}:`, e?.message ?? e);

  return {
    authEnabled: true, liveEnabled: live, pushEnabled: !!sa,
    /** Verifies a Firebase Auth ID token → { sub (the Google account id), email, name, picture } or null. */
    async verifyIdToken(idToken) {
      try {
        const d = await admin.auth(app).verifyIdToken(idToken, true);       // signature, expiry, audience, issuer — and not revoked
        // Only a real Google sign-in counts: no custom tokens, anonymous, email/password or phone accounts.
        if (d.firebase?.sign_in_provider !== 'google.com') return null;
        const sub = d.firebase?.identities?.['google.com']?.[0];
        if (!sub || !d.email || d.email_verified !== true) return null;
        return { sub: String(sub), email: d.email, name: d.name ?? '', picture: d.picture ?? '' };
      } catch { return null; }
    },
    async pushMessages(msgs) {
      if (!live || !msgs.length) return;
      const updates = {}; for (const m of msgs) updates[`chat/live/${m.id}`] = m;
      await db().ref().update(updates).catch(swallow('push'));
    },
    /** Replace the whole live window (after a delete / clear / kick). */
    async resetLive(msgs) {
      if (!live) return;
      const next = {}; for (const m of msgs.slice(-LIVE_KEEP)) next[m.id] = m;
      await db().ref('chat/live').set(Object.keys(next).length ? next : null).catch(swallow('reset'));
    },
    async prune(keepIds) {
      if (!live) return;
      const snap = await db().ref('chat/live').orderByKey().once('value').catch(() => null);
      if (!snap) return;
      const drop = {}; snap.forEach(c => { if (!keepIds.has(Number(c.key))) drop[`chat/live/${c.key}`] = null; });
      if (Object.keys(drop).length) await db().ref().update(drop).catch(swallow('prune'));
    },
    /** Stores a file in Firebase Storage (screenshot backups). Returns its path, or null when storage is not configured. */
    async saveFile(path, bytes, contentType) {
      const bucketName = env.FIREBASE_STORAGE_BUCKET ?? '';
      if (!sa || !bucketName) return null;
      await admin.storage(app).bucket(bucketName).file(path).save(bytes, { contentType, resumable: false });
      return `${bucketName}/${path}`;
    },
    /** Reads a file back (path as returned by saveFile: "bucket/path"). Null when missing or not configured. */
    async readFile(ref) {
      const bucketName = env.FIREBASE_STORAGE_BUCKET ?? '';
      if (!sa || !bucketName || !ref.startsWith(bucketName + '/')) return null;
      const f = admin.storage(app).bucket(bucketName).file(ref.slice(bucketName.length + 1));
      const [meta] = await f.getMetadata().catch(() => [null]); if (!meta) return null;
      const [bytes] = await f.download(); return { bytes, mime: meta.contentType || 'image/jpeg' };
    },
    async hasFile(ref) {
      const bucketName = env.FIREBASE_STORAGE_BUCKET ?? '';
      if (!sa || !bucketName || !ref.startsWith(bucketName + '/')) return false;
      const [ok] = await admin.storage(app).bucket(bucketName).file(ref.slice(bucketName.length + 1)).exists().catch(() => [false]); return ok;
    },
    async setStatus(status) { if (live) await db().ref('chat/status').set(status).catch(swallow('status')); },
    async subscribe(token) { if (!sa) return; await admin.messaging(app).subscribeToTopic([token], 'chat').catch(swallow('subscribe')); },
    async sendPush(title, body) {
      if (!sa) return;
      await admin.messaging(app).send({ topic: 'chat', notification: { title, body }, webpush: { fcmOptions: { link: '/community' } } }).catch(swallow('push-notification'));
    },
  };
}
