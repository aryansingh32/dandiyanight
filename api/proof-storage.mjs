// Screenshot mirrors. Postgres already holds the authoritative copy (written in the same transaction as the payment),
// so these are best-effort backups: a failure is logged and never reaches the student or blocks a payment.
//   • Supabase Storage — needs SUPABASE_URL + SUPABASE_SERVICE_KEY (bucket `payment-proofs`, created by migration 014).
//   • Firebase Storage — needs the Firebase service account and FIREBASE_STORAGE_BUCKET.
const MIME_EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' };

/** data URL → { mime, bytes } or null. */
export function parseDataUrl(dataUrl) {
  const m = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl));
  return m ? { mime: m[1], bytes: Buffer.from(m[2], 'base64') } : null;
}

export function makeProofStorage(env, { firebase, log }) {
  const url = (env.SUPABASE_URL ?? '').replace(/\/$/, ''), key = env.SUPABASE_SERVICE_KEY ?? '', bucket = env.SUPABASE_PROOF_BUCKET || 'payment-proofs';
  const supabaseOn = !!(url && key);

  async function toSupabase(path, file) {
    const res = await fetch(`${url}/storage/v1/object/${bucket}/${path}`, {
      method: 'POST', headers: { authorization: `Bearer ${key}`, apikey: key, 'content-type': file.mime, 'x-upsert': 'true' }, body: file.bytes, signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`Supabase Storage ${res.status}: ${(await res.text().catch(() => '')).slice(0, 160)}`);
    return `${bucket}/${path}`;
  }

  const authed = { authorization: `Bearer ${key}`, apikey: key };
  /** Reads one stored copy; null when it is missing (or the backend is not configured). */
  async function readSupabase(ref) {
    if (!supabaseOn || !ref.startsWith(bucket + '/')) return null;
    const res = await fetch(`${url}/storage/v1/object/authenticated/${bucket}/${ref.slice(bucket.length + 1)}`, { headers: authed, signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return null;
    return { bytes: Buffer.from(await res.arrayBuffer()), mime: res.headers.get('content-type')?.split(';')[0] || 'image/jpeg' };
  }
  async function hasSupabase(ref) {
    if (!supabaseOn || !ref.startsWith(bucket + '/')) return false;
    const res = await fetch(`${url}/storage/v1/object/info/authenticated/${bucket}/${ref.slice(bucket.length + 1)}`, { headers: authed, signal: AbortSignal.timeout(10_000) }).catch(() => null);
    return !!res?.ok;
  }

  return {
    supabaseEnabled: supabaseOn,
    /** True when at least one backend can keep the screenshots (so the database copy may be removed). */
    get enabled() { return supabaseOn || !!env.FIREBASE_STORAGE_BUCKET; },
    /** Is at least one recorded copy really there? Only then is the Postgres copy removed. */
    async verify(mirrors) {
      const checks = [];
      if (mirrors?.supabase) checks.push(hasSupabase(mirrors.supabase).catch(() => false));
      if (mirrors?.firebase) checks.push(firebase.hasFile(mirrors.firebase).catch(() => false));
      return (await Promise.all(checks)).some(Boolean);
    },
    /** The screenshot as a data URL from whichever copy answers first (Supabase, then Firebase); null when none does. */
    async read(mirrors) {
      const tries = [mirrors?.supabase && (() => readSupabase(mirrors.supabase)), mirrors?.firebase && (() => firebase.readFile(mirrors.firebase))].filter(Boolean);
      for (const t of tries) {
        const f = await t().catch(() => null);
        if (f) return `data:${f.mime};base64,${f.bytes.toString('base64')}`;
      }
      return null;
    },
    /** Copies one screenshot everywhere it can. Resolves to { supabase?, firebase? } with the paths that worked. */
    async mirror(txnId, dataUrl) {
      const file = parseDataUrl(dataUrl); if (!file) return {};
      const path = `${new Date().getUTCFullYear()}/${txnId}.${MIME_EXT[file.mime]}`;
      const out = {};
      const jobs = [];
      if (supabaseOn) jobs.push(toSupabase(path, file).then(p => { out.supabase = p; }).catch(e => log.warn(`[proof] supabase storage failed for ${txnId}: ${e.message}`)));
      jobs.push(firebase.saveFile(`payment-proofs/${path}`, file.bytes, file.mime).then(p => { if (p) out.firebase = p; }).catch(e => log.warn(`[proof] firebase storage failed for ${txnId}: ${e.message}`)));
      await Promise.all(jobs);
      return out;
    },
  };
}
