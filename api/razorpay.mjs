// Razorpay, server side. The browser never decides that a payment succeeded: the API verifies the gateway's signature
// and re-reads the payment from Razorpay before the database is told to issue a pass.
import { createHmac, timingSafeEqual } from 'node:crypto';

const API = 'https://api.razorpay.com/v1';
const safeEqual = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

/** Razorpay payment `method` → the labels the rest of the system uses. */
export function mapMethod(m) {
  return ({ upi: 'UPI', card: 'Card', netbanking: 'Net Banking', wallet: 'Wallet' })[String(m).toLowerCase()] ?? 'Card';
}

export function makeRazorpay(env = process.env) {
  const keyId = env.RAZORPAY_KEY_ID ?? '', secret = env.RAZORPAY_KEY_SECRET ?? '', webhookSecret = env.RAZORPAY_WEBHOOK_SECRET ?? '';
  const enabled = !!(keyId && secret);
  const auth = 'Basic ' + Buffer.from(`${keyId}:${secret}`).toString('base64');

  async function call(path, method = 'GET', body) {
    const res = await fetch(API + path, { method, headers: { authorization: auth, ...(body ? { 'content-type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(12_000) });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw Object.assign(new Error(json?.error?.description ?? `Razorpay ${res.status}`), { razorpay: json?.error, status: res.status });
    return json;
  }

  return {
    enabled, keyId, webhookEnabled: !!webhookSecret,
    /** amountRupees → an order in paise. `receipt` ties it back to our transaction id. */
    createOrder: ({ amountRupees, receipt, notes }) => call('/orders', 'POST', { amount: Math.round(amountRupees * 100), currency: 'INR', receipt, notes }),
    fetchPayment: id => call(`/payments/${encodeURIComponent(id)}`),
    capture: (id, amountPaise) => call(`/payments/${encodeURIComponent(id)}/capture`, 'POST', { amount: amountPaise, currency: 'INR' }),
    /** Checkout success callback: signature = HMAC_SHA256(order_id + "|" + payment_id, key_secret). */
    verifyCheckoutSignature: (orderId, paymentId, signature) =>
      enabled && !!signature && safeEqual(createHmac('sha256', secret).update(`${orderId}|${paymentId}`).digest('hex'), signature),
    /** Webhook: signature = HMAC_SHA256(raw body, webhook secret). */
    verifyWebhook: (rawBody, signature) =>
      !!webhookSecret && !!signature && safeEqual(createHmac('sha256', webhookSecret).update(rawBody).digest('hex'), signature),
    sign: (orderId, paymentId) => createHmac('sha256', secret).update(`${orderId}|${paymentId}`).digest('hex'),   // for tests
  };
}
