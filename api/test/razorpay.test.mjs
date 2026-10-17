// Razorpay against the real *test-mode* account (no money moves). Needs RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET in .env.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import pg from 'pg';
import { buildApp } from '../server.mjs';

const RUN = String(Date.now()).slice(-6);
const ROLL = `66${RUN}01000`;
const WH = 'whsec_unit_test';
const PHOTO = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBD' + 'A'.repeat(300);
const enabled = !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
let app, pool, h, regId;

const req = (method, url, payload, headers = h) => app.inject({ method, url, payload, headers }).then(r => ({ status: r.statusCode, body: r.body ? JSON.parse(r.body) : null }));

before(async () => {
  if (!enabled) return;
  app = buildApp({ ...process.env, DEV_AUTH: '1', ENABLE_RAZORPAY: '1', RAZORPAY_WEBHOOK_SECRET: WH, LOG_LEVEL: 'silent' }); await app.ready();
  pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('127.0.0.1') ? false : { rejectUnauthorized: false }, max: 2 });
  await pool.query(`insert into students (roll, name, branch, year) values ($1, 'Rzp Test Student', 'Mechanical', '3rd Year') on conflict do nothing`, [ROLL]);
  const t = (await app.inject({ method: 'POST', url: '/auth/google', payload: { credential: `dev:rzp${RUN}@test.dn` } })).json().token;
  h = { authorization: `Bearer ${t}` };
  for (const patch of [{ year: '3rd Year' }, { roll: ROLL }, { photo: PHOTO }]) await req('POST', '/me/draft', { patch });
});
after(async () => {
  if (!enabled) return;
  if (regId) await pool.query('delete from registrations where id = $1', [regId]);
  await pool.query(`delete from applicants where email like '%${RUN}@test.dn'`);
  await pool.query('delete from students where roll = $1', [ROLL]);
  await pool.end(); await app.close();
});

test('the public settings advertise Razorpay (key id only) and switch the demo checkout off', { skip: !enabled }, async () => {
  const info = (await req('GET', '/public/info', undefined, {})).body;
  assert.equal(info.razorpay, true); assert.equal(info.razorpayKeyId, process.env.RAZORPAY_KEY_ID); assert.equal(info.testMode, false);
  assert.ok(!JSON.stringify(info).includes(process.env.RAZORPAY_KEY_SECRET), 'the secret never leaves the server');
});

test('starting a payment creates a real Razorpay order for the right amount', { skip: !enabled }, async () => {
  const r = (await req('POST', '/me/pay', {})).body;
  assert.equal(r.ok, true, JSON.stringify(r)); regId = r.regId;
  assert.match(r.orderId, /^order_/); assert.equal(r.razorpay.keyId, process.env.RAZORPAY_KEY_ID); assert.equal(r.razorpay.amountPaise, r.amount * 100);
  const me = (await req('GET', '/me')).body;
  assert.equal(me.reg.payment.orderId, r.orderId, 'our record carries the Razorpay order id');
  globalThis.__order = r.orderId;
});

test('the demo "settle" shortcut is refused while Razorpay is on', { skip: !enabled }, async () => {
  const r = await req('POST', '/me/pay/test-settle', { txnId: 'x', ok: true, method: 'UPI' });
  assert.equal(r.status, 403);
});

test('a forged checkout signature is rejected and nothing is issued', { skip: !enabled }, async () => {
  const bad = await req('POST', '/me/pay/verify', { razorpay_order_id: globalThis.__order, razorpay_payment_id: 'pay_forged123', razorpay_signature: 'f'.repeat(64) });
  assert.equal(bad.status, 400);
  const me = (await req('GET', '/me')).body; assert.notEqual(me.reg.payment.status, 'paid');
});

test('a valid signature for a payment Razorpay has never seen is not enough', { skip: !enabled }, async () => {
  const sig = createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${globalThis.__order}|pay_doesnotexist1`).digest('hex');
  const r = await req('POST', '/me/pay/verify', { razorpay_order_id: globalThis.__order, razorpay_payment_id: 'pay_doesnotexist1', razorpay_signature: sig });
  assert.ok(r.status >= 400, `refused (${r.status})`);
  assert.notEqual((await req('GET', '/me')).body.reg.payment.status, 'paid');
});

test('another student cannot verify against this order', { skip: !enabled }, async () => {
  const other = (await app.inject({ method: 'POST', url: '/auth/google', payload: { credential: `dev:rzpother${RUN}@test.dn` } })).json().token;
  const sig = createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${globalThis.__order}|pay_x`).digest('hex');
  const r = await req('POST', '/me/pay/verify', { razorpay_order_id: globalThis.__order, razorpay_payment_id: 'pay_x', razorpay_signature: sig }, { authorization: `Bearer ${other}` });
  assert.equal(r.status, 404);
});

test('webhook: unsigned or wrongly signed calls are refused', { skip: !enabled }, async () => {
  const body = JSON.stringify({ event: 'payment.captured', payload: { payment: { entity: { id: 'pay_w1', order_id: globalThis.__order, method: 'upi' } } } });
  const none = await app.inject({ method: 'POST', url: '/webhooks/razorpay', payload: body, headers: { 'content-type': 'application/json' } });
  assert.equal(none.statusCode, 400);
  const wrong = await app.inject({ method: 'POST', url: '/webhooks/razorpay', payload: body, headers: { 'content-type': 'application/json', 'x-razorpay-signature': 'a'.repeat(64) } });
  assert.equal(wrong.statusCode, 400);
  assert.notEqual((await req('GET', '/me')).body.reg.payment.status, 'paid');
});

test('webhook: a correctly signed payment.captured issues the pass — once, even if delivered twice', { skip: !enabled }, async () => {
  const body = JSON.stringify({ event: 'payment.captured', payload: { payment: { entity: { id: 'pay_unitwebhook01', order_id: globalThis.__order, method: 'upi' } } } });
  const sig = createHmac('sha256', WH).update(body).digest('hex');
  const send = () => app.inject({ method: 'POST', url: '/webhooks/razorpay', payload: body, headers: { 'content-type': 'application/json', 'x-razorpay-signature': sig } });
  assert.equal((await send()).statusCode, 200);
  const me1 = (await req('GET', '/me')).body.reg;
  assert.equal(me1.payment.status, 'paid'); assert.equal(me1.payment.method, 'UPI'); assert.equal(me1.payment.paymentId, 'pay_unitwebhook01'); assert.match(me1.pass.token, /^[A-Z2-9]{10}$/);
  assert.equal((await send()).statusCode, 200);                                   // Razorpay retries: idempotent
  const me2 = (await req('GET', '/me')).body.reg; assert.equal(me2.pass.token, me1.pass.token, 'the pass is not re-issued');
});
