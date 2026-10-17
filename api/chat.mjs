// The community room, server side: a small in-memory copy of the live window (so 100 people polling cost the database nothing),
// who is currently in the room (for the 100-person cap), and the fan-out to Firebase and push notifications.
export function makeChat({ call, firebase, log = console }) {
  let messages = [];            // { m, seq } oldest first, only what is live. `seq` is the order messages reached this server — clients ask "what is newer than seq N",
  let seq = 0;                  // which stays correct even if a message with a lower database id shows up late
  let maxId = 0, epoch = null;
  let flags = { visible: false, enabled: true, vanishMinutes: 0, words: [], capacity: 100 };
  let running = false, timer = null, lastPoll = 0, lastPush = 0, lastPrune = 0, polled = false;
  const presence = new Map();   // sub → { since, last }
  const PRESENCE_MS = 25_000;

  const activeCount = () => { const cut = Date.now() - PRESENCE_MS; let n = 0; for (const [k, v] of presence) { if (v.last < cut) presence.delete(k); else n++; } return n; };

  async function poll() {
    if (running) return; running = true;
    try {
      const head = await call('api_chat_feed', [maxId, 150]);
      const changedEpoch = epoch !== null && head.epoch !== epoch;
      const reset = epoch === null || changedEpoch;
      const body = reset ? await call('api_chat_feed', [0, 150]) : head;       // epoch moved (delete / clear / kick) → take a fresh window
      flags = { visible: body.visible, enabled: body.enabled, vanishMinutes: body.vanishMinutes, words: body.words ?? [], capacity: body.capacity };
      if (reset) {
        messages = body.messages.map(m => ({ m, seq: ++seq })); maxId = body.messages.length ? Math.max(maxId, ...body.messages.map(m => m.id)) : maxId; epoch = body.epoch;
        await firebase.resetLive(body.messages); await firebase.setStatus({ visible: flags.visible, enabled: flags.enabled, epoch });
      } else if (body.messages.length) {
        const known = new Set(messages.map(x => x.m.id));
        const fresh = body.messages.filter(m => !known.has(m.id));
        maxId = Math.max(maxId, ...body.messages.map(m => m.id));
        if (fresh.length) { messages = [...messages, ...fresh.map(m => ({ m, seq: ++seq }))].slice(-300); await firebase.pushMessages(fresh); notify(fresh); }
      }
      if (Date.now() - lastPrune > 60_000) { lastPrune = Date.now(); await firebase.prune(new Set(messages.map(x => x.m.id))); }
    } catch (e) { log.warn?.('[chat] poll failed:', e.message); }
    finally { running = false; lastPoll = Date.now(); }
  }
  async function pollThenMark() {
    await poll(); polled = true;
  }
  /** At most one push every few minutes, and only while the room is open. */
  function notify(fresh) {
    if (!flags.visible || !flags.enabled || Date.now() - lastPush < 3 * 60_000) return;
    lastPush = Date.now();
    const m = fresh[fresh.length - 1];
    void firebase.sendPush('Dandiya Night Community', m.kind === 'admin' ? `Event team: ${m.body.slice(0, 80)}` : `New messages in the community`);
  }
  const alive = m => !flags.vanishMinutes || Date.parse(m.at) >= Date.now() - flags.vanishMinutes * 60_000;     // "vanishing" messages drop out of view after N minutes

  return {
    start() { if (!timer) { void pollThenMark(); timer = setInterval(poll, 900); timer.unref?.(); } },
    /** True once the room has loaded its switches at least once (before that, ask the database). */
    ready: () => polled,
    stop() { if (timer) clearInterval(timer); timer = null; },
    poll,
    flags: () => flags,
    words: () => flags.words,
    /** What a client needs: the new messages after `after`, or the whole window if the epoch moved. */
    feed(after, clientEpoch) {
      const reset = clientEpoch === undefined || clientEpoch === null || Number(clientEpoch) !== epoch || after > seq;     // after > seq: this server restarted
      const live = messages.filter(x => alive(x.m));
      return { epoch, seq, reset, messages: (reset ? live : live.filter(x => x.seq > after)).map(x => x.m), visible: flags.visible, enabled: flags.enabled, vanishMinutes: flags.vanishMinutes, serverTime: Date.now() };
    },
    /** Make a just-posted message visible to everyone right away (the poll will confirm it). */
    add(m) { if (!messages.some(x => x.m.id === m.id)) { messages = [...messages, { m, seq: ++seq }].slice(-300); void firebase.pushMessages([m]); } },     // maxId is left to the poll, so nothing with a lower id is skipped
    /** Marks the student as being in the room; returns false if the room is full and they are not already in. */
    enter(sub) {
      const now = Date.now(); const cur = presence.get(sub);
      if (!cur && activeCount() >= flags.capacity) return false;
      presence.set(sub, { since: cur?.since ?? now, last: now }); return true;
    },
    activeCount,
    size: () => messages.length,
    _seq: () => seq,
  };
}
