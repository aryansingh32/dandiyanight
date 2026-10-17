// Community chat moderation. Runs on the server, before a message is stored or shown to anyone.
//   block  → the message vanishes at once; the sender gets a personal warning (second time: removed from the room)
//   reject → not allowed but not abuse (links, phone numbers, emails): refused with a notice, no strike
//   flag   → posted, but the team is alerted (ragging, bullying, college-bashing, and @admin)
// No filter is perfect, so this is one layer: strikes, appeals, admin delete/kick and an admin-editable word list sit on top.

const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '|': 'i', '€': 'e', '£': 'l', '¡': 'i' };
const HOMOGLYPH = { а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ѕ: 's', ј: 'j', ԁ: 'd', ɡ: 'g', ο: 'o', α: 'a', ε: 'e', ι: 'i', κ: 'k', ν: 'v', ρ: 'p', τ: 't', υ: 'u' };
const MASK = /[*#%]/;
const collapse = s => s.replace(/(.)\1+/g, '$1');

/* Whole-word matches only (so "class", "cocktail", "assignment" are safe). Common endings are allowed: fuck → fucking, fucker… */
const TOKEN_WORDS = [
  'fuck', 'shit', 'cunt', 'dick', 'cock', 'piss', 'slut', 'porn', 'anal', 'rape', 'rapist', 'sex', 'ass', 'arse', 'tits', 'boob', 'boobs', 'nude', 'nudes', 'cum', 'jizz', 'wank', 'fap', 'fag', 'twat', 'prick',
  'bitch', 'whore', 'horny', 'pussy', 'bastard', 'retard', 'tranny', 'nigga', 'nigger', 'faggot', 'wanker', 'orgasm', 'erotic', 'blowjob', 'handjob', 'cumshot', 'dumbass', 'jackass', 'dickhead', 'shithead',
  // Hindi / Hinglish
  'lund', 'loda', 'lode', 'lauda', 'lavda', 'lawda', 'lavde', 'lawde', 'chut', 'gand', 'gaand', 'gandu', 'gaandu', 'randi', 'raand', 'bkl', 'bsdk', 'mkc', 'tatti', 'jhant', 'jhaant', 'kutta', 'kutte', 'kutti', 'harami', 'kamina', 'kamini', 'hijra', 'suar', 'chutiya', 'chutiye', 'chutia', 'bhosdi', 'bhosda', 'bhadwa', 'bhadwe', 'bhadva',
];
/* Long, unmistakable roots are also caught when letters are glued together, spaced out or separated by symbols. */
const ROOTS = [
  'motherfucker', 'bullshit', 'asshole', 'madarchod', 'maderchod', 'madarchd', 'bhenchod', 'behenchod', 'bahenchod', 'bhosdike', 'bhosadi', 'bhosdika', 'haramzada', 'haramzade', 'haramkhor', 'chutiya', 'chutiye',
  'gaandu', 'randwa', 'blowjob', 'cumshot', 'dickhead', 'shithead', 'pornhub', 'xvideos', 'nigger', 'faggot', 'bhadwa', 'lavde', 'lawde',
];
const SUFFIX = '(?:s|es|ed|d|er|ers|ing|in|y|ie|z)?';
/** "fuck" → f+u+c+k+ (stretching allowed); a doubled letter must stay doubled: "ass" → a+s{2,}, so the word "as" is safe. */
const stretch = w => { let out = '', i = 0; while (i < w.length) { let j = i; while (j < w.length && w[j] === w[i]) j++; out += `${w[i]}{${j - i >= 2 ? j - i : 1},}`; i = j; } return out; };

const THREATS = [
  /\b(kill|murder|stab|shoot|burn|hang)\s*(you|u|him|her|them|everyone|all|tum|tujhe)\b/,
  /\b(i|we)\s*(will|wil|ll|gonna|shall)\s*(kill|beat|hurt|find|destroy|break)\b/,
  /\bmaar\s*(dunga|dalunga|denge|dalenge|doonga|dunga)\b/, /\b(tod|phod)\s*(dunga|denge|doonga)\b/, /\bjaan\s*se\s*(maar|khatam)/, /\bdekh\s*lunga\b/, /\bbahar\s*mil\b/,
];
/* Posted, but the team is told. */
const FLAGS = [
  [/\b(ragging|ragged|ragger|raggers|bully|bullying|bullied|blackmail|harass(?:ment|ing|ed)?)\b/, 'ragging or bullying'],
  [/\b(fresher|freshers)\s*(ko|ke|ne)\b/, 'ragging or bullying'],
  [/\bseniors?\s*(ne|ko|will|are)\b.*\b(teach|lesson|beat|maar|pakad)/, 'ragging or bullying'],
  [/\b(worst|fraud|scam|useless|trash|waste|pathetic)\s*(college|campus|faculty|management|principal|professors?|teachers?)\b/, 'against the college'],
  [/\b(boycott|shut\s*down)\s*(the\s*)?(college|event|fest)\b/, 'against the college'],
];
const ADMIN_TAG = /(^|[^a-z0-9])@(admin|admins|moderator|moderators|mod)\b/i;
const LINK = /(https?:\/\/|www\.|\b[a-z0-9-]{2,}\.(?:com|in|net|org|co|io|me|app|xyz|link|ly|gl|gg|info|biz|online|site|store|tk|cc)\b)/i;
const EMAIL = /[a-z0-9._%+-]+@[a-z0-9-]+\.[a-z]{2,}/i;

const normalizeBase = text => {
  let t = text.normalize('NFKD').replace(/\p{M}+/gu, '').replace(/[​-‏⁠﻿]/g, '').toLowerCase();
  t = [...t].map(c => HOMOGLYPH[c] ?? c).join('');
  return t;
};
/** Digits and symbols are ambiguous ("0" can stand for o or u, "1" for i or l), so every message is read both ways. */
const LEET_ALT = { '0': 'u', '1': 'l', '!': 'l', '|': 'l' };
const leetify = (tok, alt = false) => tok.replace(/[^a-z0-9@$!|€£¡*#%]/g, '').split('').map(c => (alt ? LEET_ALT[c] : undefined) ?? LEET[c] ?? c).join('');

function buildMatchers(extra = []) {
  const tokenSet = new Set(), rootSet = new Set();
  for (const w of TOKEN_WORDS) tokenSet.add(w);
  for (const w of ROOTS) rootSet.add(w);
  for (const raw of extra) {                                                  // admin-added words
    const w = normalizeBase(String(raw)).replace(/[^a-z0-9]/g, '');
    if (w.length >= 5) rootSet.add(w); else if (w.length >= 2) tokenSet.add(w);
  }
  const tokenRe = [...tokenSet].map(w => ({ w, re: new RegExp(`^${stretch(w)}${SUFFIX}$`), full: w }));
  const roots = [...rootSet].map(w => ({ w, c: collapse(w) }));
  return { tokenRe, roots };
}
const cache = new Map();
const matchersFor = extra => { const k = extra.join('|'); if (!cache.has(k)) { if (cache.size > 20) cache.clear(); cache.set(k, buildMatchers(extra)); } return cache.get(k); };

function abusive(text, extra) {
  const { tokenRe, roots } = matchersFor(extra);
  const base = normalizeBase(text);
  const raw = base.split(/\s+/).filter(Boolean);

  // 1) Each word: strip separators ("f.u.c.k"), undo leetspeak ("sh!t", "b1tch"), squash repeats ("fuuuck").
  const cleaned = raw.map(t => ({ raw: t, c: leetify(t).replace(/[*#%]/g, ''), a: leetify(t, true).replace(/[*#%]/g, '') })).filter(x => x.c);
  for (const { c, a } of cleaned) if (tokenRe.some(({ re }) => re.test(c) || re.test(a))) return true;

  // 2) Masked words: "f*ck", "b**ch" — the mask stands for any letter.
  for (const t of raw) {
    const letters = t.replace(/[^a-z0-9@$!|*#%]/g, '');
    if (letters.length >= 3 && MASK.test(letters) && /[a-z]/.test(letters.replace(MASK, ''))) {
      const re = new RegExp('^' + [...letters].map(ch => (MASK.test(ch) ? '[a-z]' : (LEET[ch] ?? ch).replace(/[^a-z0-9]/g, '.'))).join('') + '$');
      if (tokenRe.some(({ full }) => full.length === letters.length && re.test(full))) return true;
    }
  }

  // 3) Spaced-out letters: "f u c k" → one word.
  const joined = []; let run = '';
  for (const { c } of cleaned) { if (c.length === 1) run += c; else { if (run.length >= 3) joined.push(run); run = ''; } }
  if (run.length >= 3) joined.push(run);
  // …and any stretch inside a run, so an innocent "a" or "i" in front ("such a f u c k i n g") cannot hide it.
  for (const j of joined) for (let i = 0; i < j.length; i++) for (let k = i + 3; k <= j.length; k++) { const part = j.slice(i, k); if (tokenRe.some(({ re }) => re.test(part))) return true; }

  // 4) Long roots anywhere, even glued into other text or broken up by symbols.
  for (const squashed of [collapse(cleaned.map(x => x.c).join('')), collapse(cleaned.map(x => x.a).join(''))])
    for (const { c } of roots) if (squashed.includes(c)) return true;
  return false;
}

/** @returns {{ action: 'ok' | 'block' | 'reject', rule?: string, flag?: string, mention: boolean, text: string }} */
export function checkMessage(input, extraWords = []) {
  // Text only: control characters (NUL would crash the database call), zero-width and right-to-left override tricks are stripped before anything else looks at it.
  const text = String(input ?? '').normalize('NFC').replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '').replace(/\s+/g, ' ').trim();
  const base = { mention: ADMIN_TAG.test(text), text };
  if (text.length < 1) return { ...base, action: 'reject', rule: 'empty message' };
  if (text.length > 300) return { ...base, action: 'reject', rule: 'too long' };

  const lower = normalizeBase(text);
  const squishedDigits = lower.replace(/[\s().\-_,]/g, '');
  if (LINK.test(lower) || EMAIL.test(lower) || /\d{8,}/.test(squishedDigits)) return { ...base, action: 'reject', rule: 'links and contact details' };
  if (abusive(text, extraWords)) return { ...base, action: 'block', rule: 'abusive or vulgar language' };
  const spaced = lower.replace(/\s+/g, ' ');
  if (THREATS.some(re => re.test(spaced))) return { ...base, action: 'block', rule: 'threatening language' };
  for (const [re, label] of FLAGS) if (re.test(spaced)) return { ...base, action: 'ok', flag: label, mention: true };
  return { ...base, action: 'ok' };
}
