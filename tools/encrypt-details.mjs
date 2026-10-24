// Encrypts the private party details into index.html.
// Usage: DETAILS_PASSWORD=... node tools/encrypt-details.mjs /path/to/details.html
// The plaintext details file must live OUTSIDE this repo (Netlify publishes the repo root).
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const pw = process.env.DETAILS_PASSWORD;
const src = process.argv[2];
if (!pw || !src) { console.error('Set DETAILS_PASSWORD and pass the details file path.'); process.exit(1); }

const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const iter = 250000;
const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(readFileSync(src, 'utf8'))));
const b64 = (u) => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ v: 1, iter, salt: b64(salt), iv: b64(iv), ct: b64(ct) });

const page = new URL('../index.html', import.meta.url);
const html = readFileSync(page, 'utf8');
const re = /(<script type="application\/json" id="locked">)[\s\S]*?(<\/script>)/;
if (!re.test(html)) { console.error('Locked payload marker not found in index.html'); process.exit(1); }
writeFileSync(page, html.replace(re, `$1${payload}$2`));
console.log('Encrypted', readFileSync(src, 'utf8').length, 'chars of details into index.html');
