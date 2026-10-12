package main

// style makes text and buttons larger, so they are easy to tap on a phone.
const style = `<style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style>`

const loginPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport login</title>
<button id="go">Log in with passkey</button><pre id="out"></pre><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
document.getElementById('go').onclick = async () => {
  try {
    const c = await post('/webapi/login/begin');
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: dec(c.challenge), rpId: c.rpId, timeout: c.timeout || undefined,
      userVerification: c.userVerification || 'required',
      allowCredentials: c.allowCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
    } });
    await post('/webapi/login/finish', {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type, extensions: cred.getClientExtensionResults(),
      response: {
        authenticatorData: enc(cred.response.authenticatorData), clientDataJSON: enc(cred.response.clientDataJSON),
        signature: enc(cred.response.signature), userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : null,
      },
    });
    location.href = '/';
  } catch (e) { out.textContent = 'error: ' + e; }
};
</script>`

const invitePage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport invite</title>
<button id="go">Register a passkey</button><pre id="out"></pre><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
const token = location.pathname.split('/').pop();
document.getElementById('go').onclick = async () => {
  try {
    const c = await post('/webapi/invite/' + token + '/begin');
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: dec(c.challenge), rp: c.rp,
      user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
      pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
      excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
      attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
    } });
    await post('/webapi/invite/' + token + '/finish', {
      type: cred.type, rawId: enc(cred.rawId),
      response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
    });
    location.href = '/';
  } catch (e) { out.textContent = 'error: ' + e; }
};
</script>`

const passkeysPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport passkeys</title>
<style>main{max-width:40em}h1{font-size:28px;margin:8px 0 16px}h2{font-size:20px;margin:28px 0 4px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid #ccc;vertical-align:middle}th{font-weight:600;color:#555}td.act{text-align:right;padding-right:0}td button{min-width:0;margin:0;padding:6px 14px;font-size:16px}.row{display:flex;flex-wrap:wrap;align-items:center;gap:0 10px}input{font-size:18px;padding:10px;flex:1 1 10em;max-width:20em;box-sizing:border-box}#out{color:#b00;white-space:pre-wrap}#qr{display:block;margin-top:8px}</style>
<main><p><a href="/">Back</a></p><h1>Passkeys</h1>
<table><thead><tr><th>Name</th><th>Added</th><th></th></tr></thead><tbody id="list"></tbody></table>
<h2>Add a passkey on this device</h2><div class="row"><button id="add">Add a passkey</button><span>named</span><input id="name" maxlength="30" aria-label="Name"></div>
<h2>Add a passkey on another device</h2><button id="link">Show a link and QR code</button>
<div id="other" hidden><p>Open this link on the other device, or scan the code. <span id="until"></span></p><p><a id="url" style="word-break:break-all"></a></p><canvas id="qr"></canvas></div>
<pre id="out"></pre></main><script>
// qr returns the modules of a QR code for text as rows of 0 and 1: byte mode, error correction level M, version 1 to 6, mask 0.
function qr(text) {
  const bytes = new TextEncoder().encode(text);
  const T = [[26, 10, 1], [44, 16, 1], [70, 26, 1], [100, 18, 2], [134, 24, 2], [172, 16, 4]];
  const v = T.findIndex(([n, ec, b]) => n - ec * b >= bytes.length + 2);
  if (v < 0) throw new Error('text too long for a QR code');
  const [total, ecLen, blocks] = T[v], dataLen = total - ecLen * blocks, n = 21 + 4 * v;
  const bits = [];
  const put = (val, k) => { for (let i = k - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  put(4, 4); put(bytes.length, 8); bytes.forEach(b => put(b, 8)); put(0, 4);
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let p = 0xec; data.length < dataLen; p ^= 0xfd) data.push(p);
  const exp = [], log = [];
  for (let i = 0, x = 1; i < 255; i++, x = (x << 1) ^ (x & 128 ? 0x11d : 0)) { exp[i] = x; log[x] = i; }
  const mul = (a, b) => a && b ? exp[(log[a] + log[b]) % 255] : 0;
  let gen = [1];
  for (let i = 0; i < ecLen; i++) {
    const next = new Array(gen.length + 1).fill(0);
    gen.forEach((g, j) => { next[j] ^= g; next[j + 1] ^= mul(g, exp[i]); });
    gen = next;
  }
  const rs = block => {
    const res = new Array(ecLen).fill(0);
    for (const b of block) {
      const f = b ^ res.shift();
      res.push(0);
      gen.slice(1).forEach((g, j) => { res[j] ^= mul(g, f); });
    }
    return res;
  };
  const cw = [], per = dataLen / blocks, ecs = [];
  for (let b = 0; b < blocks; b++) ecs.push(rs(data.slice(b * per, (b + 1) * per)));
  for (let i = 0; i < per; i++) for (let b = 0; b < blocks; b++) cw.push(data[b * per + i]);
  for (let i = 0; i < ecLen; i++) for (let b = 0; b < blocks; b++) cw.push(ecs[b][i]);
  const m = Array.from({ length: n }, () => new Array(n).fill(-1));
  const set = (r, c, val) => { if (r >= 0 && r < n && c >= 0 && c < n) m[r][c] = val ? 1 : 0; };
  for (const [r0, c0] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    for (let r = -1; r < 8; r++) for (let c = -1; c < 8; c++) set(r0 + r, c0 + c, r >= 0 && r < 7 && c >= 0 && c < 7 && Math.max(Math.abs(r - 3), Math.abs(c - 3)) != 2);
  }
  for (let i = 8; i < n - 8; i++) { set(6, i, i % 2 == 0); set(i, 6, i % 2 == 0); }
  if (v > 0) for (let r = -2; r < 3; r++) for (let c = -2; c < 3; c++) set(n - 7 + r, n - 7 + c, Math.max(Math.abs(r), Math.abs(c)) != 1);
  for (let i = 0; i < 15; i++) {
    const bit = (0x5412 >> i) & 1;
    if (i < 6) set(i, 8, bit); else if (i < 8) set(i + 1, 8, bit); else if (i == 8) set(8, 7, bit); else set(8, 14 - i, bit);
    if (i < 8) set(8, n - 1 - i, bit); else set(n - 15 + i, 8, bit);
  }
  set(n - 8, 8, 1);
  let i = 0;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right == 6) right = 5;
    for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) {
      const c = right - j, r = ((right + 1) & 2) == 0 ? n - 1 - vert : vert;
      if (m[r][c] < 0) { m[r][c] = (i < cw.length * 8 ? (cw[i >> 3] >> (7 - (i & 7))) & 1 : 0) ^ ((r + c) % 2 == 0 ? 1 : 0); i++; }
    }
  }
  return m;
}
// drawQR draws the QR code for text on canvas, 6 pixels a module with a quiet zone of 4 modules.
function drawQR(canvas, text) {
  const m = qr(text), s = 6, q = 4;
  canvas.width = canvas.height = (m.length + 2 * q) * s;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  m.forEach((row, r) => row.forEach((d, c) => { if (d) ctx.fillRect((c + q) * s, (r + q) * s, s, s); }));
}
</script><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out'), list = document.getElementById('list'), nameInput = document.getElementById('name');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
async function answer() {
  const c = await post('/webapi/passkeys/challenge');
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: dec(c.challenge), rpId: c.rpId, timeout: c.timeout || undefined,
    userVerification: c.userVerification || 'required',
    allowCredentials: c.allowCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
  } });
  return {
    id: cred.id, rawId: enc(cred.rawId), type: cred.type, extensions: cred.getClientExtensionResults(),
    response: {
      authenticatorData: enc(cred.response.authenticatorData), clientDataJSON: enc(cred.response.clientDataJSON),
      signature: enc(cred.response.signature), userHandle: cred.response.userHandle ? enc(cred.response.userHandle) : null,
    },
  };
}
async function load() {
  const { passkeys } = await get('/webapi/passkeys');
  list.replaceChildren(...passkeys.map(p => {
    const tr = document.createElement('tr'), name = document.createElement('td'), added = document.createElement('td'), act = document.createElement('td');
    name.textContent = p.name;
    added.textContent = p.addedAt.slice(0, 10);
    act.className = 'act';
    const b = document.createElement('button');
    b.textContent = 'Remove';
    b.onclick = () => remove(p.name);
    act.append(b);
    tr.append(name, added, act);
    return tr;
  }));
}
async function run(f) {
  try { out.textContent = ''; await f(); await load(); } catch (e) { out.textContent = 'error: ' + e; }
}
function remove(name) {
  if (confirm('Remove ' + name + '?')) run(async () => { await post('/webapi/passkeys/delete', { name, assertion: await answer() }); });
}
document.getElementById('add').onclick = () => run(async () => {
  const a = await answer();
  const c = await post('/webapi/passkeys/begin', a);
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: dec(c.challenge), rp: c.rp,
    user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
    pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
    excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
    attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
  } });
  await post('/webapi/passkeys/finish', { name: nameInput.value, credential: {
    type: cred.type, rawId: enc(cred.rawId),
    response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
  } });
});
let hideOther;
document.getElementById('link').onclick = () => run(async () => {
  const r = await post('/webapi/passkeys/link', await answer());
  const a = document.getElementById('url'), other = document.getElementById('other'), expires = new Date(r.expires);
  a.href = a.textContent = r.url;
  drawQR(document.getElementById('qr'), r.url);
  document.getElementById('until').textContent = 'Valid until ' + expires.toLocaleTimeString() + '.';
  other.hidden = false;
  clearTimeout(hideOther);
  hideOther = setTimeout(() => { other.hidden = true; }, expires - Date.now());
});
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
load().catch(e => { out.textContent = 'error: ' + e; });
</script>`

const addPasskeyPage = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport add passkey</title>
<p>Add a passkey for this device, then log in with it.</p>
<p><input id="name" maxlength="30" size="24"> <button id="go">Add a passkey</button></p><pre id="out"></pre><script>
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const out = document.getElementById('out'), nameInput = document.getElementById('name');
async function post(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}
const token = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
document.getElementById('go').onclick = async () => {
  try {
    out.textContent = '';
    const c = await post('/webapi/add-passkey/begin', { token });
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: dec(c.challenge), rp: c.rp,
      user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
      pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
      excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
      attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
    } });
    await post('/webapi/add-passkey/finish', { token, name: nameInput.value, credential: {
      type: cred.type, rawId: enc(cred.rawId),
      response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
    } });
    location.href = '/web/login';
  } catch (e) { out.textContent = 'error: ' + e; }
};
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
</script>`

const handoffPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><meta name="referrer" content="no-referrer"><title>sallyport</title>
<pre id="out">Signing in...</pre><script>
const [sid, subject, start] = location.hash.slice(1).split('.');
let path = '/';
// The start path must pass the same rule as start_path_ok, including no
// "." or ".." segment, because a path such as "/.//host" resolves to the
// path "//host".
try {
  const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/'));
  const segs = p.split(/[?#]/)[0].toLowerCase().replace(/%2e/g, '.').split('/');
  if (/^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/.test(p) && !segs.some(s => s === '.' || s === '..')) path = p;
} catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>`
