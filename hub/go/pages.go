package main

// The pages are the Rust hub's, byte for byte.

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
<p><a href="/">Back</a></p><ul id="list"></ul>
<p><input id="name" maxlength="30" size="24"> <button id="add">Add a passkey</button></p><pre id="out"></pre><script>
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
    const li = document.createElement('li');
    li.append(p.name + ', added ' + p.addedAt.slice(0, 10) + ' ');
    const b = document.createElement('button');
    b.textContent = 'Remove';
    b.style.minWidth = '0';
    b.onclick = () => remove(p.name);
    li.append(b);
    return li;
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
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
load().catch(e => { out.textContent = 'error: ' + e; });
</script>`

const addPasskeyPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport add passkey</title>
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
const token = location.pathname.split('/').pop();
document.getElementById('go').onclick = async () => {
  try {
    out.textContent = '';
    const c = await post('/webapi/add-passkey/' + token + '/begin');
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: dec(c.challenge), rp: c.rp,
      user: { id: dec(c.user.id), name: c.user.name, displayName: c.user.displayName },
      pubKeyCredParams: c.pubKeyCredParams, timeout: c.timeout || undefined,
      excludeCredentials: c.excludeCredentials.map(a => ({ type: a.type, id: dec(a.id) })),
      attestation: c.attestation || 'none', authenticatorSelection: c.authenticatorSelection,
    } });
    await post('/webapi/add-passkey/' + token + '/finish', { name: nameInput.value, credential: {
      type: cred.type, rawId: enc(cred.rawId),
      response: { clientDataJSON: enc(cred.response.clientDataJSON), attestationObject: enc(cred.response.attestationObject) },
    } });
    location.href = '/web/login';
  } catch (e) { out.textContent = 'error: ' + e; }
};
nameInput.value = 'passkey ' + new Date().toISOString().slice(0, 10);
</script>`

const handoffPage = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport</title>
<pre id="out">Signing in...</pre><script>
const [sid, subject, start] = location.hash.slice(1).split('.');
let path = '/';
try { const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/')); if (p.startsWith('/') && !p.startsWith('//') && !p.includes('\\')) path = p; } catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>`
