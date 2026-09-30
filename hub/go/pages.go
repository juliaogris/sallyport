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

const handoffPage = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width"><style>body{font:18px/1.5 system-ui,sans-serif;margin:24px 16px}button{font-size:18px;padding:14px 22px;margin:10px 0;min-width:12em;border-radius:10px}form{margin:0}</style><title>sallyport</title>
<pre id="out">Signing in...</pre><script>
const [sid, subject, start] = location.hash.slice(1).split('.');
let path = '/';
try { const p = atob((start || '').replace(/-/g, '+').replace(/_/g, '/')); if (p.startsWith('/') && !p.startsWith('//') && !p.includes('\\')) path = p; } catch (e) {}
history.replaceState(null, '', location.pathname);
fetch(location.pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sid, subject }) })
  .then(r => r.ok ? location.replace(path) : r.text().then(t => { document.getElementById('out').textContent = 'error: ' + r.status + ' ' + t; }));
</script>`
