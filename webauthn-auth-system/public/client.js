function log(...args) {
  const pre = document.getElementById('log');
  pre.textContent += args.map(a => typeof a === 'string' ? a : JSON.stringify(a, null, 2)).join(' ') + '\n';
}

function base64urlToBuffer(base64url) {
  const padding = '='.repeat((4 - base64url.length % 4) % 4);
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const str = atob(base64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
}
function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Register
document.getElementById('registerBtn').addEventListener('click', async () => {
  const username = document.getElementById('username').value;
  if (!username) { alert('Enter username'); return; }

  log('Requesting register options for', username);
  const res = await fetch('/webauthn/register-options', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ username })
  });
  const options = await res.json();
  log('Options:', options);

  options.challenge = base64urlToBuffer(options.challenge);
  options.user.id = base64urlToBuffer(options.user.id);

  log('Calling navigator.credentials.create()');
  const cred = await navigator.credentials.create({ publicKey: options });
  log('Credential created', cred);

  const attestationResponse = {
    id: cred.id,
    rawId: bufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      attestationObject: bufferToBase64url(cred.response.attestationObject),
    },
  };

  const verifyRes = await fetch('/webauthn/verify-registration', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ username, attestationResponse })
  });
  const verification = await verifyRes.json();
  log('Registration verified:', verification);
  alert(verification.verified ? 'Registered!' : 'Registration failed');
});

// Login
document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('username').value;
  if (!username) { alert('Enter username'); return; }

  log('Requesting authn options for', username);
  const res = await fetch('/webauthn/authn-options', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ username })
  });
  const options = await res.json();
  log('Authn options:', options);

  options.challenge = base64urlToBuffer(options.challenge);
  options.allowCredentials = options.allowCredentials.map(c => ({
    ...c,
    id: base64urlToBuffer(c.id),
  }));

  log('Calling navigator.credentials.get()');
  const assertion = await navigator.credentials.get({ publicKey: options });
  log('Assertion:', assertion);

  const authnResponse = {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
    }
  };

  const verifyRes = await fetch('/webauthn/verify-authn', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ username, assertionResponse: authnResponse })
  });

  const verification = await verifyRes.json();
  log('Authentication verification:', verification);
  alert(verification.verified ? 'Login successful!' : 'Login failed');
});
