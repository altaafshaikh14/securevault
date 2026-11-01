/********************************************************************
 * OFFLINE DECRYPTION KIT (written next to every automatic backup)
 * Lets the owner decrypt a .vault.json backup even if this website no longer exists.
 * String.raw keeps "\u0000" etc. literal so the generated files contain valid source code.
 ********************************************************************/
const SECUREVAULT_DECRYPT_README = String.raw`==================================================================
  SECUREVAULT - HOW TO DECRYPT YOUR BACKUP WITHOUT THE WEBSITE
==================================================================

FILES IN THIS FOLDER
  SecureVault-AutoBackup-latest.vault.json      Newest encrypted copy (rewritten after every change)
  SecureVault-AutoBackup-YYYY-MM-DD.vault.json  Last encrypted copy of each day (history)
  SecureVault-Offline-Decrypter.html            Stand-alone decrypter, works with NO internet
  HOW-TO-DECRYPT-SecureVault-Backup.txt         This file

The .vault.json files are ENCRYPTED (AES-256-GCM). They are useless to
anyone who does not have ONE of these:
  - your Master Password (plus your Unlock PIN, if you set one), or
  - your 20-character Emergency Recovery Key (looks like SV-XXXX-XXXX-XXXX-XXXX-XXXX)

  >> Never store your Master Password or Recovery Key in this folder. <<
  >> Keep a copy of this folder on a USB drive / second device too.  <<

------------------------------------------------------------------
OPTION 1 - RESTORE INTO SECUREVAULT (if you still have the app)
------------------------------------------------------------------
  1. Open SecureVault. On the unlock screen click "Restore .vault"
     (on a new device: "Import .vault JSON" on the setup screen).
  2. Select SecureVault-AutoBackup-latest.vault.json.
  3. Unlock with your Master Password (+ PIN) or your Recovery Key.

------------------------------------------------------------------
OPTION 2 - OFFLINE DECRYPTER (website deleted / no internet)
------------------------------------------------------------------
  1. Double-click SecureVault-Offline-Decrypter.html. It opens in any
     modern browser (Chrome, Edge, Firefox, Safari) and never connects
     to the internet.
  2. Choose a .vault.json backup file.
  3. Enter your Master Password (+ Unlock PIN if you set one), OR
     switch to "Recovery Key" and enter your Emergency Recovery Key.
  4. Click "Decrypt". All entries are shown on screen.
  5. Optional: "Download CSV" to import into another password manager
     (Bitwarden, 1Password, Chrome, Firefox...). The CSV is PLAIN TEXT -
     delete it right after importing.

------------------------------------------------------------------
OPTION 3 - NODE.JS SCRIPT (if the .html file is lost)
------------------------------------------------------------------
  Install Node.js (https://nodejs.org), save the code below as
  decrypt-securevault.js and run:

      node decrypt-securevault.js SecureVault-AutoBackup-latest.vault.json

  It asks for your password / PIN / recovery key and writes the
  decrypted entries to securevault-decrypted.json (PLAIN TEXT).

----- copy from here -----
const fs = require('fs');
const readline = require('readline');
const { subtle } = require('crypto').webcrypto;

const b64 = (s) => Buffer.from(s, 'base64');
const ask = (q) => new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(q, (answer) => { rl.close(); resolve(answer); });
});

async function openSlot(slot, secret) {
    const material = await subtle.importKey('raw', Buffer.from(secret, 'utf8'), 'PBKDF2', false, ['deriveKey']);
    const kek = await subtle.deriveKey(
        { name: 'PBKDF2', salt: b64(slot.salt), iterations: slot.iterations || 600000, hash: 'SHA-256' },
        material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const rawKey = await subtle.decrypt({ name: 'AES-GCM', iv: b64(slot.iv) }, kek, b64(slot.wrapped));
    return subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
}

(async () => {
    const env = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
    if (env.version !== 3 || !env.slots) throw new Error('Not a SecureVault v3 backup');
    let dataKey;
    if ((await ask('Unlock with (1) Master Password or (2) Recovery Key? ')).trim() === '2') {
        let key = (await ask('Recovery Key: ')).toUpperCase().replace(/[^A-Z0-9]/g, '');
        if (key.length === 22 && key.startsWith('SV')) key = key.slice(2);
        dataKey = await openSlot(env.slots.recovery, key);
    } else {
        let secret = await ask('Master Password: ');
        if (env.slots.password.pinRequired) secret += '\u0000PIN:' + (await ask('Unlock PIN: ')).trim();
        dataKey = await openSlot(env.slots.password, secret);
    }
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64(env.iv) }, dataKey, b64(env.ciphertext));
    const payload = JSON.parse(Buffer.from(plain).toString('utf8'));
    const out = process.argv[3] || 'securevault-decrypted.json';
    fs.writeFileSync(out, JSON.stringify(payload.items, null, 2));
    console.log('Decrypted ' + payload.items.length + ' entries to ' + out + ' (PLAIN TEXT - delete it when done).');
})().catch((err) => {
    console.error('Decryption failed (wrong password / PIN / recovery key, or damaged file): ' + err.message);
    process.exit(1);
});
----- copy until here -----

------------------------------------------------------------------
OPTION 4 - TECHNICAL FORMAT (re-implement in any language)
------------------------------------------------------------------
  The backup is JSON. All binary fields are standard Base64.

  {
    "version": 3, "cipher": "AES-256-GCM", "kdf": "PBKDF2-SHA256",
    "hint": "...", "iv": "...", "ciphertext": "...",
    "slots": {
      "password": { "salt", "iterations", "iv", "wrapped", "pinRequired" },
      "recovery": { "salt", "iterations", "iv", "wrapped" },
      "biometric": (device-bound, cannot be used outside the original device)
    }
  }

  1. Build the secret (UTF-8):
       Master password slot : password
                              or, if pinRequired is true:
                              password + U+0000 + "PIN:" + pin
       Recovery slot        : recovery key in UPPER CASE, remove every
                              character except A-Z and 0-9, then drop the
                              leading "SV" (leaves 20 characters).
  2. KEK  = PBKDF2-HMAC-SHA256(secret, salt, iterations, 32-byte output)
  3. DEK  = AES-256-GCM-Decrypt(key = KEK, iv = slot.iv, data = slot.wrapped)
            -> 32 raw key bytes. (The last 16 bytes of "data" are the GCM tag.)
  4. JSON = AES-256-GCM-Decrypt(key = DEK, iv = iv, data = ciphertext)
            -> UTF-8 JSON:
            { "verifier": "CIPHERVAULT_GCM_VERIFIED", "updatedAt": "...",
              "items": [ { "title", "category", "username", "password",
                           "url", "notes", "favorite", "deletedAt" } ] }
            Items with a non-null "deletedAt" were in Recently Deleted.

  A GCM authentication failure in step 3 means the password / PIN /
  recovery key is wrong. A failure in step 4 means the file is damaged.
==================================================================
`;

const SECUREVAULT_OFFLINE_DECRYPTER_HTML = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>SecureVault Offline Decrypter</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #0b1120; color: #e2e8f0; }
  main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  p { color: #94a3b8; font-size: 14px; line-height: 1.5; }
  .card { background: #111827; border: 1px solid #1f2937; border-radius: 14px; padding: 16px; margin-top: 16px; }
  label { display: block; font-size: 13px; color: #cbd5e1; margin: 10px 0 4px; }
  input[type=text], input[type=password] { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #334155; background: #020617; color: #fff; font-size: 14px; }
  input[type=file] { color: #cbd5e1; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  button { padding: 10px 14px; border-radius: 10px; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; font-weight: 600; cursor: pointer; }
  button.primary { background: #2fa47c; border-color: #2fa47c; color: #070a12; }
  button:disabled { opacity: .5; cursor: wait; }
  .tabs button.active { background: #283872; border-color: #4866d1; }
  .warn { color: #f2c977; }
  .err { color: #f2a1ad; }
  .ok { color: #7fd6b5; }
  .hidden { display: none; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 12px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #1f2937; vertical-align: top; word-break: break-word; }
  th { color: #94a3b8; font-weight: 600; }
  td.mono { font-family: ui-monospace, Consolas, monospace; }
  tr.trash td { opacity: .6; }
</style>
</head>
<body>
<main>
  <h1>SecureVault Offline Decrypter</h1>
  <p>Decrypts a SecureVault <code>.vault.json</code> backup entirely inside this browser window. Nothing is uploaded and no internet connection is needed.</p>

  <div class="card">
    <label for="file">1. Choose your encrypted backup (.vault.json)</label>
    <input type="file" id="file" accept=".json,.vault">
    <p id="file-info"></p>

    <div class="row tabs" style="margin-top:8px">
      <span style="font-size:13px;color:#cbd5e1">2. Unlock with:</span>
      <button type="button" id="tab-password" class="active">Master Password</button>
      <button type="button" id="tab-recovery">Recovery Key</button>
    </div>

    <div id="pane-password">
      <label for="password">Master Password</label>
      <input type="password" id="password" autocomplete="off">
      <div id="pin-box" class="hidden">
        <label for="pin">Unlock PIN (this backup requires it)</label>
        <input type="password" id="pin" inputmode="numeric" autocomplete="off">
      </div>
    </div>
    <div id="pane-recovery" class="hidden">
      <label for="recovery">Emergency Recovery Key</label>
      <input type="text" id="recovery" autocomplete="off" spellcheck="false" placeholder="SV-XXXX-XXXX-XXXX-XXXX-XXXX">
    </div>

    <div class="row" style="margin-top:14px">
      <button type="button" id="decrypt" class="primary">Decrypt</button>
      <button type="button" id="clear">Clear Everything</button>
    </div>
    <p id="status"></p>
  </div>

  <div id="result" class="card hidden">
    <div class="row">
      <strong id="summary"></strong>
      <label style="margin:0 0 0 auto"><input type="checkbox" id="show"> Show passwords</label>
    </div>
    <p class="warn">Downloads below are PLAIN TEXT. Delete them as soon as you have imported them somewhere safe.</p>
    <div class="row">
      <button type="button" id="dl-csv">Download CSV</button>
      <button type="button" id="dl-json">Download JSON</button>
    </div>
    <table>
      <thead><tr><th>Title</th><th>Type</th><th>Username</th><th>Password / Secret</th><th>URL</th><th>Notes</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</main>
<script>
(function () {
    'use strict';
    var VERIFIER = 'CIPHERVAULT_GCM_VERIFIED';
    var enc = new TextEncoder();
    var dec = new TextDecoder();
    var envelope = null;
    var items = [];
    var mode = 'password';
    var $ = function (id) { return document.getElementById(id); };

    function b64(s) {
        var bin = atob(s), out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function normalizeRecoveryKey(s) {
        var c = String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
        return c.length === 22 && c.indexOf('SV') === 0 ? c.slice(2) : c;
    }

    function setStatus(text, cls) {
        $('status').textContent = text;
        $('status').className = cls || '';
    }

    async function openSlot(slot, secret) {
        var material = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
        var kek = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: b64(slot.salt), iterations: slot.iterations || 600000, hash: 'SHA-256' },
            material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        var raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(slot.iv) }, kek, b64(slot.wrapped));
        return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    }

    function setMode(next) {
        mode = next;
        $('tab-password').classList.toggle('active', next === 'password');
        $('tab-recovery').classList.toggle('active', next === 'recovery');
        $('pane-password').classList.toggle('hidden', next !== 'password');
        $('pane-recovery').classList.toggle('hidden', next !== 'recovery');
    }

    $('tab-password').onclick = function () { setMode('password'); };
    $('tab-recovery').onclick = function () { setMode('recovery'); };

    $('file').onchange = function (e) {
        var file = e.target.files && e.target.files[0];
        envelope = null;
        $('file-info').textContent = '';
        $('pin-box').classList.add('hidden');
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function () {
            try {
                var env = JSON.parse(reader.result);
                if (env.version !== 3 || !env.slots || !env.slots.password || !env.iv || !env.ciphertext) {
                    throw new Error('unsupported');
                }
                envelope = env;
                var info = 'Backup loaded. Last change: ' + (env.updatedAt ? new Date(env.updatedAt).toLocaleString() : 'unknown') + '.';
                if (env.hint) info += ' Password hint: ' + env.hint;
                $('file-info').textContent = info;
                $('file-info').className = 'ok';
                $('pin-box').classList.toggle('hidden', !env.slots.password.pinRequired);
                setStatus('');
            } catch (err) {
                $('file-info').textContent = 'This is not a SecureVault v3 backup file.';
                $('file-info').className = 'err';
            }
        };
        reader.readAsText(file);
    };

    $('decrypt').onclick = async function () {
        if (!envelope) { setStatus('Choose a backup file first.', 'err'); return; }
        var btn = $('decrypt');
        btn.disabled = true;
        setStatus('Deriving key... this takes a few seconds.', '');
        try {
            var dataKey;
            if (mode === 'recovery') {
                if (!envelope.slots.recovery) throw new Error('This backup has no recovery-key slot.');
                dataKey = await openSlot(envelope.slots.recovery, normalizeRecoveryKey($('recovery').value));
            } else {
                var secret = $('password').value;
                if (envelope.slots.password.pinRequired) secret += '\u0000PIN:' + $('pin').value.trim();
                dataKey = await openSlot(envelope.slots.password, secret);
            }
            var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(envelope.iv) }, dataKey, b64(envelope.ciphertext));
            var payload = JSON.parse(dec.decode(plain));
            if (payload.verifier !== VERIFIER) throw new Error('Payload verification failed.');
            items = Array.isArray(payload.items) ? payload.items : [];
            $('password').value = '';
            $('pin').value = '';
            $('recovery').value = '';
            render();
            setStatus('Decrypted successfully.', 'ok');
        } catch (err) {
            var wrong = err && (err.name === 'OperationError' || err.name === 'InvalidAccessError');
            setStatus(wrong ? 'Wrong master password / PIN / recovery key (or the file is damaged).' : 'Decryption failed: ' + (err && err.message), 'err');
        } finally {
            btn.disabled = false;
        }
    };

    function cell(tr, text, cls) {
        var td = document.createElement('td');
        td.textContent = text == null ? '' : String(text);
        if (cls) td.className = cls;
        tr.appendChild(td);
        return td;
    }

    function render() {
        var tbody = $('rows');
        var show = $('show').checked;
        tbody.textContent = '';
        items.forEach(function (it) {
            var tr = document.createElement('tr');
            if (it.deletedAt) tr.className = 'trash';
            cell(tr, (it.title || '(untitled)') + (it.deletedAt ? ' [Recently Deleted]' : ''));
            cell(tr, it.category || 'login');
            cell(tr, it.username, 'mono');
            cell(tr, it.password ? (show ? it.password : '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022') : '', 'mono');
            cell(tr, it.url, 'mono');
            cell(tr, it.notes);
            tbody.appendChild(tr);
        });
        var active = items.filter(function (i) { return !i.deletedAt; }).length;
        $('summary').textContent = items.length + ' entries (' + active + ' active, ' + (items.length - active) + ' in Recently Deleted)';
        $('result').classList.remove('hidden');
    }

    $('show').onchange = render;

    function download(text, name, type) {
        var url = URL.createObjectURL(new Blob([text], { type: type }));
        var a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function csvField(v) {
        return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    }

    $('dl-csv').onclick = function () {
        var lines = [['name', 'url', 'username', 'password', 'note', 'category'].join(',')];
        items.filter(function (i) { return !i.deletedAt; }).forEach(function (i) {
            lines.push([i.title, i.url, i.username, i.password, i.notes, i.category].map(csvField).join(','));
        });
        download(lines.join('\r\n'), 'securevault-decrypted.csv', 'text/csv;charset=utf-8');
    };

    $('dl-json').onclick = function () {
        download(JSON.stringify(items, null, 2), 'securevault-decrypted.json', 'application/json');
    };

    $('clear').onclick = function () {
        items = [];
        envelope = null;
        ['password', 'pin', 'recovery', 'file'].forEach(function (id) { $(id).value = ''; });
        $('rows').textContent = '';
        $('result').classList.add('hidden');
        $('file-info').textContent = '';
        $('pin-box').classList.add('hidden');
        setStatus('Cleared.', '');
    };
})();
</script>
</body>
</html>
`;
