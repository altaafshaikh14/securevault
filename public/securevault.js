/********************************************************************
 * 1. PWA MANIFEST, SERVICE WORKER & PERSISTENT STORAGE PROTECTION
 ********************************************************************/
let deferredInstallPrompt = null;

async function initializePWAAndStorageProtection() {
    // Request browser-level storage persistence so the OS doesn't auto-evict localStorage
    if (navigator.storage && navigator.storage.persist) {
        try {
            const isPersisted = await navigator.storage.persist();
            const badge = document.getElementById('storage-persist-badge');
            if (badge && isPersisted) {
                badge.innerHTML = `<i class="fa-solid fa-lock mr-1 text-emerald-400"></i>OS Eviction Protected`;
            }
        } catch (e) {}
    }

    // Service workers cannot be registered from blob: URLs, so sw.js must be served next to this file
    if ('serviceWorker' in navigator && window.isSecureContext && /^https?:$/.test(window.location.protocol)) {
        navigator.serviceWorker.register('sw.js').catch(() => {});
    }

    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredInstallPrompt = e;
        const btn = document.getElementById('pwa-install-btn');
        btn.classList.remove('hidden');
        btn.onclick = async () => {
            if (!deferredInstallPrompt) return;
            deferredInstallPrompt.prompt();
            await deferredInstallPrompt.userChoice;
            deferredInstallPrompt = null;
            btn.classList.add('hidden');
        };
    });
}

/********************************************************************
 * 2. DUAL-SLOT WEB CRYPTO API ENGINE (MASTER PASSWORD + RECOVERY KEY)
 ********************************************************************/
// Legacy key names are kept so vaults created by earlier versions keep loading
const STORAGE_KEY = 'CIPHERVAULT_ENCRYPTED_STORE_V1';
const PREVIOUS_VAULT_KEY = 'SECUREVAULT_PREVIOUS_VAULT_V1';
const LEGACY_BIO_TOKEN_KEY = 'SECUREVAULT_BIO_TOKEN_V1';
const VAULT_VERSION = 3;
const PBKDF2_ITERATIONS = 600000; // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
const SHARE_PBKDF2_ITERATIONS = 100000;
const PAYLOAD_VERIFIER = 'CIPHERVAULT_GCM_VERIFIED';
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

// Uniform integer in [0, max) using rejection sampling to avoid modulo bias
function secureRandomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do {
        crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % max;
}

function normalizeRecoveryKey(str) {
    const compact = String(str || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    return compact.length === 22 && compact.startsWith('SV') ? compact.slice(2) : compact;
}

function generateFormattedRecoveryKey() {
    const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    let chars = '';
    for (let i = 0; i < 20; i++) {
        chars += alphabet[secureRandomInt(alphabet.length)];
    }
    return `SV-${chars.slice(0,4)}-${chars.slice(4,8)}-${chars.slice(8,12)}-${chars.slice(12,16)}-${chars.slice(16,20)}`;
}

async function deriveMasterKey(secretString, saltBuffer, iterations = PBKDF2_ITERATIONS) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        textEncoder.encode(secretString),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuffer, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
}

function composePasswordSecret(password, pin) {
    return pin ? `${password}\u0000PIN:${pin}` : password;
}

// The vault is encrypted with a random data key (DEK); each unlock method only wraps that DEK.
function generateDataKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function wrapDataKey(dek, kek) {
    const iv = randomBytes(12);
    const wrapped = await crypto.subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv });
    return { iv: bufferToBase64(iv.buffer), wrapped: bufferToBase64(wrapped) };
}

function unwrapDataKey(slot, kek) {
    return crypto.subtle.unwrapKey(
        'raw',
        base64ToBuffer(slot.wrapped),
        kek,
        { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(slot.iv)) },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function createPasswordSlot(dek, password, pin) {
    const salt = randomBytes(16);
    const kek = await deriveMasterKey(composePasswordSecret(password, pin), salt.buffer, PBKDF2_ITERATIONS);
    return {
        kdf: 'PBKDF2-SHA256',
        iterations: PBKDF2_ITERATIONS,
        salt: bufferToBase64(salt.buffer),
        pinRequired: !!pin,
        ...(await wrapDataKey(dek, kek))
    };
}

async function openPasswordSlot(slot, password, pin) {
    const kek = await deriveMasterKey(composePasswordSecret(password, pin), base64ToBuffer(slot.salt), slot.iterations || PBKDF2_ITERATIONS);
    return unwrapDataKey(slot, kek);
}

async function createRecoverySlot(dek, recoveryKey) {
    const salt = randomBytes(16);
    const kek = await deriveMasterKey(normalizeRecoveryKey(recoveryKey), salt.buffer, PBKDF2_ITERATIONS);
    return {
        kdf: 'PBKDF2-SHA256',
        iterations: PBKDF2_ITERATIONS,
        salt: bufferToBase64(salt.buffer),
        ...(await wrapDataKey(dek, kek))
    };
}

async function openRecoverySlot(slot, recoveryKey) {
    const kek = await deriveMasterKey(normalizeRecoveryKey(recoveryKey), base64ToBuffer(slot.salt), slot.iterations || PBKDF2_ITERATIONS);
    return unwrapDataKey(slot, kek);
}

async function decryptPayload(dek, envelope) {
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(envelope.iv)) },
        dek,
        base64ToBuffer(envelope.ciphertext)
    );
    const parsed = JSON.parse(textDecoder.decode(decrypted));
    if (parsed.verifier !== PAYLOAD_VERIFIER) {
        throw new Error('Vault payload verification failed');
    }
    return parsed;
}

function isValidEnvelope(env) {
    if (!env || typeof env !== 'object') return false;
    if (env.version === VAULT_VERSION) {
        return !!(env.slots && env.slots.password && env.slots.password.wrapped && env.iv && env.ciphertext);
    }
    return !!(env.salt && env.iv && env.ciphertext);
}

function readStoredEnvelope() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { status: 'none', envelope: null };
    try {
        const envelope = JSON.parse(raw);
        if (isValidEnvelope(envelope)) return { status: 'ok', envelope };
    } catch (e) {}
    return { status: 'corrupt', envelope: null };
}

function envelopeRequiresPin(env) {
    if (!env) return false;
    return env.version === VAULT_VERSION ? !!env.slots.password.pinRequired : !!env.mfaRequired;
}

// Saves are serialized so an older snapshot can never overwrite a newer one
let persistChain = Promise.resolve();

function persistVault() {
    if (!activeSession.dek || !activeSession.slots) {
        return Promise.reject(new Error('Vault is locked'));
    }
    const dek = activeSession.dek;
    const slots = { ...activeSession.slots };
    const hint = activeSession.hint || '';
    const updatedAt = new Date().toISOString();
    const plaintext = textEncoder.encode(JSON.stringify({
        verifier: PAYLOAD_VERIFIER,
        updatedAt,
        recoveryKeyFormatted: activeSession.recoveryKeyFormatted,
        lastBackupAt: activeSession.lastBackupAt || null,
        items: activeSession.items
    }));

    const job = persistChain.then(async () => {
        const iv = randomBytes(12);
        const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, plaintext);
        const envelope = {
            version: VAULT_VERSION,
            app: 'SecureVault',
            cipher: 'AES-256-GCM',
            kdf: 'PBKDF2-SHA256',
            hint,
            updatedAt,
            slots,
            iv: bufferToBase64(iv.buffer),
            ciphertext: bufferToBase64(ciphertext)
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
        scheduleAutoBackup();
        return envelope;
    });
    persistChain = job.catch(() => {});
    return job;
}

async function saveVault() {
    try {
        await persistVault();
        return true;
    } catch (err) {
        showToast(`Save failed — changes were NOT stored (${err && err.message ? err.message : 'unknown error'}).`, 'error');
        return false;
    }
}

const ITEM_CATEGORIES = ['login', 'card', 'note', 'passkey'];
const SAFE_ITEM_ID = /^[A-Za-z0-9-]{1,64}$/;

// Items may come from imported files, so IDs are restricted to a safe charset before they are rendered into markup
function sanitizeItems(items) {
    if (!Array.isArray(items)) return [];
    const seenIds = new Set();
    return items.filter(i => i && typeof i === 'object').map(i => {
        let id = typeof i.id === 'string' && SAFE_ITEM_ID.test(i.id) ? i.id : crypto.randomUUID();
        if (seenIds.has(id)) id = crypto.randomUUID();
        seenIds.add(id);
        const breached = Number(i.breachedCount);
        return {
            id,
            title: String(i.title ?? '').trim() || 'Untitled',
            category: ITEM_CATEGORIES.includes(i.category) ? i.category : 'login',
            username: String(i.username ?? ''),
            password: String(i.password ?? ''),
            url: String(i.url ?? ''),
            notes: String(i.notes ?? ''),
            favorite: !!i.favorite,
            deletedAt: i.deletedAt ? String(i.deletedAt) : null,
            updatedAt: i.updatedAt ? String(i.updatedAt) : new Date().toISOString(),
            breachedCount: Number.isFinite(breached) && breached > 0 ? Math.floor(breached) : 0
        };
    });
}

// ---- Legacy (v1/v2) envelope support, used only to migrate old vaults to v3 ----
async function decryptLegacyWithPassword(masterPassword, envelope) {
    const key = await deriveMasterKey(masterPassword, base64ToBuffer(envelope.salt), envelope.iterations || 250000);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(envelope.iv)) },
        key,
        base64ToBuffer(envelope.ciphertext)
    );
    const parsed = JSON.parse(textDecoder.decode(decrypted));
    if (parsed.verifier !== PAYLOAD_VERIFIER) throw new Error('Vault payload verification failed');
    return parsed;
}

async function decryptLegacyWithRecoveryKey(rawRecoveryInput, envelope) {
    if (!envelope.recoverySlot) throw new Error('No recovery slot found on this vault');
    const slot = envelope.recoverySlot;
    const legacyNormalized = String(rawRecoveryInput || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const recKey = await deriveMasterKey(legacyNormalized, base64ToBuffer(slot.salt), envelope.iterations || 250000);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(slot.iv)) },
        recKey,
        base64ToBuffer(slot.ciphertext)
    );
    const parsed = JSON.parse(textDecoder.decode(decrypted));
    if (parsed.verifier !== PAYLOAD_VERIFIER) throw new Error('Recovery verification failed');
    return parsed;
}

/********************************************************************
 * 3. APPLICATION STATE & AUTO-LOCK SESSION MANAGER
 ********************************************************************/
const IDLE_TIMEOUT_MS = 180000;

function createEmptySession() {
    return {
        dek: null,
        slots: null,
        recoveryKeyFormatted: null,
        hint: '',
        lastBackupAt: null,
        items: [],
        category: 'all',
        revealedIds: new Set(),
        idleDeadline: 0,
        idleInterval: null,
        clipboardSecondsRemaining: 0,
        clipboardInterval: null,
        pendingClipboardText: null
    };
}

let activeSession = createEmptySession();

function loadSession(dek, slots, hint, payload) {
    activeSession.dek = dek;
    activeSession.slots = slots;
    activeSession.hint = hint || '';
    activeSession.recoveryKeyFormatted = payload.recoveryKeyFormatted || null;
    activeSession.lastBackupAt = payload.lastBackupAt || null;
    activeSession.items = sanitizeItems(payload.items);
}

const SECURITY_LOG_KEY = 'CIPHERVAULT_SECURITY_AUDIT_LOG_V1';

// The log is stored unencrypted, so callers must never pass site names, usernames or secrets
function recordSecurityEvent(eventTitle, severity = 'info') {
    try {
        const raw = localStorage.getItem(SECURITY_LOG_KEY);
        const logs = raw ? JSON.parse(raw) : [];
        logs.unshift({
            id: crypto.randomUUID(),
            title: eventTitle,
            severity,
            timestamp: new Date().toISOString()
        });
        localStorage.setItem(SECURITY_LOG_KEY, JSON.stringify(logs.slice(0, 35)));
    } catch (e) {}
}

function resetIdleTimer() {
    if (!activeSession.dek) return;
    activeSession.idleDeadline = Date.now() + IDLE_TIMEOUT_MS;
    updateIdleDisplay();
}

// Deadline-based so throttled timers in background tabs cannot extend the unlocked period
function checkIdleDeadline() {
    if (!activeSession.dek) return;
    if (Date.now() >= activeSession.idleDeadline) {
        lockVault('Vault auto-locked due to inactivity.');
    } else {
        updateIdleDisplay();
    }
}

function startIdleMonitor() {
    clearInterval(activeSession.idleInterval);
    activeSession.idleDeadline = Date.now() + IDLE_TIMEOUT_MS;
    updateIdleDisplay();
    activeSession.idleInterval = setInterval(checkIdleDeadline, 1000);
}

function updateIdleDisplay() {
    const el = document.getElementById('idle-timer-display');
    if (!el) return;
    const remaining = Math.max(0, Math.ceil((activeSession.idleDeadline - Date.now()) / 1000));
    const mins = String(Math.floor(remaining / 60)).padStart(2, '0');
    const secs = String(remaining % 60).padStart(2, '0');
    el.textContent = `${mins}:${secs}`;
}

['mousemove', 'keydown', 'mousedown', 'touchstart'].forEach(evt => {
    window.addEventListener(evt, resetIdleTimer, { passive: true });
});
document.addEventListener('visibilitychange', checkIdleDeadline);

// Phones/tablets: lock as soon as the app goes to the background or the screen turns off
const LOCK_ON_HIDE = window.matchMedia('(pointer: coarse)').matches;
const EXTERNAL_UI_OPEN_WINDOW_MS = 10000;
const EXTERNAL_UI_MAX_AWAY_MS = 120000;
let externalUiRequestedAt = 0;
let awayInExternalUi = false;
let hiddenSince = 0;

// File pickers, share sheets and biometric prompts can briefly background the page; they must not lock the vault
function expectExternalUi() {
    externalUiRequestedAt = Date.now();
}

function handleBackgroundLock() {
    if (document.hidden) {
        hiddenSince = Date.now();
        awayInExternalUi = Date.now() - externalUiRequestedAt < EXTERNAL_UI_OPEN_WINDOW_MS;
        if (LOCK_ON_HIDE && activeSession.dek && !awayInExternalUi) {
            lockVault('Vault locked because you left the app.', { keepClipboard: true });
        }
        return;
    }
    if (LOCK_ON_HIDE && activeSession.dek && awayInExternalUi && Date.now() - hiddenSince > EXTERNAL_UI_MAX_AWAY_MS) {
        lockVault('Vault locked because you were away too long.', { keepClipboard: true });
    }
    awayInExternalUi = false;
    externalUiRequestedAt = 0;
    flushDeferredClipboardScrub();
}
document.addEventListener('visibilitychange', handleBackgroundLock);

/********************************************************************
 * 4. VAULT SETUP, UNLOCK, HINT & EMERGENCY RECOVERY FLOWS
 ********************************************************************/
function checkExistingVault() {
    const stored = readStoredEnvelope();
    const setupForm = document.getElementById('setup-form');
    const unlockForm = document.getElementById('unlock-form');
    const recoveryForm = document.getElementById('recovery-form');
    const subtitle = document.getElementById('auth-subtitle');
    const hintBox = document.getElementById('hint-box');

    recoveryForm.classList.add('hidden');
    if (hintBox) hintBox.classList.add('hidden');

    if (stored.status === 'none') {
        unlockForm.classList.add('hidden');
        setupForm.classList.remove('hidden');
        subtitle.textContent = 'Create Your Zero-Knowledge Local Vault';
        setTimeout(() => document.getElementById('setup-password')?.focus(), 100);
        return;
    }

    setupForm.classList.add('hidden');
    unlockForm.classList.remove('hidden');
    const isCorrupt = stored.status === 'corrupt';
    const env = stored.envelope;
    subtitle.textContent = isCorrupt ? 'Stored Vault Is Unreadable' : 'Encrypted Vault Detected on Device';
    document.getElementById('vault-corrupt-warning').classList.toggle('hidden', !isCorrupt);
    document.getElementById('unlock-submit-btn').disabled = isCorrupt;
    document.getElementById('unlock-mfa-box').classList.toggle('hidden', !envelopeRequiresPin(env));

    const hasBiometricSlot = !!(env && env.version === VAULT_VERSION && env.slots.biometric);
    document.getElementById('biometric-unlock-row').classList.toggle('hidden', !(hasBiometricSlot && isWebAuthnAvailable()));
    const bioHint = document.getElementById('biometric-status-hint');
    if (hasBiometricSlot && !isWebAuthnAvailable()) {
        bioHint.textContent = 'Biometric unlock needs HTTPS (or localhost) and a WebAuthn-capable browser.';
    } else if (hasBiometricSlot) {
        bioHint.textContent = '';
    } else {
        bioHint.textContent = isCorrupt ? '' : 'Biometric unlock can be enrolled in the Security Center after unlocking.';
    }
    if (!isCorrupt) setTimeout(() => document.getElementById('unlock-password')?.focus(), 100);
}

function toggleHintDisplay() {
    const { envelope } = readStoredEnvelope();
    if (!envelope) return;
    const hintBox = document.getElementById('hint-box');
    const hintText = document.getElementById('hint-text');

    hintText.textContent = envelope.hint
        ? envelope.hint
        : 'No password hint was configured for this vault. Use your Emergency Recovery Key below if needed.';
    hintBox.classList.toggle('hidden');
}

function switchToRecoveryForm() {
    document.getElementById('unlock-form').classList.add('hidden');
    document.getElementById('setup-form').classList.add('hidden');
    document.getElementById('recovery-form').classList.remove('hidden');
    document.getElementById('auth-subtitle').textContent = 'Emergency Recovery Key Reset';
    setTimeout(() => document.getElementById('recovery-key-input')?.focus(), 100);
}

// Rejects hints that contain the password or any 5-character run of it
function hintRevealsPassword(hint, password) {
    const h = String(hint || '').toLowerCase();
    const p = String(password || '').toLowerCase();
    if (!h || !p) return false;
    if (h.includes(p)) return true;
    for (let i = 0; i + 5 <= p.length; i++) {
        if (h.includes(p.slice(i, i + 5))) return true;
    }
    return false;
}

function isWrongCredentialError(err) {
    return err && (err.name === 'OperationError' || err.name === 'InvalidAccessError');
}

async function handleSetupVault(e) {
    e.preventDefault();
    const pwd = document.getElementById('setup-password').value;
    const confirmPwd = document.getElementById('setup-confirm').value;
    const hint = document.getElementById('setup-hint').value.trim();
    const btn = document.getElementById('setup-submit-btn');

    if (pwd !== confirmPwd) {
        showToast('Master passwords do not match.', 'error');
        return;
    }
    if (hintRevealsPassword(hint, pwd)) {
        showToast('Your hint contains part of your password. Choose a different hint.', 'error');
        return;
    }

    try {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Generating Keys...`;

        const dek = await generateDataKey();
        const recoveryKey = generateFormattedRecoveryKey();
        const [passwordSlot, recoverySlot] = await Promise.all([
            createPasswordSlot(dek, pwd, ''),
            createRecoverySlot(dek, recoveryKey)
        ]);

        activeSession = createEmptySession();
        loadSession(dek, { password: passwordSlot, recovery: recoverySlot, biometric: null }, hint, {
            recoveryKeyFormatted: recoveryKey,
            lastBackupAt: null,
            items: []
        });
        await persistVault();
        localStorage.removeItem(LEGACY_BIO_TOKEN_KEY);
        recordSecurityEvent('New encrypted vault initialized with recovery key.', 'success');

        document.getElementById('setup-form').reset();
        updateSetupStrength('');
        transitionToUnlockedApp();
        openRecoveryKitModal();
        showToast('Vault initialized! Save your Emergency Recovery Key.', 'success');
    } catch (err) {
        activeSession = createEmptySession();
        showToast('Failed to initialize the encrypted vault.', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-key"></i> Initialize Vault & Recovery Key`;
    }
}

// Re-encrypts a v1/v2 vault into the v3 data-key format; the old biometric token is discarded
async function migrateLegacyVault(legacyPayload, envelope, password, pin) {
    const dek = await generateDataKey();
    const hadRecoveryKey = !!legacyPayload.recoveryKeyFormatted;
    const recoveryKey = legacyPayload.recoveryKeyFormatted || generateFormattedRecoveryKey();
    const [passwordSlot, recoverySlot] = await Promise.all([
        createPasswordSlot(dek, password, pin),
        createRecoverySlot(dek, recoveryKey)
    ]);
    loadSession(dek, { password: passwordSlot, recovery: recoverySlot, biometric: null }, envelope.hint || legacyPayload.hint || '', {
        recoveryKeyFormatted: recoveryKey,
        lastBackupAt: legacyPayload.lastBackupAt || envelope.lastBackupAt || null,
        items: legacyPayload.items
    });
    await persistVault();
    localStorage.removeItem(LEGACY_BIO_TOKEN_KEY);
    recordSecurityEvent('Vault upgraded to v3 key-wrapping format.', 'success');
    return hadRecoveryKey;
}

async function handleUnlockVault(e) {
    e.preventDefault();
    const pwd = document.getElementById('unlock-password').value;
    const enteredPin = (document.getElementById('unlock-mfa-code')?.value || '').trim();
    const btn = document.getElementById('unlock-submit-btn');

    const stored = readStoredEnvelope();
    if (stored.status !== 'ok') {
        checkExistingVault();
        showToast('No readable vault found on this device.', 'error');
        return;
    }
    const env = stored.envelope;

    try {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Deriving key...`;
        activeSession = createEmptySession();
        let showKitAfterUnlock = false;

        if (env.version === VAULT_VERSION) {
            const pin = env.slots.password.pinRequired ? enteredPin : '';
            const dek = await openPasswordSlot(env.slots.password, pwd, pin);
            const payload = await decryptPayload(dek, env);
            loadSession(dek, env.slots, env.hint, payload);
        } else {
            const legacyPayload = await decryptLegacyWithPassword(pwd, env);
            if (legacyPayload.mfaPin && legacyPayload.mfaPin !== enteredPin) {
                const pinError = new Error('Wrong PIN');
                pinError.name = 'OperationError';
                throw pinError;
            }
            showKitAfterUnlock = !(await migrateLegacyVault(legacyPayload, env, pwd, legacyPayload.mfaPin || ''));
        }

        recordSecurityEvent('Vault unlocked with master password.', 'success');
        document.getElementById('unlock-form').reset();
        transitionToUnlockedApp();
        if (showKitAfterUnlock) openRecoveryKitModal();
        showToast('Vault decrypted and verified in memory.', 'success');
    } catch (err) {
        activeSession = createEmptySession();
        if (isWrongCredentialError(err)) {
            recordSecurityEvent('Failed unlock attempt (wrong master password or PIN).', 'error');
            showToast('Incorrect master password or PIN. Attempt logged.', 'error');
        } else {
            showToast(`Unlock failed: ${err && err.message ? err.message : 'unknown error'}`, 'error');
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-unlock-keyhole"></i> Decrypt & Unlock`;
    }
}

async function handleRecoveryReset(e) {
    e.preventDefault();
    const rawRecKey = document.getElementById('recovery-key-input').value;
    const newPwd = document.getElementById('recovery-new-password').value;
    const newHint = document.getElementById('recovery-new-hint').value.trim();
    const btn = document.getElementById('recovery-submit-btn');

    if (hintRevealsPassword(newHint, newPwd)) {
        showToast('Your hint contains part of your password. Choose a different hint.', 'error');
        return;
    }
    const stored = readStoredEnvelope();
    if (stored.status !== 'ok') {
        showToast('No readable vault found on this device.', 'error');
        return;
    }
    const env = stored.envelope;

    try {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Verifying Recovery Key...`;

        let dek;
        let payload;
        let biometricSlot = null;
        const hadPin = envelopeRequiresPin(env);
        if (env.version === VAULT_VERSION) {
            dek = await openRecoverySlot(env.slots.recovery, rawRecKey);
            payload = await decryptPayload(dek, env);
            biometricSlot = env.slots.biometric || null;
        } else {
            payload = await decryptLegacyWithRecoveryKey(rawRecKey, env);
            dek = await generateDataKey();
            localStorage.removeItem(LEGACY_BIO_TOKEN_KEY);
        }

        // A used recovery key is considered exposed, so a fresh one is issued
        const newRecoveryKey = generateFormattedRecoveryKey();
        const [passwordSlot, recoverySlot] = await Promise.all([
            createPasswordSlot(dek, newPwd, ''),
            createRecoverySlot(dek, newRecoveryKey)
        ]);

        activeSession = createEmptySession();
        loadSession(dek, { password: passwordSlot, recovery: recoverySlot, biometric: biometricSlot }, newHint || env.hint || '', {
            ...payload,
            recoveryKeyFormatted: newRecoveryKey
        });
        await persistVault();
        recordSecurityEvent('Master password reset with recovery key; new recovery key issued.', 'success');

        document.getElementById('recovery-form').reset();
        transitionToUnlockedApp();
        openRecoveryKitModal();
        showToast(`Vault recovered. A NEW recovery key was issued — save it now.${hadPin ? ' Your Unlock PIN was removed.' : ''}`, 'success');
    } catch (err) {
        activeSession = createEmptySession();
        if (isWrongCredentialError(err)) {
            recordSecurityEvent('Failed recovery-key attempt.', 'error');
            showToast('Invalid Emergency Recovery Key.', 'error');
        } else {
            showToast(`Recovery failed: ${err && err.message ? err.message : 'unknown error'}`, 'error');
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-rotate"></i> Recover Vault & Reset Password`;
    }
}

function transitionToUnlockedApp() {
    document.getElementById('auth-screen').classList.add('hidden');
    document.getElementById('app-screen').classList.remove('hidden');
    activeSession.revealedIds.clear();
    updateBackupStatusBanner();
    refreshAutoBackupPermission().then(() => {
        if (autoBackup.mode === 'folder' && autoBackup.paused) {
            showToast('Automatic backup is paused until you reconnect the backup folder.', 'info', {
                actionText: 'Reconnect',
                onAction: () => reconnectAutoBackupFolder()
            });
        }
    });
    startIdleMonitor();
    setCategoryFilter(activeSession.category || 'all');
}

const SENSITIVE_FIELD_IDS = [
    'share-passphrase', 'share-ciphertext-box',
    'receive-share-bundle', 'receive-share-passphrase', 'mfa-current-password',
    'mfa-current-pin', 'mfa-setup-pin', 'sync-token-input', 'item-password'
];

function lockVault(message = 'Vault locked. Memory cleared.', { keepClipboard = false } = {}) {
    setMobileMenu(false);
    if (activeSession.pendingClipboardText !== null) {
        if (keepClipboard) {
            // The user may be switching apps to paste, so finish the 30s window instead of wiping it now
            deferClipboardScrub(activeSession.pendingClipboardText, Math.max(0, activeSession.clipboardSecondsRemaining) * 1000);
        } else {
            scrubClipboardNow(true);
        }
    }
    clearInterval(activeSession.idleInterval);
    clearInterval(activeSession.clipboardInterval);
    const category = activeSession.category;
    activeSession = createEmptySession();
    activeSession.category = category;

    document.getElementById('vault-grid').innerHTML = '';
    document.getElementById('item-form').reset();
    SENSITIVE_FIELD_IDS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('clipboard-countdown-bar').classList.add('hidden');
    closeAllModals();

    document.getElementById('app-screen').classList.add('hidden');
    document.getElementById('auth-screen').classList.remove('hidden');
    checkExistingVault();
    showToast(message, 'info');
}

/********************************************************************
 * 5. CSPRNG PASSWORD GENERATOR & ENTROPY CALCULATOR
 ********************************************************************/
function generateCSPRNGPassword(length = 20, upper = true, lower = true, num = true, sym = true) {
    const sets = [];
    if (upper) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
    if (lower) sets.push('abcdefghijkmnopqrstuvwxyz');
    if (num) sets.push('23456789');
    if (sym) sets.push('!@#$%^&*()-_=+[]{}<>?');

    if (sets.length === 0) sets.push('abcdefghijkmnopqrstuvwxyz23456789');

    const allChars = sets.join('');
    const passwordArray = [];
    for (let i = 0; i < sets.length && i < length; i++) {
        passwordArray.push(sets[i][secureRandomInt(sets[i].length)]);
    }
    while (passwordArray.length < length) {
        passwordArray.push(allChars[secureRandomInt(allChars.length)]);
    }

    for (let i = passwordArray.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }

    return passwordArray.join('');
}

const STRENGTH_WEAK_BELOW = 60;
const STRENGTH_STRONG_FROM = 80;
const COMMON_PASSWORD_FRAGMENTS = [
    'password', 'qwerty', 'letmein', 'welcome', 'admin', 'iloveyou', 'monkey', 'dragon',
    'football', 'baseball', 'master', 'sunshine', 'princess', 'shadow', 'superman', 'trustno',
    'abc123', 'login', 'starwars', 'hello', 'freedom', 'whatever', 'secret', '111111',
    '123456', '654321', 'qazwsx', 'asdfgh', 'zxcvbn', '000000', 'changeme', 'default'
];

// Character-pool entropy capped by common patterns that attackers try first
function calculatePasswordEntropy(pwd) {
    if (!pwd) return 0;
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
    if (pool === 0) return 0;

    let bits = pwd.length * Math.log2(pool);

    const lower = pwd.toLowerCase();
    const deLeet = lower.replace(/[@4]/g, 'a').replace(/3/g, 'e').replace(/[1!|]/g, 'i')
        .replace(/0/g, 'o').replace(/[$5]/g, 's').replace(/7/g, 't');
    if (COMMON_PASSWORD_FRAGMENTS.some(f => lower.includes(f) || deLeet.includes(f))) {
        bits = Math.min(bits, 20);
    }

    const wordDigitsSymbol = pwd.match(/^([A-Za-z]{3,12})([0-9]{0,4})([^A-Za-z0-9]{0,2})$/);
    if (wordDigitsSymbol) {
        const [, , digits, symbols] = wordDigitsSymbol;
        bits = Math.min(bits, 16 + 1 + digits.length * Math.log2(10) + symbols.length * 5);
    }

    const uniqueChars = new Set(pwd).size;
    bits = Math.min(bits, uniqueChars * Math.log2(pool) * 1.5);

    return Math.round(bits);
}

function updateSetupStrength(pwd) {
    const entropy = calculatePasswordEntropy(pwd);
    const bar = document.getElementById('setup-strength-bar');
    const label = document.getElementById('setup-strength-text');

    if (!pwd) {
        bar.style.width = '0%';
        label.textContent = 'Minimum 8 characters required';
        return;
    }

    const pct = Math.min(100, Math.round((entropy / 110) * 100));
    bar.style.width = `${pct}%`;

    if (entropy < 50) {
        bar.className = 'h-full bg-rose-500 transition-all duration-300';
        label.textContent = `${entropy} bits entropy — Weak master password`;
    } else if (entropy < 80) {
        bar.className = 'h-full bg-amber-400 transition-all duration-300';
        label.textContent = `${entropy} bits entropy — Good protection`;
    } else {
        bar.className = 'h-full bg-emerald-400 transition-all duration-300';
        label.textContent = `${entropy} bits entropy — Military-grade key strength`;
    }
}

function evaluateModalPasswordEntropy(pwd) {
    const entropy = calculatePasswordEntropy(pwd);
    const bar = document.getElementById('modal-entropy-bar');
    const label = document.getElementById('modal-entropy-label');
    const pct = Math.min(100, Math.round((entropy / 120) * 100));
    bar.style.width = `${pct}%`;
    label.textContent = `${entropy} bits entropy`;

    if (entropy < STRENGTH_WEAK_BELOW) {
        bar.className = 'h-full bg-rose-500 transition-all';
    } else if (entropy < STRENGTH_STRONG_FROM) {
        bar.className = 'h-full bg-amber-400 transition-all';
    } else {
        bar.className = 'h-full bg-emerald-400 transition-all';
    }
}

/********************************************************************
 * 6. VAULT ITEM CRUD, SOFT-DELETE RECYCLE BIN & UI RENDERING
 ********************************************************************/
const CAT_BTN_BASE = 'cat-btn flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs transition whitespace-nowrap';
const CAT_BTN_TRASH_EXTRA = ' mt-1 lg:border-t lg:border-slate-800 lg:pt-3';

function setCategoryFilter(cat) {
    activeSession.category = cat;
    document.querySelectorAll('.cat-btn').forEach(btn => {
        const extra = btn.id === 'cat-trash' ? CAT_BTN_TRASH_EXTRA : '';
        if (btn.id === `cat-${cat}`) {
            const active = cat === 'trash'
                ? ' font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : ' font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30';
            btn.className = CAT_BTN_BASE + active + extra;
            btn.setAttribute('aria-pressed', 'true');
        } else {
            btn.className = CAT_BTN_BASE + ' font-medium text-slate-400 hover:text-white hover:bg-slate-800/60' + extra;
            btn.setAttribute('aria-pressed', 'false');
        }
    });
    const list = document.getElementById('vault-scroll');
    if (list) list.scrollTop = 0;
    // Keep the selected chip visible in the horizontally scrolling mobile category bar
    document.getElementById(`cat-${cat}`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    renderVaultItems();
}

function clearSearch() {
    const input = document.getElementById('search-input');
    input.value = '';
    renderVaultItems();
}

function computePasswordHealth(activeItems) {
    const audited = activeItems.filter(i => i.category === 'login' && i.password);
    const freq = {};
    audited.forEach(i => { freq[i.password] = (freq[i.password] || 0) + 1; });
    const weak = audited.filter(i => calculatePasswordEntropy(i.password) < STRENGTH_WEAK_BELOW);
    const reused = audited.filter(i => freq[i.password] > 1);
    const breached = audited.filter(i => i.breachedCount > 0);
    const score = audited.length === 0
        ? 100
        : Math.max(5, 100 - weak.length * 10 - reused.length * 12 - breached.length * 20);
    return { audited, freq, weak, reused, breached, score };
}

const HEALTH_SECTIONS = ['weak', 'reused', 'breached'];

function renderHealthList(key, items, describe) {
    document.getElementById(`health-count-${key}`).textContent = items.length;
    document.getElementById(`health-list-${key}`).innerHTML = items.length
        ? items.map(i => `
            <li class="flex items-center justify-between gap-2 p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                <div class="min-w-0">
                    <p class="text-slate-200 font-medium truncate">${escapeHTML(i.title || '(untitled)')}</p>
                    <p class="text-[11px] text-slate-500 truncate">${escapeHTML(describe(i))}</p>
                </div>
                <button data-action="editItemFromHealth" data-id="${i.id}" class="shrink-0 px-3.5 py-2 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 border border-indigo-500/30 font-semibold">Fix</button>
            </li>`).join('')
        : '<li class="px-1 text-slate-500">None — nice work.</li>';
}

function openHealthModal(section) {
    if (!activeSession.dek) return;
    const h = computePasswordHealth(activeSession.items.filter(i => !i.deletedAt));
    const scoreEl = document.getElementById('health-score-big');
    scoreEl.textContent = `${h.score}%`;
    scoreEl.className = `text-3xl font-bold font-mono ${h.score >= 80 ? 'text-emerald-400' : h.score >= 50 ? 'text-amber-400' : 'text-rose-400'}`;
    const problems = new Set([...h.weak, ...h.reused, ...h.breached]).size;
    document.getElementById('health-score-text').textContent = h.audited.length === 0
        ? 'Add website logins with passwords to see their health.'
        : problems === 0
            ? `All ${h.audited.length} login password(s) look good.`
            : `${problems} of ${h.audited.length} login password(s) need attention. Tap Fix to change them.`;

    renderHealthList('weak', h.weak, i => `Strength ${calculatePasswordEntropy(i.password)} bits (aim for ${STRENGTH_STRONG_FROM}+)`);
    renderHealthList('reused', h.reused, i => `Same password used on ${h.freq[i.password]} logins`);
    renderHealthList('breached', h.breached, i => `Seen ${Number(i.breachedCount).toLocaleString()} times in leaks`);

    showModal('health-modal');
    if (HEALTH_SECTIONS.includes(section)) {
        document.getElementById(`health-section-${section}`).scrollIntoView({ block: 'start' });
    }
}

// Titles are cleared on close so nothing lingers in the DOM after locking
function closeHealthModal() {
    hideModal('health-modal');
    HEALTH_SECTIONS.forEach(key => { document.getElementById(`health-list-${key}`).innerHTML = ''; });
}

function editItemFromHealth(id) {
    closeHealthModal();
    openItemModal(id);
}

function escapeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function renderVaultItems() {
    const allItems = activeSession.items || [];
    const activeItems = allItems.filter(i => !i.deletedAt);
    const trashedItems = allItems.filter(i => !!i.deletedAt);

    const query = (document.getElementById('search-input')?.value || '').trim().toLowerCase();
    const clearBtn = document.getElementById('clear-search-btn');
    if (clearBtn) clearBtn.classList.toggle('hidden', !query);

    // Toggle Trash Banner
    const trashBanner = document.getElementById('trash-banner');
    if (trashBanner) {
        trashBanner.classList.toggle('hidden', activeSession.category !== 'trash' || trashedItems.length === 0);
    }

    // Update Category Counts
    document.getElementById('count-all').textContent = activeItems.length;
    document.getElementById('count-favorites').textContent = activeItems.filter(i => i.favorite).length;
    document.getElementById('count-login').textContent = activeItems.filter(i => i.category === 'login').length;
    document.getElementById('count-card').textContent = activeItems.filter(i => i.category === 'card').length;
    document.getElementById('count-note').textContent = activeItems.filter(i => i.category === 'note').length;
    const passkeyCountEl = document.getElementById('count-passkey');
    if (passkeyCountEl) passkeyCountEl.textContent = activeItems.filter(i => i.category === 'passkey').length;
    document.getElementById('count-trash').textContent = trashedItems.length;

    // Health metrics only apply to website logins; card PINs, passkey IDs and notes are not passwords
    const health = computePasswordHealth(activeItems);
    const pwdFrequency = health.freq;

    const scoreTile = document.getElementById('metric-score');
    scoreTile.textContent = `${health.score}%`;
    scoreTile.className = `text-base font-bold font-mono ${health.score >= 80 ? 'text-emerald-400' : health.score >= 50 ? 'text-amber-400' : 'text-rose-400'}`;
    document.getElementById('metric-weak').textContent = health.weak.length;
    const reusedEl = document.getElementById('metric-reused');
    if (reusedEl) reusedEl.textContent = health.reused.length;
    const breachedEl = document.getElementById('metric-breached');
    if (breachedEl) breachedEl.textContent = health.breached.length;

    // Filter Items based on Category / Trash state
    const sourcePool = activeSession.category === 'trash' ? trashedItems : activeItems;
    const filtered = sourcePool.filter(item => {
        if (activeSession.category === 'favorites' && !item.favorite) return false;
        if (['login', 'card', 'note', 'passkey'].includes(activeSession.category) && item.category !== activeSession.category) return false;

        if (!query) return true;
        return (
            (item.title || '').toLowerCase().includes(query) ||
            (item.username || '').toLowerCase().includes(query) ||
            (item.url || '').toLowerCase().includes(query) ||
            (item.notes || '').toLowerCase().includes(query)
        );
    });

    const grid = document.getElementById('vault-grid');
    const emptyState = document.getElementById('empty-state');

    if (filtered.length === 0) {
        grid.innerHTML = '';
        emptyState.classList.remove('hidden');
        if (activeSession.category === 'trash') {
            document.getElementById('empty-title').textContent = 'Recently Deleted Bin is Empty';
            document.getElementById('empty-desc').textContent = 'Any password entry you delete is moved here first so you never lose a credential by mistake.';
            document.getElementById('empty-actions').classList.add('hidden');
        } else {
            document.getElementById('empty-title').textContent = 'No Encrypted Entries Found';
            document.getElementById('empty-desc').textContent = 'Your vault is decrypted in memory and ready. Add your first login, payment card, or secret note.';
            document.getElementById('empty-actions').classList.remove('hidden');
        }
        return;
    }

    emptyState.classList.add('hidden');

    const categoryMeta = {
        login: { icon: 'fa-globe', color: 'text-sky-400 bg-sky-500/15 border-sky-500/30', label: 'Login' },
        card: { icon: 'fa-credit-card', color: 'text-purple-400 bg-purple-500/15 border-purple-500/30', label: 'Payment Card' },
        note: { icon: 'fa-note-sticky', color: 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30', label: 'Secure Note' },
        passkey: { icon: 'fa-fingerprint', color: 'text-indigo-400 bg-indigo-500/15 border-indigo-500/30', label: 'Passkey' }
    };

    grid.innerHTML = filtered.map((item) => {
        const meta = categoryMeta[item.category] || categoryMeta.login;
        const isRevealed = activeSession.revealedIds.has(item.id);
        const entropy = calculatePasswordEntropy(item.password);
        const isTrashed = !!item.deletedAt;
        const isAudited = item.category === 'login' && !!item.password;
        const isReused = isAudited && pwdFrequency[item.password] > 1;
        const hasSecret = !!item.password;

        const statusBadge = isTrashed
            ? `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">Deleted</span>`
            : !isAudited
                ? ''
            : item.breachedCount > 0
                ? `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30" title="Found ${item.breachedCount} times in public data breaches">Breached (${item.breachedCount})</span>`
                : isReused
                    ? `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">Reused</span>`
                    : entropy >= STRENGTH_STRONG_FROM
                        ? `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">${entropy} bits</span>`
                        : entropy >= STRENGTH_WEAK_BELOW
                            ? `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">${entropy} bits</span>`
                            : `<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/15 text-rose-400 border border-rose-500/30">Weak (${entropy}b)</span>`;

        return `
            <article class="glass-panel rounded-2xl p-5 border border-slate-800/90 hover:border-indigo-500/40 transition flex flex-col justify-between gap-4 ${isTrashed ? 'opacity-75' : ''}">
                <div>
                    <div class="flex items-start justify-between gap-2">
                        <div class="flex items-center gap-3 min-w-0">
                            <div class="w-10 h-10 rounded-xl border flex items-center justify-center shrink-0 ${meta.color}">
                                <i class="fa-solid ${meta.icon}"></i>
                            </div>
                            <div class="min-w-0">
                                <div class="flex items-center gap-1.5">
                                    <h4 class="font-bold text-sm text-white truncate">${escapeHTML(item.title)}</h4>
                                    ${item.favorite && !isTrashed ? '<i class="fa-solid fa-star text-amber-400 text-[11px]"></i>' : ''}
                                </div>
                                <p class="text-xs font-mono text-slate-400 truncate mt-0.5">${escapeHTML(item.username || meta.label)}</p>
                            </div>
                        </div>
                        ${statusBadge}
                    </div>

                    <!-- Secret Password Box -->
                    ${hasSecret ? `
                    <div class="mt-4 p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between gap-2">
                        <div class="font-mono text-xs truncate select-all ${isRevealed ? 'text-indigo-300' : 'text-slate-500 tracking-widest'}">
                            ${isRevealed ? escapeHTML(item.password) : '••••••••••••••••'}
                        </div>
                        <div class="flex items-center gap-1 shrink-0">
                            <button data-action="toggleItemReveal" data-id="${item.id}" title="${isRevealed ? 'Hide Secret' : 'Show Secret'}" aria-label="${isRevealed ? 'Hide Secret' : 'Show Secret'}"
                                class="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition text-xs">
                                <i class="fa-regular ${isRevealed ? 'fa-eye-slash' : 'fa-eye'}"></i>
                            </button>
                            <button data-action="copyItemField" data-id="${item.id}" data-field="password" title="Copy Secret (Auto-Clears in 30s)" aria-label="Copy Secret"
                                class="p-1.5 rounded-lg hover:bg-indigo-500/20 text-indigo-400 transition text-xs">
                                <i class="fa-regular fa-copy"></i>
                            </button>
                        </div>
                    </div>` : ''}

                    ${item.notes ? `<p class="mt-2.5 text-[11px] text-slate-400 line-clamp-2">${escapeHTML(item.notes)}</p>` : ''}
                </div>

                <div class="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span class="text-[11px] text-slate-500">${meta.label}</span>
                    <div class="flex flex-wrap items-center justify-end gap-1.5 ml-auto">
                        ${isTrashed ? `
                            <button data-action="restoreItemFromTrash" data-id="${item.id}" class="px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30 font-semibold text-[11px]">
                                Restore
                            </button>
                            <button data-action="permanentlyDeleteItem" data-id="${item.id}" class="px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 font-semibold text-[11px]">
                                Delete Forever
                            </button>
                        ` : `
                            ${item.username ? `
                                <button data-action="copyItemField" data-id="${item.id}" data-field="username" class="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]" title="Copy Username">
                                    User
                                </button>
                            ` : ''}
                            ${item.url ? `
                                <button data-action="launchAndAutoFill" data-id="${item.id}" class="px-2.5 py-1 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 text-[11px] font-medium" title="Copy password and open website">
                                    Copy & Open ↗
                                </button>
                            ` : ''}
                            <button data-action="openShareItemModal" data-id="${item.id}" class="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white" title="Secure Share" aria-label="Secure Share">
                                <i class="fa-solid fa-share-nodes"></i>
                            </button>
                            <button data-action="openItemModal" data-id="${item.id}" class="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white" title="Edit" aria-label="Edit">
                                <i class="fa-regular fa-pen-to-square"></i>
                            </button>
                            <button data-action="softDeleteVaultItem" data-id="${item.id}" class="p-1.5 rounded-lg hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 transition" title="Move to Trash" aria-label="Move to Trash">
                                <i class="fa-regular fa-trash-can"></i>
                            </button>
                        `}
                    </div>
                </div>
            </article>
        `;
    }).join('');
}

function toggleItemReveal(id) {
    if (activeSession.revealedIds.has(id)) {
        activeSession.revealedIds.delete(id);
    } else {
        activeSession.revealedIds.add(id);
    }
    renderVaultItems();
}

function copyItemField(id, field) {
    const item = activeSession.items.find(i => i.id === id);
    if (!item || !item[field]) return;
    const isSecret = field === 'password';
    copyTextToClipboard(item[field], isSecret ? 'Secret copied to clipboard' : 'Username copied to clipboard', isSecret);
}

// Applies a new items array, persists it, and rolls back if the save fails
async function commitItems(nextItems) {
    const previous = activeSession.items;
    activeSession.items = nextItems;
    const ok = await saveVault();
    if (!ok) activeSession.items = previous;
    renderVaultItems();
    return ok;
}

/********************************************************************
 * 7. ADD / EDIT / SOFT-DELETE / RESTORE HANDLERS
 ********************************************************************/
function updateItemModalForCategory() {
    const isNote = document.getElementById('item-category').value === 'note';
    const pwdInput = document.getElementById('item-password');
    pwdInput.required = !isNote;
    document.getElementById('item-password-label').textContent = isNote
        ? 'Secret (Optional)'
        : 'Secret Password / PIN / Key *';
}

function openItemModal(itemId = null) {
    const titleEl = document.getElementById('modal-title');
    document.getElementById('item-form').reset();

    if (itemId) {
        const existing = activeSession.items.find(i => i.id === itemId);
        if (!existing) return;
        titleEl.innerHTML = `<i class="fa-regular fa-pen-to-square text-emerald-400"></i> Edit Encrypted Item`;
        document.getElementById('item-id').value = existing.id;
        document.getElementById('item-title').value = existing.title || '';
        document.getElementById('item-category').value = existing.category || 'login';
        document.getElementById('item-username').value = existing.username || '';
        document.getElementById('item-url').value = existing.url || '';
        document.getElementById('item-password').value = existing.password || '';
        document.getElementById('item-notes').value = existing.notes || '';
        document.getElementById('item-favorite').checked = !!existing.favorite;
        evaluateModalPasswordEntropy(existing.password || '');
    } else {
        titleEl.innerHTML = `<i class="fa-solid fa-shield-halved text-emerald-400"></i> New Encrypted Item`;
        document.getElementById('item-id').value = '';
        fillRandomPasswordInModal();
    }

    updateItemModalForCategory();
    showModal('item-modal');
}

function closeItemModal() {
    hideModal('item-modal');
    document.getElementById('item-password').value = '';
}

function fillRandomPasswordInModal() {
    const generated = generateCSPRNGPassword(20, true, true, true, true);
    const pwdInput = document.getElementById('item-password');
    pwdInput.value = generated;
    evaluateModalPasswordEntropy(generated);
}

async function saveVaultItem(e) {
    e.preventDefault();
    if (!activeSession.dek) return;

    const id = document.getElementById('item-id').value;
    const existing = id ? activeSession.items.find(i => i.id === id) : null;
    const password = document.getElementById('item-password').value;
    const entry = {
        id: existing ? existing.id : crypto.randomUUID(),
        title: document.getElementById('item-title').value.trim(),
        category: document.getElementById('item-category').value,
        username: document.getElementById('item-username').value.trim(),
        url: document.getElementById('item-url').value.trim(),
        password,
        notes: document.getElementById('item-notes').value.trim(),
        favorite: document.getElementById('item-favorite').checked,
        deletedAt: null,
        updatedAt: new Date().toISOString(),
        breachedCount: existing && existing.password === password ? existing.breachedCount : 0
    };

    const nextItems = existing
        ? activeSession.items.map(i => (i.id === existing.id ? entry : i))
        : [entry, ...activeSession.items];

    if (await commitItems(nextItems)) {
        closeItemModal();
        showToast('Entry encrypted and saved.', 'success');
    }
}

// Soft-Delete: Moves item to Recently Deleted Bin with an instant Undo button
async function softDeleteVaultItem(id) {
    if (!activeSession.dek) return;
    const item = activeSession.items.find(i => i.id === id);
    if (!item) return;

    const deletedAt = new Date().toISOString();
    if (await commitItems(activeSession.items.map(i => (i.id === id ? { ...i, deletedAt } : i)))) {
        showToast(`"${item.title}" moved to Recently Deleted.`, 'info', {
            actionText: 'Undo',
            onAction: () => restoreItemFromTrash(id)
        });
    }
}

async function restoreItemFromTrash(id) {
    if (!activeSession.dek) return;
    const item = activeSession.items.find(i => i.id === id);
    if (!item) return;

    if (await commitItems(activeSession.items.map(i => (i.id === id ? { ...i, deletedAt: null } : i)))) {
        showToast(`"${item.title}" restored to your active vault!`, 'success');
    }
}

async function permanentlyDeleteItem(id) {
    if (!activeSession.dek) return;
    const item = activeSession.items.find(i => i.id === id);
    if (!item || !confirm(`Permanently delete "${item.title}"? This cannot be undone.`)) return;
    if (await commitItems(activeSession.items.filter(i => i.id !== id))) {
        showToast('Entry permanently purged from encrypted storage.', 'info');
    }
}

async function emptyTrashBin() {
    if (!activeSession.dek) return;
    const count = activeSession.items.filter(i => i.deletedAt).length;
    if (!count || !confirm(`Permanently delete ${count} item(s) in Recently Deleted? This cannot be undone.`)) return;
    if (await commitItems(activeSession.items.filter(i => !i.deletedAt))) {
        showToast('Recently Deleted bin emptied.', 'info');
    }
}

/********************************************************************
 * 8. EMERGENCY RECOVERY KIT, GENERATOR & BACKUP EXPORT/IMPORT
 ********************************************************************/
function openRecoveryKitModal() {
    document.getElementById('recovery-kit-key-display').textContent =
        activeSession.recoveryKeyFormatted || 'SV-XXXX-XXXX-XXXX-XXXX-XXXX';
    document.getElementById('recovery-kit-hint-display').textContent =
        activeSession.hint || 'No password hint configured';
    showModal('recovery-kit-modal');
}

function closeRecoveryKitModal() {
    hideModal('recovery-kit-modal');
}

function copyRecoveryKey() {
    if (!activeSession.recoveryKeyFormatted) return;
    copyTextToClipboard(activeSession.recoveryKeyFormatted, 'Emergency Recovery Key copied!', true);
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadRecoveryKitTxt() {
    if (!activeSession.recoveryKeyFormatted) return;
    const dateStr = new Date().toISOString().slice(0, 10);
    const content = [
        '============================================================',
        '        SECUREVAULT — EMERGENCY RECOVERY KIT',
        '============================================================',
        `Generated Date : ${new Date().toUTCString()}`,
        `Encryption     : AES-256-GCM data key, wrapped with PBKDF2-SHA256 (${PBKDF2_ITERATIONS.toLocaleString('en-US')} iter)`,
        '',
        '1. YOUR 20-CHARACTER EMERGENCY RECOVERY KEY:',
        `   ${activeSession.recoveryKeyFormatted}`,
        '',
        '2. YOUR MASTER PASSWORD HINT:',
        `   ${activeSession.hint || '(None set)'}`,
        '',
        'HOW TO USE THIS KIT:',
        '- If you forget your Master Password, click "Forgot Master Password?"',
        '  on the SecureVault unlock screen and enter the Recovery Key above.',
        '- After a recovery, SecureVault issues a NEW recovery key; this one',
        '  stops working. Replace this kit when that happens.',
        '- Keep a copy of your encrypted .vault.json backup file so you can',
        '  restore your vault even if your device or browser is wiped.',
        '- Store this kit offline (printed or on an encrypted drive).',
        '============================================================'
    ].join('\n');

    downloadBlob(new Blob([content], { type: 'text/plain;charset=utf-8' }), `SecureVault-Recovery-Kit-${dateStr}.txt`);
    showToast('Emergency Recovery Kit (.txt) downloaded!', 'success');
}

function updateBackupStatusBanner() {
    const badge = document.getElementById('last-backup-badge');
    if (badge) {
        const latestBackupAt = [activeSession.lastBackupAt, localStorage.getItem(AUTO_BACKUP_LAST_KEY)].filter(Boolean).sort().pop();
        if (latestBackupAt) {
            const d = new Date(latestBackupAt);
            badge.className = 'text-[11px] font-mono px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/25';
            badge.textContent = `Last Snapshot: ${d.toLocaleDateString()}`;
        } else {
            badge.className = 'text-[11px] font-mono px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/25';
            badge.textContent = 'No Offline Snapshot Yet';
        }
    }
    const mfaPill = document.getElementById('mfa-status-pill');
    if (mfaPill) {
        const hasPin = !!(activeSession.slots && activeSession.slots.password.pinRequired);
        const hasBio = !!(activeSession.slots && activeSession.slots.biometric);
        if (hasPin || hasBio) {
            mfaPill.className = 'text-[11px] font-mono px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/25';
            mfaPill.textContent = `Auth: ${[hasPin ? 'Unlock PIN' : '', hasBio ? 'Biometrics' : ''].filter(Boolean).join(' + ')}`;
        } else {
            mfaPill.className = 'text-[11px] font-mono px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 border border-slate-700';
            mfaPill.textContent = 'Biometrics & PIN: Off';
        }
    }
    updateStatusAlertDot();
}

// Vault Status lives in the Security Center, so header dots flag anything that needs attention
function updateStatusAlertDot() {
    const hasBackup = !!(activeSession.lastBackupAt || localStorage.getItem(AUTO_BACKUP_LAST_KEY));
    const backupPaused = autoBackup.mode === 'folder' && autoBackup.paused;
    const needsAttention = !!activeSession.dek && (!hasBackup || backupPaused);
    document.querySelectorAll('.status-alert-dot').forEach(dot => dot.classList.toggle('hidden', !needsAttention));
}

/********************************************************************
 * 8B. K-ANONYMITY BREACH DETECTION, MFA, PASSKEYS, SHARE, SYNC & CSV
 ********************************************************************/
async function sha1HexUpper(str) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-1', buf);
    return Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
}

// k-Anonymity Breach Check: only the first 5 hex chars of each SHA-1 hash leave the device
async function runVaultBreachCheck() {
    if (!activeSession.dek) return;
    const btn = document.getElementById('breach-scan-btn');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...`;

    try {
        const results = new Map();
        let unchecked = 0;
        const targets = activeSession.items.filter(i => !i.deletedAt && i.category === 'login' && i.password);
        for (const item of targets) {
            const fullHash = await sha1HexUpper(item.password);
            const prefix = fullHash.slice(0, 5);
            const suffix = fullHash.slice(5);
            try {
                // Add-Padding hides the real response size from network observers
                const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                    headers: { 'Add-Padding': 'true' },
                    referrerPolicy: 'no-referrer',
                    cache: 'no-store'
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const text = await res.text();
                let count = 0;
                for (const line of text.split(/\r?\n/)) {
                    const [hashSuffix, rawCount] = line.split(':');
                    if (hashSuffix === suffix) {
                        count = parseInt(rawCount, 10) || 0;
                        break;
                    }
                }
                results.set(item.id, count);
            } catch (networkErr) {
                unchecked++;
            }
        }

        const compromised = [...results.values()].filter(c => c > 0).length;
        const saved = await commitItems(activeSession.items.map(i =>
            results.has(i.id) ? { ...i, breachedCount: results.get(i.id) } : i
        ));
        if (!saved) return;
        recordSecurityEvent(`Breach scan completed: ${compromised} compromised, ${unchecked} not checked.`, compromised > 0 ? 'error' : 'success');

        if (results.size === 0 && unchecked > 0) {
            showToast('Breach scan failed — the breach service could not be reached. Nothing was checked.', 'error');
        } else if (compromised > 0) {
            showToast(`Warning: ${compromised} password(s) found in public breaches!${unchecked ? ` ${unchecked} could not be checked.` : ''}`, 'error');
        } else if (unchecked > 0) {
            showToast(`No breached passwords among ${results.size} checked; ${unchecked} could not be checked.`, 'info');
        } else {
            showToast(`None of your ${results.size} login password(s) appear in known breaches.`, 'success');
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-satellite-dish"></i> Breach Scan`;
    }
}

function toSafeHttpUrl(rawUrl) {
    try {
        const parsed = new URL(/^[a-z][a-z0-9+.-]*:/i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
        return ['http:', 'https:'].includes(parsed.protocol) ? parsed.href : null;
    } catch (e) {
        return null;
    }
}

// A web page cannot fill other sites' forms, so this copies the secret and opens the site
function launchAndAutoFill(itemId) {
    const item = activeSession.items.find(i => i.id === itemId);
    if (!item) return;

    const targetUrl = toSafeHttpUrl(item.url);
    if (!targetUrl) {
        showToast('This entry\'s URL is not a valid http(s) address.', 'error');
        return;
    }
    if (item.password) {
        copyTextToClipboard(item.password, `Password for ${item.title} copied — paste it on the site.`, true);
    }
    window.open(targetUrl, '_blank', 'noopener,noreferrer');
}

// End-to-End Encrypted Credential Sharing
async function openShareItemModal(itemId) {
    const item = activeSession.items.find(i => i.id === itemId);
    if (!item) return;

    document.getElementById('share-item-title').textContent = item.title;
    const sharePassphrase = generateCSPRNGPassword(20, true, true, true, false);
    document.getElementById('share-passphrase').value = sharePassphrase;

    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const shareKey = await deriveMasterKey(sharePassphrase, salt.buffer, SHARE_PBKDF2_ITERATIONS);
    const payload = JSON.stringify({
        title: item.title,
        category: item.category,
        username: item.username,
        password: item.password,
        url: item.url,
        notes: item.notes,
        sharedAt: new Date().toISOString()
    });
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, shareKey, textEncoder.encode(payload));

    const shareBundle = {
        cipher: 'AES-256-GCM-SHARE',
        iterations: SHARE_PBKDF2_ITERATIONS,
        salt: bufferToBase64(salt.buffer),
        iv: bufferToBase64(iv.buffer),
        data: bufferToBase64(cipherBuf)
    };

    document.getElementById('share-ciphertext-box').value = btoa(JSON.stringify(shareBundle));
    showModal('share-item-modal');
}

function closeShareModal() {
    hideModal('share-item-modal');
    document.getElementById('share-passphrase').value = '';
    document.getElementById('share-ciphertext-box').value = '';
}

function copySharePassphrase() {
    const val = document.getElementById('share-passphrase').value;
    copyTextToClipboard(val, 'Share passphrase copied!', true);
}

function copyEncryptedSharePackage() {
    const val = document.getElementById('share-ciphertext-box').value;
    copyTextToClipboard(val, 'Encrypted share package copied!', false);
}

async function decryptReceivedShare() {
    if (!activeSession.dek) return;
    const bundleInput = document.getElementById('receive-share-bundle');
    const passInput = document.getElementById('receive-share-passphrase');
    let bundle;
    try {
        bundle = JSON.parse(atob(bundleInput.value.trim()));
        if (bundle.cipher !== 'AES-256-GCM-SHARE' || !bundle.salt || !bundle.iv || !bundle.data) throw new Error('format');
    } catch (e) {
        showToast('That is not a valid SecureVault share bundle.', 'error');
        return;
    }
    try {
        const iterations = Number(bundle.iterations) || SHARE_PBKDF2_ITERATIONS;
        const key = await deriveMasterKey(passInput.value.trim(), base64ToBuffer(bundle.salt), iterations);
        const plain = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(bundle.iv)) },
            key,
            base64ToBuffer(bundle.data)
        );
        const shared = JSON.parse(textDecoder.decode(plain));
        const [imported] = sanitizeItems([{ ...shared, id: crypto.randomUUID(), favorite: false, deletedAt: null }]);
        if (await commitItems([imported, ...activeSession.items])) {
            bundleInput.value = '';
            passInput.value = '';
            recordSecurityEvent('Shared credential imported.', 'success');
            showToast(`Imported shared credential "${imported.title}".`, 'success');
        }
    } catch (e) {
        showToast('Could not decrypt the share — check the passphrase.', 'error');
    }
}

// Security Center Modal (Biometrics, Unlock PIN, Sync, CSV Migration, Sharing, Event Log)
function openSecurityCenterModal() {
    const hasPin = !!(activeSession.slots && activeSession.slots.password.pinRequired);
    const hasBio = !!(activeSession.slots && activeSession.slots.biometric);
    document.getElementById('mfa-setup-pin').value = '';
    document.getElementById('mfa-current-password').value = '';
    document.getElementById('mfa-current-pin').value = '';
    document.getElementById('mfa-current-pin').classList.toggle('hidden', !hasPin);
    const badge = document.getElementById('sec-mfa-badge');
    const bioStatus = document.getElementById('biometric-enrolled-status');
    if (hasPin || hasBio) {
        badge.className = 'px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-[10px]';
        badge.textContent = 'Protected';
    } else {
        badge.className = 'px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]';
        badge.textContent = 'Disabled';
    }
    bioStatus.textContent = `Biometrics: ${hasBio ? 'Enrolled' : 'Not Enrolled'} · PIN: ${hasPin ? 'On' : 'Off'}`;
    renderSecurityAuditLog();
    showModal('security-center-modal');
}

function closeSecurityCenterModal() {
    hideModal('security-center-modal');
    ['mfa-current-password', 'mfa-current-pin', 'mfa-setup-pin', 'receive-share-passphrase'].forEach(id => {
        document.getElementById(id).value = '';
    });
}

// Re-derives the password slot; the current password (and PIN) must unwrap the existing slot first
async function replacePasswordSlot(newPin) {
    const password = document.getElementById('mfa-current-password').value;
    const currentPin = document.getElementById('mfa-current-pin').value.trim();
    if (!password) {
        showToast('Enter your current master password.', 'error');
        return false;
    }
    const previousSlots = activeSession.slots;
    try {
        await openPasswordSlot(previousSlots.password, password, previousSlots.password.pinRequired ? currentPin : '');
    } catch (err) {
        recordSecurityEvent('Failed PIN change (wrong master password or PIN).', 'error');
        showToast('Current master password or PIN is incorrect.', 'error');
        return false;
    }
    activeSession.slots = { ...previousSlots, password: await createPasswordSlot(activeSession.dek, password, newPin) };
    if (!(await saveVault())) {
        activeSession.slots = previousSlots;
        return false;
    }
    return true;
}

async function saveMfaConfiguration() {
    if (!activeSession.dek) return;
    const pin = document.getElementById('mfa-setup-pin').value.trim();
    if (!/^\d{4,6}$/.test(pin)) {
        showToast('The Unlock PIN must be 4 to 6 digits.', 'error');
        return;
    }
    if (!(await replacePasswordSlot(pin))) return;
    updateBackupStatusBanner();
    recordSecurityEvent('Unlock PIN enabled.', 'success');
    openSecurityCenterModal();
    showToast('Unlock PIN enabled. You will need it with your master password.', 'success');
}

async function disableMfaConfiguration() {
    if (!activeSession.dek) return;
    if (!activeSession.slots.password.pinRequired) {
        showToast('No Unlock PIN is set.', 'info');
        return;
    }
    if (!(await replacePasswordSlot(''))) return;
    updateBackupStatusBanner();
    recordSecurityEvent('Unlock PIN removed.', 'info');
    openSecurityCenterModal();
    showToast('Unlock PIN removed.', 'info');
}

async function removeBiometricEnrollment() {
    if (!activeSession.dek || !activeSession.slots.biometric) {
        showToast('Biometric unlock is not enrolled.', 'info');
        return;
    }
    const previousSlots = activeSession.slots;
    activeSession.slots = { ...previousSlots, biometric: null };
    if (!(await saveVault())) {
        activeSession.slots = previousSlots;
        return;
    }
    updateBackupStatusBanner();
    recordSecurityEvent('Biometric unlock removed.', 'info');
    openSecurityCenterModal();
    showToast('Biometric unlock removed. You can also delete the passkey from your device settings.', 'info');
}

/********************************************************************
 * 8D. APPLE FACE ID & ANDROID FINGERPRINT BIOMETRIC ENGINE
 ********************************************************************/
let biometricModalState = { action: 'unlock' };

function isWebAuthnAvailable() {
    return window.isSecureContext && !!window.PublicKeyCredential && !!navigator.credentials;
}

async function openBiometricScannerModal(mode = 'auto', action = 'unlock') {
    biometricModalState.action = action;
    const isEnroll = action === 'enroll';
    const statusEl = document.getElementById('bio-status-box');
    const verifyBtn = document.getElementById('bio-Verify-btn');
    document.getElementById('bio-modal-title').textContent = isEnroll ? 'Enroll Biometric Unlock' : 'Biometric Unlock';

    if (!isWebAuthnAvailable()) {
        statusEl.textContent = 'Biometric unlock requires HTTPS (or localhost) and a browser with WebAuthn support.';
        verifyBtn.disabled = true;
    } else if (isEnroll && !activeSession.dek) {
        statusEl.textContent = 'Unlock your vault with the master password first.';
        verifyBtn.disabled = true;
    } else {
        statusEl.textContent = isEnroll
            ? 'Your device will create a passkey and ask you to verify (Face ID, fingerprint or PIN).'
            : 'Your device will ask you to verify your identity.';
        verifyBtn.disabled = false;
    }
    showModal('biometric-modal');
}

function closeBiometricScannerModal() {
    hideModal('biometric-modal');
}

// Turns the authenticator's PRF output into a wrapping key; nothing secret is stored on disk
async function prfOutputToKek(prfOutput) {
    const material = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: textEncoder.encode('SecureVault-biometric-slot-v1'), info: new Uint8Array(0) },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
    );
}

function prfUnsupportedError() {
    const err = new Error('This browser or authenticator does not support the WebAuthn PRF extension.');
    err.name = 'PrfUnsupportedError';
    return err;
}

async function getPrfOutput(credentialId, prfSalt) {
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: randomBytes(32),
            allowCredentials: [{ type: 'public-key', id: credentialId }],
            userVerification: 'required',
            timeout: 60000,
            extensions: { prf: { eval: { first: prfSalt } } }
        }
    });
    const output = assertion.getClientExtensionResults().prf?.results?.first;
    if (!output) throw prfUnsupportedError();
    return output;
}

async function enrollBiometricSlot() {
    const prfSalt = randomBytes(32);
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: randomBytes(32),
            rp: { name: 'SecureVault' },
            user: { id: randomBytes(16), name: 'securevault-owner', displayName: 'SecureVault Owner' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
            timeout: 60000,
            extensions: { prf: { eval: { first: prfSalt } } }
        }
    });
    const prfResult = credential.getClientExtensionResults().prf;
    if (!prfResult || prfResult.enabled === false) throw prfUnsupportedError();
    // Some browsers only report PRF support at creation; a follow-up assertion yields the output
    const output = prfResult.results?.first || await getPrfOutput(credential.rawId, prfSalt);
    const kek = await prfOutputToKek(output);
    return {
        credentialId: bufferToBase64(credential.rawId),
        prfSalt: bufferToBase64(prfSalt.buffer),
        createdAt: new Date().toISOString(),
        ...(await wrapDataKey(activeSession.dek, kek))
    };
}

function describeBiometricError(err) {
    if (!err) return 'Biometric verification failed.';
    if (err.name === 'NotAllowedError') return 'Verification was cancelled or timed out.';
    if (err.name === 'PrfUnsupportedError') return err.message;
    if (err.name === 'SecurityError') return 'Biometric unlock is not allowed on this origin (HTTPS or localhost required).';
    if (isWrongCredentialError(err)) return 'This passkey does not match the enrolled one.';
    return err.message || 'Biometric verification failed.';
}

async function triggerBiometricVerificationStep() {
    expectExternalUi();
    const statusEl = document.getElementById('bio-status-box');
    const verifyBtn = document.getElementById('bio-Verify-btn');
    verifyBtn.disabled = true;
    verifyBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Waiting for device...`;
    statusEl.textContent = 'Follow the prompt from your device...';

    try {
        if (biometricModalState.action === 'enroll') {
            if (!activeSession.dek) throw new Error('Unlock your vault first to enroll biometrics.');
            const slot = await enrollBiometricSlot();
            const previousSlots = activeSession.slots;
            activeSession.slots = { ...previousSlots, biometric: slot };
            if (!(await saveVault())) {
                activeSession.slots = previousSlots;
                return;
            }
            updateBackupStatusBanner();
            recordSecurityEvent('Biometric unlock enrolled.', 'success');
            closeBiometricScannerModal();
            if (!document.getElementById('security-center-modal').classList.contains('hidden')) {
                openSecurityCenterModal();
            }
            showToast('Biometric unlock enrolled on this device.', 'success');
        } else {
            const { envelope } = readStoredEnvelope();
            const slot = envelope && envelope.version === VAULT_VERSION ? envelope.slots.biometric : null;
            if (!slot) throw new Error('Biometric unlock is not enrolled for this vault.');

            const output = await getPrfOutput(base64ToBuffer(slot.credentialId), new Uint8Array(base64ToBuffer(slot.prfSalt)));
            const kek = await prfOutputToKek(output);
            const dek = await unwrapDataKey(slot, kek);
            const payload = await decryptPayload(dek, envelope);

            activeSession = createEmptySession();
            loadSession(dek, envelope.slots, envelope.hint, payload);
            recordSecurityEvent('Vault unlocked with biometrics.', 'success');
            closeBiometricScannerModal();
            document.getElementById('unlock-form').reset();
            transitionToUnlockedApp();
            showToast('Verified! Vault decrypted.', 'success');
        }
    } catch (err) {
        if (biometricModalState.action !== 'enroll') activeSession = createEmptySession();
        if (err && err.name !== 'NotAllowedError') recordSecurityEvent('Failed biometric verification attempt.', 'error');
        const message = describeBiometricError(err);
        statusEl.textContent = message;
        showToast(message, 'error');
    } finally {
        verifyBtn.disabled = false;
        verifyBtn.innerHTML = `<i class="fa-solid fa-circle-check"></i> Verify Now`;
    }
}

function copyEncryptedSyncToken() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const token = 'SVSYNC1:' + bufferToBase64(textEncoder.encode(raw).buffer);
    copyTextToClipboard(token, 'Encrypted Sync Payload copied!', false);
}

// Single entry point for anything that overwrites the stored vault: confirms, keeps the old copy, then locks
function replaceStoredVault(envelope, sourceLabel) {
    if (!isValidEnvelope(envelope)) {
        showToast(`The ${sourceLabel} is not a valid SecureVault vault.`, 'error');
        return false;
    }
    const existing = localStorage.getItem(STORAGE_KEY);
    const incoming = JSON.stringify(envelope);
    if (existing === incoming) {
        showToast(`The ${sourceLabel} is identical to the vault already on this device.`, 'info');
        return false;
    }
    if (existing) {
        const ok = confirm(
            `Replace the vault on this device with this ${sourceLabel}?\n\n` +
            'The current vault will be kept as a previous-version copy on this device, ' +
            'but entries that are not in the incoming vault will no longer be visible.'
        );
        if (!ok) return false;
    }
    try {
        if (existing) localStorage.setItem(PREVIOUS_VAULT_KEY, existing);
        localStorage.setItem(STORAGE_KEY, incoming);
        scheduleAutoBackup();
    } catch (err) {
        showToast(`Could not store the ${sourceLabel}: ${err.message}`, 'error');
        return false;
    }
    localStorage.removeItem(LEGACY_BIO_TOKEN_KEY);
    recordSecurityEvent(`Vault replaced from ${sourceLabel}.`, 'info');
    if (activeSession.dek) {
        lockVault(`Vault replaced from ${sourceLabel}. Unlock it with its master password.`);
    } else {
        checkExistingVault();
        showToast(`Vault restored from ${sourceLabel}. Unlock with its master password or recovery key.`, 'success');
    }
    return true;
}

function applyEncryptedSyncToken() {
    const input = document.getElementById('sync-token-input').value.trim();
    const match = input.match(/^(SVSYNC1|CVSYNC1):(.+)$/);
    if (!match) {
        showToast('Invalid Sync Payload (must start with SVSYNC1:).', 'error');
        return;
    }
    let parsed;
    try {
        parsed = JSON.parse(textDecoder.decode(base64ToBuffer(match[2])));
    } catch (e) {
        showToast('Failed to parse encrypted sync payload.', 'error');
        return;
    }
    if (replaceStoredVault(parsed, 'sync payload')) {
        document.getElementById('sync-token-input').value = '';
    }
}

function exportVaultCSV() {
    if (!activeSession.dek) return;
    if (!confirm('The CSV export contains ALL your passwords in plain text. Anyone with the file can read them.\n\nExport anyway?')) return;
    const active = activeSession.items.filter(i => !i.deletedAt);
    const rows = [['title', 'url', 'username', 'password', 'notes', 'category']];
    active.forEach(item => {
        rows.push([
            item.title || '',
            item.url || '',
            item.username || '',
            item.password || '',
            item.notes || '',
            item.category || 'login'
        ]);
    });
    const csvContent = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\r\n');
    downloadBlob(new Blob([csvContent], { type: 'text/csv;charset=utf-8' }), `securevault-export-${new Date().toISOString().slice(0,10)}.csv`);
    recordSecurityEvent('Vault exported to unencrypted CSV.', 'info');
    showToast('CSV exported — delete it once you are done with it.', 'success');
}

// RFC 4180 parser: handles quoted commas, escaped quotes and newlines inside fields
function parseCSV(text) {
    const rows = [];
    let row = [];
    let field = '';
    let inQuotes = false;
    const src = text.replace(/^\uFEFF/, '');
    for (let i = 0; i < src.length; i++) {
        const c = src[i];
        if (inQuotes) {
            if (c === '"') {
                if (src[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
            } else {
                field += c;
            }
        } else if (c === '"') {
            inQuotes = true;
        } else if (c === ',') {
            row.push(field);
            field = '';
        } else if (c === '\n' || c === '\r') {
            if (c === '\r' && src[i + 1] === '\n') i++;
            row.push(field);
            rows.push(row);
            row = [];
            field = '';
        } else {
            field += c;
        }
    }
    if (field !== '' || row.length) {
        row.push(field);
        rows.push(row);
    }
    return rows.filter(r => r.some(v => v.trim() !== ''));
}

// Header aliases cover Chrome, Firefox, Bitwarden, 1Password and SecureVault exports
const CSV_COLUMN_ALIASES = {
    title: ['title', 'name'],
    url: ['url', 'login_uri', 'website', 'uri', 'login url'],
    username: ['username', 'login_username', 'user name', 'email', 'login'],
    password: ['password', 'login_password'],
    notes: ['notes', 'note', 'extra', 'comments'],
    category: ['category', 'type']
};

function mapCsvHeader(headerRow) {
    const normalized = headerRow.map(h => h.trim().toLowerCase());
    const map = {};
    for (const [field, aliases] of Object.entries(CSV_COLUMN_ALIASES)) {
        const idx = normalized.findIndex(h => aliases.includes(h));
        if (idx > -1) map[field] = idx;
    }
    return map;
}

function titleFromUrl(url) {
    const safe = toSafeHttpUrl(url);
    return safe ? new URL(safe).hostname.replace(/^www\./, '') : '';
}

async function importMigrationFile(event) {
    const input = event.target;
    const file = input.files?.[0];
    if (!file) return;

    if (!/\.csv$/i.test(file.name)) {
        importVaultFile(event);
        return;
    }
    try {
        if (!activeSession.dek) return;
        const rows = parseCSV(await file.text());
        if (rows.length < 2) {
            showToast('CSV file has no data rows.', 'error');
            return;
        }
        const col = mapCsvHeader(rows[0]);
        if (col.password === undefined) {
            showToast('Unrecognized CSV header — a "password" column is required.', 'error');
            return;
        }
        const pick = (row, field) => (col[field] !== undefined ? (row[col[field]] || '').trim() : '');
        const imported = [];
        for (const row of rows.slice(1)) {
            const url = pick(row, 'url');
            const username = pick(row, 'username');
            const password = col.password !== undefined ? (row[col.password] || '') : '';
            const title = pick(row, 'title') || titleFromUrl(url);
            if (!title && !username && !password) continue;
            const rawCategory = pick(row, 'category').toLowerCase();
            imported.push({
                id: crypto.randomUUID(),
                title: title || 'Imported Credential',
                url,
                username,
                password,
                notes: pick(row, 'notes'),
                category: rawCategory === 'securenote' ? 'note' : rawCategory,
                favorite: false,
                deletedAt: null,
                updatedAt: new Date().toISOString()
            });
        }
        if (imported.length === 0) {
            showToast('No credentials found in the CSV file.', 'error');
            return;
        }
        if (await commitItems([...sanitizeItems(imported), ...activeSession.items])) {
            recordSecurityEvent(`Imported ${imported.length} credentials from CSV.`, 'success');
            showToast(`Imported & encrypted ${imported.length} credentials. Delete the CSV file now.`, 'success');
        }
    } catch (err) {
        showToast(`CSV import failed: ${err.message}`, 'error');
    } finally {
        input.value = '';
    }
}

function renderSecurityAuditLog() {
    const listEl = document.getElementById('security-audit-log-list');
    if (!listEl) return;
    let logs = [];
    try {
        logs = JSON.parse(localStorage.getItem(SECURITY_LOG_KEY) || '[]');
        if (!Array.isArray(logs)) logs = [];
    } catch (e) {}
    if (logs.length === 0) {
        listEl.innerHTML = `<div class="text-slate-500 py-2">No security events recorded yet.</div>`;
        return;
    }
    listEl.innerHTML = logs.map(log => {
        const color = log.severity === 'error' ? 'text-rose-400' : log.severity === 'success' ? 'text-emerald-400' : 'text-sky-300';
        const time = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        return `<div class="flex items-center justify-between py-1 border-b border-slate-800/60">
            <span class="${color} truncate pr-2">${escapeHTML(log.title)}</span>
            <span class="text-slate-500 shrink-0">${time}</span>
        </div>`;
    }).join('');
}

function clearSecurityLogs() {
    localStorage.removeItem(SECURITY_LOG_KEY);
    renderSecurityAuditLog();
    showToast('Security event log cleared.', 'info');
}

/********************************************************************
 * 8C. ENCRYPTED BACKUP EXPORT / IMPORT
 ********************************************************************/
async function exportEncryptedVault() {
    if (activeSession.dek) {
        const previousBackupAt = activeSession.lastBackupAt;
        activeSession.lastBackupAt = new Date().toISOString();
        if (!(await saveVault())) {
            activeSession.lastBackupAt = previousBackupAt;
            return;
        }
        updateBackupStatusBanner();
    }
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
        showToast('There is no vault on this device to back up.', 'error');
        return;
    }
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadBlob(new Blob([raw], { type: 'application/json' }), `securevault-encrypted-${dateStr}.vault.json`);
    showToast('Encrypted .vault.json snapshot downloaded!', 'success');
}

function importVaultFile(event) {
    const input = event.target;
    const file = input.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            replaceStoredVault(JSON.parse(e.target.result), 'backup file');
        } catch (err) {
            showToast('Invalid encrypted backup file.', 'error');
        } finally {
            input.value = '';
        }
    };
    reader.readAsText(file);
}

/********************************************************************
 * 8D. AUTOMATIC ON-DEVICE BACKUP (AFTER EVERY SAVE / DELETE / UPDATE)
 ********************************************************************/
// Only the already-encrypted envelope is ever written; the kit lets the owner decrypt it without this site
const AUTO_BACKUP_MODE_KEY = 'SECUREVAULT_AUTO_BACKUP_MODE_V1';
const AUTO_BACKUP_LAST_KEY = 'SECUREVAULT_AUTO_BACKUP_LAST_V1';
const AUTO_BACKUP_DB = 'securevault-auto-backup';
const AUTO_BACKUP_DEBOUNCE_MS = 1500;
const AUTO_BACKUP_LATEST_FILE = 'SecureVault-AutoBackup-latest.vault.json';
const DECRYPT_README_FILE = 'HOW-TO-DECRYPT-SecureVault-Backup.txt';
const OFFLINE_DECRYPTER_FILE = 'SecureVault-Offline-Decrypter.html';

const autoBackup = { mode: 'off', dirHandle: null, paused: false, timer: null, queue: Promise.resolve() };

function supportsFolderBackup() {
    return typeof window.showDirectoryPicker === 'function';
}

function backupHandleStore(txMode, op) {
    return new Promise((resolve, reject) => {
        const open = indexedDB.open(AUTO_BACKUP_DB, 1);
        open.onupgradeneeded = () => open.result.createObjectStore('handles');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
            const db = open.result;
            const tx = db.transaction('handles', txMode);
            const req = op(tx.objectStore('handles'));
            tx.oncomplete = () => { db.close(); resolve(req.result); };
            tx.onerror = () => { db.close(); reject(tx.error); };
        };
    });
}

async function writeFileToDir(dir, name, data) {
    const fileHandle = await dir.getFileHandle(name, { create: true });
    const writable = await fileHandle.createWritable();
    await writable.write(data);
    await writable.close();
}

async function writeDecryptionKitToDir(dir) {
    await writeFileToDir(dir, DECRYPT_README_FILE, SECUREVAULT_DECRYPT_README);
    await writeFileToDir(dir, OFFLINE_DECRYPTER_FILE, SECUREVAULT_OFFLINE_DECRYPTER_HTML);
}

function downloadDecryptionKit() {
    downloadBlob(new Blob([SECUREVAULT_DECRYPT_README], { type: 'text/plain;charset=utf-8' }), DECRYPT_README_FILE);
    setTimeout(() => downloadBlob(new Blob([SECUREVAULT_OFFLINE_DECRYPTER_HTML], { type: 'text/html;charset=utf-8' }), OFFLINE_DECRYPTER_FILE), 400);
}

async function initAutoBackup() {
    const mode = localStorage.getItem(AUTO_BACKUP_MODE_KEY);
    autoBackup.mode = mode === 'folder' || mode === 'download' ? mode : 'off';
    if (autoBackup.mode === 'folder') {
        try {
            autoBackup.dirHandle = (await backupHandleStore('readonly', s => s.get('dir'))) || null;
        } catch (e) {
            autoBackup.dirHandle = null;
        }
        await refreshAutoBackupPermission();
    }
    renderAutoBackupStatus();
}

// Folder access usually has to be re-granted after a reload, which needs a click
async function refreshAutoBackupPermission() {
    if (autoBackup.mode !== 'folder') return;
    let granted = false;
    try {
        granted = !!autoBackup.dirHandle && (await autoBackup.dirHandle.queryPermission({ mode: 'readwrite' })) === 'granted';
    } catch (e) {}
    autoBackup.paused = !granted;
    renderAutoBackupStatus();
}

function scheduleAutoBackup() {
    if (autoBackup.mode === 'off') return;
    clearTimeout(autoBackup.timer);
    autoBackup.timer = setTimeout(runAutoBackupNow, AUTO_BACKUP_DEBOUNCE_MS);
}

function runAutoBackupNow() {
    clearTimeout(autoBackup.timer);
    autoBackup.queue = autoBackup.queue.then(writeAutoBackup);
    return autoBackup.queue;
}

async function writeAutoBackup() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw || autoBackup.mode === 'off') return;
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    try {
        if (autoBackup.mode === 'folder') {
            const dir = autoBackup.dirHandle;
            if (!dir || (await dir.queryPermission({ mode: 'readwrite' })) !== 'granted') {
                pauseAutoBackup();
                return;
            }
            await writeFileToDir(dir, AUTO_BACKUP_LATEST_FILE, raw);
            await writeFileToDir(dir, `SecureVault-AutoBackup-${day}.vault.json`, raw);
        } else {
            const stamp = now.toISOString().slice(0, 19).replace(/:/g, '-');
            downloadBlob(new Blob([raw], { type: 'application/json' }), `SecureVault-AutoBackup-${stamp}.vault.json`);
        }
        localStorage.setItem(AUTO_BACKUP_LAST_KEY, now.toISOString());
        autoBackup.paused = false;
    } catch (err) {
        pauseAutoBackup(err && err.message);
        return;
    }
    renderAutoBackupStatus();
    updateBackupStatusBanner();
}

function pauseAutoBackup(reason) {
    const wasPaused = autoBackup.paused;
    autoBackup.paused = true;
    renderAutoBackupStatus();
    if (wasPaused) return;
    showToast(`Automatic backup paused${reason ? ` (${reason})` : ''}. Your latest change is NOT in the backup folder yet.`, 'error', {
        actionText: 'Reconnect',
        onAction: () => reconnectAutoBackupFolder()
    });
}

async function chooseAutoBackupFolder() {
    expectExternalUi();
    if (!supportsFolderBackup()) {
        showToast('This browser cannot save into a chosen folder. Use Auto-Download or "Save Backup To…" instead.', 'error');
        return;
    }
    const previousDir = autoBackup.mode === 'folder' ? autoBackup.dirHandle : null;
    let dir;
    try {
        dir = await window.showDirectoryPicker({ id: 'securevault-backup', mode: 'readwrite', startIn: previousDir || 'documents' });
    } catch (err) {
        if (err && err.name !== 'AbortError') showToast(`Could not open that folder: ${err.message}`, 'error');
        return;
    }
    try {
        await writeDecryptionKitToDir(dir);
        await backupHandleStore('readwrite', s => s.put(dir, 'dir'));
    } catch (err) {
        showToast(`Could not use that folder: ${err && err.message ? err.message : 'unknown error'}`, 'error');
        return;
    }
    autoBackup.mode = 'folder';
    autoBackup.dirHandle = dir;
    autoBackup.paused = false;
    localStorage.setItem(AUTO_BACKUP_MODE_KEY, 'folder');
    recordSecurityEvent(previousDir ? 'Automatic backup folder changed.' : 'Automatic encrypted folder backup enabled.', 'success');
    await runAutoBackupNow();
    showToast(previousDir
        ? `Backup folder changed to "${dir.name}". Old backups were left in the previous folder.`
        : `Auto-backup on: every change is saved to the "${dir.name}" folder, with decryption instructions.`, 'success');
}

async function reconnectAutoBackupFolder() {
    const dir = autoBackup.dirHandle;
    if (!dir) {
        await chooseAutoBackupFolder();
        return;
    }
    try {
        if ((await dir.requestPermission({ mode: 'readwrite' })) !== 'granted') {
            showToast('Folder access was not granted; automatic backup stays paused.', 'error');
            return;
        }
        await writeDecryptionKitToDir(dir);
    } catch (err) {
        showToast('The backup folder is no longer available. Choose it again.', 'error');
        await chooseAutoBackupFolder();
        return;
    }
    autoBackup.paused = false;
    await runAutoBackupNow();
    showToast('Backup folder reconnected and up to date.', 'success');
}

function enableAutoBackupDownloads() {
    autoBackup.mode = 'download';
    autoBackup.dirHandle = null;
    autoBackup.paused = false;
    localStorage.setItem(AUTO_BACKUP_MODE_KEY, 'download');
    backupHandleStore('readwrite', s => s.delete('dir')).catch(() => {});
    downloadDecryptionKit();
    recordSecurityEvent('Automatic encrypted backup downloads enabled.', 'success');
    renderAutoBackupStatus();
    scheduleAutoBackup();
    showToast('Auto-download on: an encrypted backup is downloaded after every change. Allow multiple downloads if asked.', 'success');
}

function buildBackupShareFiles() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const day = new Date().toISOString().slice(0, 10);
    return [
        new File([raw], `SecureVault-Backup-${day}.vault.json`, { type: 'application/json' }),
        new File([SECUREVAULT_DECRYPT_README], DECRYPT_README_FILE, { type: 'text/plain' }),
        new File([SECUREVAULT_OFFLINE_DECRYPTER_HTML], OFFLINE_DECRYPTER_FILE, { type: 'text/html' })
    ];
}

function supportsBackupShare() {
    try {
        return !!navigator.canShare && navigator.canShare({ files: [new File(['{}'], 'test.vault.json', { type: 'application/json' })] });
    } catch (e) {
        return false;
    }
}

// Opens the OS share/save sheet (e.g. iOS "Save to Files") so the user picks any folder or cloud drive
async function shareBackupToLocation() {
    expectExternalUi();
    const files = buildBackupShareFiles();
    if (!files) {
        showToast('There is no vault on this device to back up.', 'error');
        return;
    }
    if (!supportsBackupShare() || !navigator.canShare({ files })) {
        downloadBlob(files[0], files[0].name);
        showToast('This browser cannot open the save sheet, so the backup was downloaded instead.', 'info');
        return;
    }
    try {
        await navigator.share({ files, title: 'SecureVault encrypted backup' });
        localStorage.setItem(AUTO_BACKUP_LAST_KEY, new Date().toISOString());
        renderAutoBackupStatus();
        updateBackupStatusBanner();
        showToast('Encrypted backup and decryption kit handed to your chosen location.', 'success');
    } catch (err) {
        if (err && err.name !== 'AbortError') showToast(`Could not save the backup: ${err.message}`, 'error');
    }
}

function getDownloadLocationHelp() {
    const ua = navigator.userAgent || '';
    const isIOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    if (isIOS) {
        return 'iPhone / iPad: open Settings \u2192 Apps \u2192 Safari \u2192 Downloads and choose "On My iPhone" or an iCloud Drive folder. Safari may ask you to confirm each download. To pick any folder for a single backup, tap "Save Backup To\u2026" and choose "Save to Files".';
    }
    if (/Android/i.test(ua)) {
        return 'Android (Chrome): tap \u22ee \u2192 Settings \u2192 Downloads \u2192 Download location to pick phone storage or SD card, or turn on "Ask where to save files" to choose a folder for every backup.';
    }
    return 'Change where downloads go in your browser\'s settings (Chrome / Edge: Settings \u2192 Downloads \u2192 Location \u2192 Change; Firefox: Settings \u2192 Files and Applications \u2192 Downloads).';
}

function disableAutoBackup(silent = false) {
    clearTimeout(autoBackup.timer);
    const wasOn = autoBackup.mode !== 'off';
    autoBackup.mode = 'off';
    autoBackup.dirHandle = null;
    autoBackup.paused = false;
    localStorage.removeItem(AUTO_BACKUP_MODE_KEY);
    backupHandleStore('readwrite', s => s.delete('dir')).catch(() => {});
    renderAutoBackupStatus();
    if (silent || !wasOn) return;
    recordSecurityEvent('Automatic backup disabled.', 'info');
    showToast('Automatic backup turned off. Existing backup files were left untouched.', 'info');
}

function handleAutoBackupBadgeClick() {
    if (autoBackup.mode === 'folder' && autoBackup.paused) {
        reconnectAutoBackupFolder();
    } else {
        openSecurityCenterModal();
    }
}

function renderAutoBackupStatus() {
    const lastAt = localStorage.getItem(AUTO_BACKUP_LAST_KEY);
    const lastText = lastAt ? new Date(lastAt).toLocaleString() : 'never';
    let label;
    let tone;
    if (autoBackup.mode === 'off') {
        label = 'Auto-Backup: Off';
        tone = 'bg-slate-800 text-slate-400 border-slate-700';
    } else if (autoBackup.paused) {
        label = 'Auto-Backup Paused — Tap to Reconnect';
        tone = 'bg-amber-500/15 text-amber-300 border-amber-500/25';
    } else {
        const target = autoBackup.mode === 'folder' ? (autoBackup.dirHandle ? autoBackup.dirHandle.name : 'folder') : 'Downloads';
        label = `Auto-Backup: ${target}`;
        tone = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25';
    }

    const badge = document.getElementById('auto-backup-badge');
    if (badge) {
        badge.className = `text-[11px] font-mono px-2.5 py-0.5 rounded-lg border ${tone}`;
        badge.textContent = label;
        badge.title = `Last automatic backup: ${lastText}`;
    }
    const status = document.getElementById('auto-backup-status');
    if (status) {
        status.className = `px-2 py-0.5 rounded font-mono text-[10px] border ${tone}`;
        status.textContent = autoBackup.mode === 'off' ? 'Off' : autoBackup.paused ? 'Paused' : 'On';
    }
    const last = document.getElementById('auto-backup-last');
    if (last) last.textContent = `Last automatic backup: ${lastText}`;
    document.getElementById('auto-backup-reconnect-btn')?.classList.toggle('hidden', !(autoBackup.mode === 'folder' && autoBackup.paused));
    document.getElementById('auto-backup-off-btn')?.classList.toggle('hidden', autoBackup.mode === 'off');

    const canPickFolder = supportsFolderBackup();
    const location = document.getElementById('auto-backup-location');
    if (location) {
        if (autoBackup.mode === 'folder') {
            const name = autoBackup.dirHandle ? autoBackup.dirHandle.name : 'unknown';
            location.textContent = `Folder "${name}"${autoBackup.paused ? ' (paused \u2014 access needs to be re-allowed)' : ''}`;
        } else if (autoBackup.mode === 'download') {
            location.textContent = 'Your browser\'s Downloads folder (a new file after each change)';
        } else {
            location.textContent = 'Not saving automatically';
        }
    }
    document.getElementById('auto-backup-folder-btn')?.classList.toggle('hidden', !canPickFolder);
    const folderLabel = document.getElementById('auto-backup-folder-label');
    if (folderLabel) folderLabel.textContent = autoBackup.mode === 'folder' ? 'Change Folder' : 'Choose Backup Folder';
    const downloadLabel = document.getElementById('auto-backup-download-label');
    if (downloadLabel) downloadLabel.textContent = canPickFolder ? 'Use Downloads Instead' : 'Turn On Auto-Download';
    document.getElementById('auto-backup-download-btn')?.classList.toggle('hidden', autoBackup.mode === 'download');
    document.getElementById('auto-backup-share-btn')?.classList.toggle('hidden', !supportsBackupShare());
    const help = document.getElementById('auto-backup-download-help');
    if (help) {
        help.classList.toggle('hidden', canPickFolder && autoBackup.mode !== 'download');
        document.getElementById('auto-backup-download-help-text').textContent = getDownloadLocationHelp();
    }
    updateStatusAlertDot();
}

function openGeneratorModal() {
    generateModalPassword();
    showModal('generator-modal');
}

function closeGeneratorModal() {
    hideModal('generator-modal');
}

function generateModalPassword() {
    const len = parseInt(document.getElementById('gen-length').value, 10);
    document.getElementById('gen-length-val').textContent = len;
    const upper = document.getElementById('gen-upper').checked;
    const lower = document.getElementById('gen-lower').checked;
    const num = document.getElementById('gen-num').checked;
    const sym = document.getElementById('gen-sym').checked;

    const pwd = generateCSPRNGPassword(len, upper, lower, num, sym);
    document.getElementById('gen-output').textContent = pwd;

    const entropy = calculatePasswordEntropy(pwd);
    document.getElementById('gen-entropy-badge').textContent = `${entropy} bits (${entropy >= STRENGTH_STRONG_FROM ? 'Crack-Resistant' : 'Moderate'})`;
}

function copyGeneratedPassword() {
    const pwd = document.getElementById('gen-output').textContent;
    copyTextToClipboard(pwd, 'Generated password copied!', true);
}

function useGeneratedPasswordInNewItem() {
    const pwd = document.getElementById('gen-output').textContent;
    closeGeneratorModal();
    openItemModal();
    document.getElementById('item-password').value = pwd;
    evaluateModalPasswordEntropy(pwd);
}

function openCryptoInspectorModal() {
    const { envelope: env } = readStoredEnvelope();
    if (!env) return;
    if (env.version === VAULT_VERSION) {
        const slotNames = ['password', 'recovery', 'biometric'].filter(n => env.slots[n]);
        document.getElementById('inspect-suite').textContent =
            `${env.cipher} | Random data key wrapped by: ${slotNames.join(', ')} | KDF: ${env.kdf} (${env.slots.password.iterations} iter)`;
        document.getElementById('inspect-salt').textContent = env.slots.password.salt;
    } else {
        document.getElementById('inspect-suite').textContent = `${env.cipher} | KDF: ${env.kdf} | Legacy v${env.version || 1} format`;
        document.getElementById('inspect-salt').textContent = env.salt;
    }
    document.getElementById('inspect-iv').textContent = env.iv;
    document.getElementById('inspect-ciphertext').textContent = env.ciphertext;
    showModal('crypto-modal');
}

function closeCryptoInspectorModal() {
    hideModal('crypto-modal');
}

function openResetVaultModal() {
    document.getElementById('wipe-confirm-input').value = '';
    showModal('reset-modal');
}

function closeResetVaultModal() {
    hideModal('reset-modal');
}

function confirmWipeVault() {
    const val = document.getElementById('wipe-confirm-input').value.trim().toUpperCase();
    if (val !== 'DELETE') {
        showToast('Please type DELETE to confirm wiping the vault.', 'error');
        return;
    }
    [STORAGE_KEY, PREVIOUS_VAULT_KEY, LEGACY_BIO_TOKEN_KEY, SECURITY_LOG_KEY, AUTO_BACKUP_LAST_KEY].forEach(k => localStorage.removeItem(k));
    // Stop auto-backup so a new empty vault can never overwrite the old vault's backup files
    disableAutoBackup(true);
    closeResetVaultModal();
    checkExistingVault();
    showToast('Vault, previous-version copy and event log wiped from this device.', 'info');
}

function togglePasswordField(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) icon.className = 'fa-regular fa-eye-slash';
    } else {
        input.type = 'password';
        if (icon) icon.className = 'fa-regular fa-eye';
    }
}

async function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        if (!document.execCommand('copy')) throw new Error('Copy command was rejected');
    } finally {
        document.body.removeChild(textarea);
    }
}

async function copyTextToClipboard(text, message = 'Copied to clipboard', isSecret = false) {
    try {
        await writeClipboard(text);
        showToast(message, 'success');
        if (isSecret) {
            activeSession.pendingClipboardText = text;
            startClipboardSanitizerCountdown();
        }
    } catch (err) {
        showToast('Clipboard copy failed', 'error');
    }
}

// Automatic clipboard clearing 30 seconds after a secret is copied
function startClipboardSanitizerCountdown() {
    cancelDeferredClipboardScrub();
    clearInterval(activeSession.clipboardInterval);
    activeSession.clipboardSecondsRemaining = 30;
    const bar = document.getElementById('clipboard-countdown-bar');
    const secEl = document.getElementById('clipboard-timer-sec');
    if (bar) bar.classList.remove('hidden');
    if (secEl) secEl.textContent = '30s';

    activeSession.clipboardInterval = setInterval(() => {
        activeSession.clipboardSecondsRemaining--;
        if (secEl) secEl.textContent = `${activeSession.clipboardSecondsRemaining}s`;
        if (activeSession.clipboardSecondsRemaining <= 0) {
            scrubClipboardNow();
        }
    }, 1000);
}

// Only clears the clipboard if it still holds the secret we put there (when the browser lets us check)
async function clearClipboardIfUnchanged(expected) {
    if (navigator.clipboard && navigator.clipboard.readText && navigator.permissions) {
        const perm = await navigator.permissions.query({ name: 'clipboard-read' }).catch(() => null);
        if (perm && perm.state === 'granted') {
            const current = await navigator.clipboard.readText();
            if (current !== expected) return false;
        }
    }
    await writeClipboard(' ');
    return true;
}

async function scrubClipboardNow(silent = false) {
    const expected = activeSession.pendingClipboardText;
    activeSession.pendingClipboardText = null;
    clearInterval(activeSession.clipboardInterval);
    const bar = document.getElementById('clipboard-countdown-bar');
    if (bar) bar.classList.add('hidden');
    if (expected === null) return;

    try {
        if ((await clearClipboardIfUnchanged(expected)) && !silent) showToast('Clipboard cleared for security.', 'info');
    } catch (e) {
        if (!silent) showToast('Could not clear the clipboard — this window must be focused. Clear it manually.', 'error');
    }
}

// A secret copied before a background lock is cleared once its 30s window ends and the app is visible again
let deferredClipboardScrub = null;

function deferClipboardScrub(text, delayMs) {
    cancelDeferredClipboardScrub();
    deferredClipboardScrub = { text, at: Date.now() + delayMs, timer: setTimeout(flushDeferredClipboardScrub, delayMs) };
}

function cancelDeferredClipboardScrub() {
    if (deferredClipboardScrub) clearTimeout(deferredClipboardScrub.timer);
    deferredClipboardScrub = null;
}

function flushDeferredClipboardScrub() {
    if (!deferredClipboardScrub || document.hidden || Date.now() < deferredClipboardScrub.at) return;
    const { text } = deferredClipboardScrub;
    deferredClipboardScrub = null;
    clearClipboardIfUnchanged(text).catch(() => {});
}

function showToast(message, type = 'info', options = {}) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    const styles = {
        success: 'border-emerald-500/40 bg-slate-900/95 text-emerald-300',
        error: 'border-rose-500/40 bg-slate-900/95 text-rose-300',
        info: 'border-sky-500/40 bg-slate-900/95 text-sky-300'
    };
    const icons = {
        success: 'fa-circle-check text-emerald-400',
        error: 'fa-triangle-exclamation text-rose-400',
        info: 'fa-shield-halved text-sky-400'
    };

    toast.className = `pointer-events-auto flex items-center justify-between gap-3 px-4 py-3 rounded-2xl border shadow-xl backdrop-blur-md text-xs sm:text-sm font-medium transition-all duration-300 ${styles[type] || styles.info}`;
    
    const leftDiv = document.createElement('div');
    leftDiv.className = 'flex items-center gap-2.5';
    leftDiv.innerHTML = `<i class="fa-solid ${icons[type] || icons.info} text-base"></i><span>${escapeHTML(message)}</span>`;
    toast.appendChild(leftDiv);

    if (options.actionText && typeof options.onAction === 'function') {
        const actionBtn = document.createElement('button');
        actionBtn.className = 'px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-semibold shrink-0 transition';
        actionBtn.textContent = options.actionText;
        actionBtn.onclick = () => {
            options.onAction();
            toast.remove();
        };
        toast.appendChild(actionBtn);
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-8px)';
        setTimeout(() => toast.remove(), 300);
    }, 4200);
}

/********************************************************************
 * 9. MODAL MANAGER (FOCUS TRAP, ESCAPE, BACKDROP CLICK)
 ********************************************************************/
const MODAL_CLOSERS = {
    'recovery-kit-modal': () => closeRecoveryKitModal(),
    'item-modal': () => closeItemModal(),
    'security-center-modal': () => closeSecurityCenterModal(),
    'generator-modal': () => closeGeneratorModal(),
    'health-modal': () => closeHealthModal(),
    'crypto-modal': () => closeCryptoInspectorModal(),
    'share-item-modal': () => closeShareModal(),
    'biometric-modal': () => closeBiometricScannerModal(),
    'reset-modal': () => closeResetVaultModal()
};
const modalStack = [];
const modalReturnFocus = new Map();
const FOCUSABLE_SELECTOR = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function getFocusableElements(container) {
    return [...container.querySelectorAll(FOCUSABLE_SELECTOR)].filter(el => el.offsetParent !== null);
}

function showModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const alreadyOpen = !el.classList.contains('hidden');
    el.classList.remove('hidden');
    if (alreadyOpen) return;
    modalReturnFocus.set(id, document.activeElement);
    modalStack.push(id);
    setTimeout(() => {
        const preferred = el.querySelector('input:not([type="hidden"]):not([readonly]):not(.hidden), select, textarea:not([readonly])');
        (preferred && preferred.offsetParent !== null ? preferred : getFocusableElements(el)[0])?.focus();
    }, 30);
}

function hideModal(id) {
    const el = document.getElementById(id);
    if (!el || el.classList.contains('hidden')) return;
    el.classList.add('hidden');
    const idx = modalStack.lastIndexOf(id);
    if (idx > -1) modalStack.splice(idx, 1);
    const returnTo = modalReturnFocus.get(id);
    modalReturnFocus.delete(id);
    if (returnTo && typeof returnTo.focus === 'function' && document.contains(returnTo)) returnTo.focus();
}

function closeAllModals() {
    Object.keys(MODAL_CLOSERS).forEach(id => MODAL_CLOSERS[id]());
    modalStack.length = 0;
    modalReturnFocus.clear();
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        if (isMobileMenuOpen()) {
            setMobileMenu(false);
            document.getElementById('mobile-menu-btn').focus();
            return;
        }
        if (modalStack.length) MODAL_CLOSERS[modalStack[modalStack.length - 1]]();
        return;
    }
    if (e.key !== 'Tab' || !modalStack.length) return;
    const top = document.getElementById(modalStack[modalStack.length - 1]);
    const focusables = getFocusableElements(top);
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (!top.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
    } else if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
    }
});

document.addEventListener('mousedown', (e) => {
    if (modalStack.length && e.target.id === modalStack[modalStack.length - 1]) {
        MODAL_CLOSERS[e.target.id]();
    }
});

/********************************************************************
 * 10. DELEGATED EVENT HANDLING (NO INLINE HANDLERS, CSP script-src 'self')
 ********************************************************************/
function isMobileMenuOpen() {
    const menu = document.getElementById('mobile-menu');
    return !!menu && !menu.classList.contains('hidden');
}

function setMobileMenu(open) {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('mobile-menu-btn');
    if (!menu || !btn) return;
    menu.classList.toggle('hidden', !open);
    btn.setAttribute('aria-expanded', String(open));
    btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    btn.querySelector('i').className = `fa-solid ${open ? 'fa-xmark' : 'fa-bars'} text-lg`;
}

// Markup can only trigger actions listed here; data-* values are never evaluated as code
const CLICK_ACTIONS = {
    toggleMobileMenu: () => setMobileMenu(!isMobileMenuOpen()),
    togglePasswordField: (el) => togglePasswordField(el.dataset.arg, el),
    toggleHintDisplay: () => toggleHintDisplay(),
    openBiometricScannerModal: (el) => openBiometricScannerModal(el.dataset.arg, el.dataset.arg2),
    switchToRecoveryForm: () => switchToRecoveryForm(),
    openResetVaultModal: () => openResetVaultModal(),
    checkExistingVault: () => checkExistingVault(),
    openSecurityCenterModal: () => openSecurityCenterModal(),
    openRecoveryKitModal: () => openRecoveryKitModal(),
    openGeneratorModal: () => openGeneratorModal(),
    lockVault: () => lockVault(),
    openItemModal: (el) => openItemModal(el.dataset.id || null),
    setCategoryFilter: (el) => setCategoryFilter(el.dataset.arg),
    openCryptoInspectorModal: () => openCryptoInspectorModal(),
    exportEncryptedVault: () => exportEncryptedVault(),
    chooseAutoBackupFolder: () => chooseAutoBackupFolder(),
    reconnectAutoBackupFolder: () => reconnectAutoBackupFolder(),
    enableAutoBackupDownloads: () => enableAutoBackupDownloads(),
    disableAutoBackup: () => disableAutoBackup(),
    downloadDecryptionKit: () => downloadDecryptionKit(),
    shareBackupToLocation: () => shareBackupToLocation(),
    handleAutoBackupBadgeClick: () => handleAutoBackupBadgeClick(),
    scrubClipboardNow: () => scrubClipboardNow(),
    runVaultBreachCheck: () => runVaultBreachCheck(),
    clearSearch: () => clearSearch(),
    emptyTrashBin: () => emptyTrashBin(),
    closeRecoveryKitModal: () => closeRecoveryKitModal(),
    copyRecoveryKey: () => copyRecoveryKey(),
    downloadRecoveryKitTxt: () => downloadRecoveryKitTxt(),
    closeItemModal: () => closeItemModal(),
    fillRandomPasswordInModal: () => fillRandomPasswordInModal(),
    closeSecurityCenterModal: () => closeSecurityCenterModal(),
    saveMfaConfiguration: () => saveMfaConfiguration(),
    removeBiometricEnrollment: () => removeBiometricEnrollment(),
    disableMfaConfiguration: () => disableMfaConfiguration(),
    copyEncryptedSyncToken: () => copyEncryptedSyncToken(),
    applyEncryptedSyncToken: () => applyEncryptedSyncToken(),
    exportVaultCSV: () => exportVaultCSV(),
    decryptReceivedShare: () => decryptReceivedShare(),
    clearSecurityLogs: () => clearSecurityLogs(),
    closeGeneratorModal: () => closeGeneratorModal(),
    openHealthModal: (el) => openHealthModal(el.dataset.arg),
    closeHealthModal: () => closeHealthModal(),
    editItemFromHealth: (el) => editItemFromHealth(el.dataset.id),
    copyGeneratedPassword: () => copyGeneratedPassword(),
    useGeneratedPasswordInNewItem: () => useGeneratedPasswordInNewItem(),
    closeCryptoInspectorModal: () => closeCryptoInspectorModal(),
    closeShareModal: () => closeShareModal(),
    copySharePassphrase: () => copySharePassphrase(),
    copyEncryptedSharePackage: () => copyEncryptedSharePackage(),
    triggerBiometricVerificationStep: () => triggerBiometricVerificationStep(),
    closeBiometricScannerModal: () => closeBiometricScannerModal(),
    closeResetVaultModal: () => closeResetVaultModal(),
    confirmWipeVault: () => confirmWipeVault(),
    toggleItemReveal: (el) => toggleItemReveal(el.dataset.id),
    copyItemField: (el) => copyItemField(el.dataset.id, el.dataset.field),
    restoreItemFromTrash: (el) => restoreItemFromTrash(el.dataset.id),
    permanentlyDeleteItem: (el) => permanentlyDeleteItem(el.dataset.id),
    launchAndAutoFill: (el) => launchAndAutoFill(el.dataset.id),
    openShareItemModal: (el) => openShareItemModal(el.dataset.id),
    softDeleteVaultItem: (el) => softDeleteVaultItem(el.dataset.id)
};

const SUBMIT_ACTIONS = {
    handleSetupVault: (e) => handleSetupVault(e),
    handleUnlockVault: (e) => handleUnlockVault(e),
    handleRecoveryReset: (e) => handleRecoveryReset(e),
    saveVaultItem: (e) => saveVaultItem(e)
};

const CHANGE_ACTIONS = {
    importVaultFile: (el, e) => importVaultFile(e),
    importMigrationFile: (el, e) => importMigrationFile(e),
    updateItemModalForCategory: () => updateItemModalForCategory(),
    generateModalPassword: () => generateModalPassword()
};

const INPUT_ACTIONS = {
    updateSetupStrength: (el) => updateSetupStrength(el.value),
    renderVaultItems: () => renderVaultItems(),
    evaluateModalPasswordEntropy: (el) => evaluateModalPasswordEntropy(el.value),
    generateModalPassword: () => generateModalPassword()
};

function dispatchAction(map, name, ...args) {
    if (name && Object.prototype.hasOwnProperty.call(map, name)) map[name](...args);
}

document.addEventListener('click', (e) => {
    // Any tap outside the menu button (including on a menu item) closes the mobile menu
    if (isMobileMenuOpen() && !e.target.closest('#mobile-menu-btn')) setMobileMenu(false);
    const fileLabel = e.target.closest('label');
    if (e.target.matches('input[type="file"]') || (fileLabel && fileLabel.querySelector('input[type="file"]'))) expectExternalUi();
    const el = e.target.closest('[data-action]');
    if (el) dispatchAction(CLICK_ACTIONS, el.dataset.action, el, e);
});
document.addEventListener('submit', (e) => {
    if (e.target.dataset.submit) {
        e.preventDefault();
        dispatchAction(SUBMIT_ACTIONS, e.target.dataset.submit, e);
    }
});
document.addEventListener('change', (e) => dispatchAction(CHANGE_ACTIONS, e.target.dataset?.change, e.target, e));
document.addEventListener('input', (e) => dispatchAction(INPUT_ACTIONS, e.target.dataset?.input, e.target, e));

// Initialize on Window Load
window.addEventListener('load', () => {
    initializePWAAndStorageProtection();
    checkExistingVault();
    initAutoBackup();
});
