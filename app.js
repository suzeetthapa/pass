// Vault (Encrypted) — Firebase backend, HTML/CSS/JS only
// - Firebase Auth (email/password) identifies user
// - Firestore stores ONLY an encrypted envelope {kdf params + ciphertext}
// - Master password never leaves the browser

import { initializeApp } from "https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js";
import {
  getFirestore,
  doc,
  getDoc,
  setDoc,
  deleteDoc
} from "https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js";

/**
 * 1) Paste your config from Firebase Console:
 *    Project settings → Your apps → Web app → "Firebase SDK snippet" (config)
 */
const firebaseConfig = {
  apiKey: "AIzaSyAP3j9-R32nnpPq0hXVWrW7XO8Fn3Ic94E",
  authDomain: "passwordmanager-2c5d0.firebaseapp.com",
projectId: "passwordmanager-2c5d0",

     appId: "1:300096879544:web:33d1807a1a7121df80ed4d",
};

// ---------- Firebase init
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// ---------- UI refs
const authView = document.getElementById("authView");
const vaultView = document.getElementById("vaultView");
const authMsg = document.getElementById("authMsg");
const masterPwEl = document.getElementById("masterPw");

const emailEl = document.getElementById("email");
const accountPwEl = document.getElementById("accountPw");
const signUpBtn = document.getElementById("signUpBtn");
const signInBtn = document.getElementById("signInBtn");
const signOutBtn = document.getElementById("signOutBtn");
const accountStatus = document.getElementById("accountStatus");

const unlockBtn = document.getElementById("unlockBtn");
const createBtn = document.getElementById("createBtn");
const lockBtn = document.getElementById("lockBtn");
const wipeLocalBtn = document.getElementById("wipeLocalBtn");
const wipeCloudBtn = document.getElementById("wipeCloudBtn");

const entryForm = document.getElementById("entryForm");
const entryIdEl = document.getElementById("entryId");
const siteEl = document.getElementById("site");
const usernameEl = document.getElementById("username");
const passwordEl = document.getElementById("password");
const notesEl = document.getElementById("notes");
const genBtn = document.getElementById("genBtn");
const clearBtn = document.getElementById("clearBtn");
const saveMsg = document.getElementById("saveMsg");

const entriesEl = document.getElementById("entries");
const listMsg = document.getElementById("listMsg");
const searchEl = document.getElementById("search");

const exportBtn = document.getElementById("exportBtn");
const importFileEl = document.getElementById("importFile");

// ---------- runtime state (in memory)
let aesKey = null;       // CryptoKey
let vault = [];          // decrypted array of entries
let currentUser = null;  // Firebase user

// ============ helpers
function setMsg(el, text, isError = false) {
  el.textContent = text || "";
  el.style.color = isError ? "#ff8a95" : "#cbd3e6";
}

function showAuth() {
  authView.classList.remove("hidden");
  vaultView.classList.add("hidden");
  lockBtn.classList.add("hidden");
  wipeCloudBtn.classList.add("hidden");
}

function showVault() {
  authView.classList.add("hidden");
  vaultView.classList.remove("hidden");
  lockBtn.classList.remove("hidden");
  wipeCloudBtn.classList.remove("hidden");
  renderEntries();
}

function lockNow(message = "Locked.") {
  aesKey = null;
  vault = [];
  clearForm();
  entriesEl.innerHTML = "";
  setMsg(listMsg, "");
  showAuth();
  setMsg(authMsg, message);
}

function clearForm() {
  entryIdEl.value = "";
  siteEl.value = "";
  usernameEl.value = "";
  passwordEl.value = "";
  notesEl.value = "";
  setMsg(saveMsg, "");
}

function escapeHtml(str) {
  return (str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[c]));
}

function bytesToB64(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function generatePassword(len = 22) {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (let i = 0; i < len; i++) out += charset[bytes[i] % charset.length];
  return out;
}

// ============ crypto (PBKDF2 -> AES-GCM)
async function deriveKeyPBKDF2(masterPassword, saltBytes, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return { iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ctBuf)) };
}

async function decryptJSON(key, ivB64, ctB64) {
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(ptBuf));
}

// ============ Firestore storage
function vaultRef(uid) {
  return doc(db, "vaults", uid);
}

async function fetchEnvelope(uid) {
  const snap = await getDoc(vaultRef(uid));
  return snap.exists() ? snap.data() : null;
}

async function writeEnvelope(uid, envelope) {
  await setDoc(vaultRef(uid), envelope, { merge: false });
}

async function removeEnvelope(uid) {
  await deleteDoc(vaultRef(uid));
}

// Envelope format stored in Firestore:
// {
//   v: 1,
//   kdf: { name:"PBKDF2", hash:"SHA-256", iter: number, salt: base64 },
//   data: { iv: base64, ct: base64 },
//   updatedAt: number
// }

// ============ vault ops
async function createVault(uid, masterPassword) {
  const existing = await fetchEnvelope(uid);
  if (existing) throw new Error("Vault already exists for this account. Use Unlock.");

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 310000; // good starting point; adjust if your device is slow
  const key = await deriveKeyPBKDF2(masterPassword, salt, iterations);

  const empty = [];
  const enc = await encryptJSON(key, empty);

  const envelope = {
    v: 1,
    kdf: { name: "PBKDF2", hash: "SHA-256", iter: iterations, salt: bytesToB64(salt) },
    data: enc,
    updatedAt: Date.now()
  };

  await writeEnvelope(uid, envelope);
  return { key, vault: empty };
}

async function unlockVault(uid, masterPassword) {
  const env = await fetchEnvelope(uid);
  if (!env) throw new Error("No vault found for this account. Click 'Create new vault'.");

  if (env.v !== 1 || !env.kdf || !env.data) throw new Error("Vault format not recognized.");

  const salt = b64ToBytes(env.kdf.salt);
  const iterations = env.kdf.iter;

  const key = await deriveKeyPBKDF2(masterPassword, salt, iterations);
  const decrypted = await decryptJSON(key, env.data.iv, env.data.ct);

  if (!Array.isArray(decrypted)) throw new Error("Vault data corrupted.");
  return { key, vault: decrypted };
}

async function persistVault(uid) {
  const env = await fetchEnvelope(uid);
  if (!env) throw new Error("No stored vault to update.");
  env.data = await encryptJSON(aesKey, vault);
  env.updatedAt = Date.now();
  await writeEnvelope(uid, env);
}

// ============ entries UI
function renderEntries() {
  const q = (searchEl.value || "").trim().toLowerCase();
  const filtered = vault.filter((e) => {
    const hay = `${e.site || ""} ${e.username || ""} ${e.notes || ""}`.toLowerCase();
    return hay.includes(q);
  });

  entriesEl.innerHTML = "";
  if (filtered.length === 0) {
    entriesEl.innerHTML = `<div class="muted small">No entries.</div>`;
    return;
  }

  for (const e of filtered) {
    const el = document.createElement("div");
    el.className = "entry";
    el.innerHTML = `
      <div class="top">
        <div>
          <div class="site">${escapeHtml(e.site || "(no site)")}</div>
          <div class="meta">User: ${escapeHtml(e.username || "—")}</div>
        </div>
        <div class="actions">
          <button class="ghost" data-act="copyUser" data-id="${e.id}">Copy user</button>
          <button class="ghost" data-act="copyPw" data-id="${e.id}">Copy password</button>
          <button class="ghost" data-act="reveal" data-id="${e.id}">Reveal</button>
          <button class="ghost" data-act="edit" data-id="${e.id}">Edit</button>
          <button class="danger ghost" data-act="del" data-id="${e.id}">Delete</button>
        </div>
      </div>
      <div class="meta small" id="reveal-${e.id}" style="display:none; margin-top:8px;">
        <div><b>Password:</b> <span class="mono">${escapeHtml(e.password || "")}</span></div>
        ${e.notes ? `<div style="margin-top:6px;"><b>Notes:</b> ${escapeHtml(e.notes)}</div>` : ""}
      </div>
    `;
    entriesEl.appendChild(el);
  }
}

// ============ Auth UI wiring
signUpBtn.addEventListener("click", async () => {
  setMsg(authMsg, "");
  const email = emailEl.value.trim();
  const pw = accountPwEl.value;

  if (!email || !pw) return setMsg(authMsg, "Enter email + account password.", true);

  try {
    await createUserWithEmailAndPassword(auth, email, pw);
    setMsg(authMsg, "Account created. Now create or unlock your vault.");
  } catch (e) {
    setMsg(authMsg, e?.message || "Signup failed.", true);
  }
});

signInBtn.addEventListener("click", async () => {
  setMsg(authMsg, "");
  const email = emailEl.value.trim();
  const pw = accountPwEl.value;

  if (!email || !pw) return setMsg(authMsg, "Enter email + account password.", true);

  try {
    await signInWithEmailAndPassword(auth, email, pw);
    setMsg(authMsg, "Signed in. Now create or unlock your vault.");
  } catch (e) {
    setMsg(authMsg, e?.message || "Signin failed.", true);
  }
});

signOutBtn.addEventListener("click", async () => {
  await signOut(auth);
  lockNow("Signed out & locked.");
});

// Track auth state
onAuthStateChanged(auth, (user) => {
  currentUser = user || null;
  const signedIn = !!currentUser;

  signOutBtn.classList.toggle("hidden", !signedIn);
  wipeCloudBtn.classList.toggle("hidden", !signedIn);

  if (accountStatus) {
    accountStatus.textContent = signedIn ? `Signed in as: ${currentUser.email}` : "Not signed in";
  }

  if (!signedIn) lockNow("Sign in to continue.");
});

// ============ Vault actions
createBtn.addEventListener("click", async () => {
  setMsg(authMsg, "");
  if (!currentUser) return setMsg(authMsg, "Sign in first.", true);

  const master = masterPwEl.value;
  if (!master || master.length < 12) return setMsg(authMsg, "Use a stronger master password (12+ chars).", true);

  try {
    const res = await createVault(currentUser.uid, master);
    aesKey = res.key;
    vault = res.vault;
    showVault();
    setMsg(authMsg, "Vault created & unlocked.");
  } catch (e) {
    setMsg(authMsg, e?.message || "Create failed.", true);
  }
});

unlockBtn.addEventListener("click", async () => {
  setMsg(authMsg, "");
  if (!currentUser) return setMsg(authMsg, "Sign in first.", true);

  const master = masterPwEl.value;
  if (!master) return setMsg(authMsg, "Enter master password.", true);

  try {
    const res = await unlockVault(currentUser.uid, master);
    aesKey = res.key;
    vault = res.vault;
    showVault();
    setMsg(authMsg, "");
  } catch (e) {
    setMsg(authMsg, e?.message || "Unlock failed.", true);
  }
});

lockBtn.addEventListener("click", () => lockNow());

wipeLocalBtn.addEventListener("click", () => lockNow("Local session cleared."));

wipeCloudBtn.addEventListener("click", async () => {
  if (!currentUser) return setMsg(authMsg, "Sign in first.", true);

  const ok = confirm(
    "Delete your encrypted vault from the cloud? This cannot be undone unless you exported a backup."
  );
  if (!ok) return;

  try {
    await removeEnvelope(currentUser.uid);
    lockNow("Cloud vault deleted.");
  } catch (e) {
    setMsg(authMsg, e?.message || "Delete failed.", true);
  }
});

// ============ Entry actions
genBtn.addEventListener("click", () => (passwordEl.value = generatePassword(22)));
clearBtn.addEventListener("click", () => clearForm());
searchEl.addEventListener("input", () => renderEntries());

entriesEl.addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const act = btn.dataset.act;
  const id = btn.dataset.id;
  const item = vault.find((x) => x.id === id);
  if (!item) return;

  if (act === "reveal") {
    const box = document.getElementById(`reveal-${id}`);
    const showing = box.style.display !== "none";
    box.style.display = showing ? "none" : "block";
    btn.textContent = showing ? "Reveal" : "Hide";
  }

  if (act === "copyUser") {
    const ok = await copyToClipboard(item.username || "");
    setMsg(listMsg, ok ? "Username copied." : "Copy failed (browser permissions).", !ok);
  }

  if (act === "copyPw") {
    const ok = await copyToClipboard(item.password || "");
    setMsg(listMsg, ok ? "Password copied." : "Copy failed (browser permissions).", !ok);
  }

  if (act === "edit") {
    entryIdEl.value = item.id;
    siteEl.value = item.site || "";
    usernameEl.value = item.username || "";
    passwordEl.value = item.password || "";
    notesEl.value = item.notes || "";
    setMsg(saveMsg, "Editing entry…");
    siteEl.focus();
  }

  if (act === "del") {
    const ok = confirm(`Delete entry for "${item.site}"?`);
    if (!ok) return;

    vault = vault.filter((x) => x.id !== id);
    await persistVault(currentUser.uid);
    renderEntries();
    setMsg(listMsg, "Deleted.");
    clearForm();
  }
});

entryForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!aesKey || !currentUser) return setMsg(saveMsg, "Locked or not signed in.", true);

  const id = entryIdEl.value || crypto.randomUUID();
  const entry = {
    id,
    site: siteEl.value.trim(),
    username: usernameEl.value.trim(),
    password: passwordEl.value,
    notes: notesEl.value.trim(),
    updatedAt: Date.now(),
  };

  if (!entry.site) return setMsg(saveMsg, "Site is required.", true);

  const idx = vault.findIndex((x) => x.id === id);
  if (idx >= 0) vault[idx] = entry;
  else vault.unshift(entry);

  try {
    await persistVault(currentUser.uid);
    renderEntries();
    setMsg(saveMsg, idx >= 0 ? "Updated." : "Saved.");
    entryIdEl.value = "";
  } catch (err) {
    setMsg(saveMsg, err?.message || "Save failed.", true);
  }
});

// ============ Export / Import encrypted envelope
exportBtn.addEventListener("click", async () => {
  if (!currentUser) return setMsg(listMsg, "Sign in first.", true);

  try {
    const env = await fetchEnvelope(currentUser.uid);
    if (!env) return setMsg(listMsg, "No vault to export.", true);

    const blob = new Blob([JSON.stringify(env, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vault-encrypted-export.json";
    a.click();
    URL.revokeObjectURL(url);
    setMsg(listMsg, "Exported encrypted vault.");
  } catch (e) {
    setMsg(listMsg, e?.message || "Export failed.", true);
  }
});

importFileEl.addEventListener("change", async () => {
  const file = importFileEl.files?.[0];
  if (!file) return;
  if (!currentUser) return setMsg(listMsg, "Sign in first.", true);

  try {
    const text = await file.text();
    const env = JSON.parse(text);

    if (!env || env.v !== 1 || !env.kdf || !env.data) throw new Error("Invalid export file.");

    const ok = confirm("This will REPLACE your cloud vault with the imported one. Continue?");
    if (!ok) return;

    env.updatedAt = Date.now();
    await writeEnvelope(currentUser.uid, env);

    lockNow("Imported. Enter master password to unlock.");
  } catch (err) {
    setMsg(listMsg, err?.message || "Import failed.", true);
  } finally {
    importFileEl.value = "";
  }
});

// Optional auto-lock when tab loses focus
window.addEventListener("blur", () => {
  if (aesKey) lockNow("Locked (tab unfocused).");
});

// Init
showAuth();
setMsg(authMsg, "Sign in, then create or unlock your vault.");
