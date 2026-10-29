// Veil web UI — account + chamber administration against the real
// backend (backend/src/app.js). No build step: plain DOM + fetch, so it
// can be opened straight from a static file server with nothing to
// compile.
//
// Honest scope, stated once here rather than implied: this page does
// NOT implement the hybrid X25519 + ML-KEM-768 end-to-end encryption (or
// the forward-secret X3DH ratchet) that the Rust CLI's crypto/src
// actually does. Porting that into browser JS with the Web Crypto API
// is real, substantial future work of its own (ML-KEM in particular has
// no native Web Crypto support as of this writing and would need a
// vetted WASM/JS implementation, not a hand-rolled one) — faking it here
// with a placeholder key would be worse than not having it, since it
// would look like a working account that quietly can never receive a
// real end-to-end-encrypted message. Instead: registering here creates a
// REAL account (handle + PIN, real bcrypt hash server-side) with an
// explicitly-labeled placeholder public key, good for chamber
// administration; actual messaging needs the CLI (or, once ported,
// Android) for a real identity key.

const BACKEND_URL = window.VEIL_BACKEND_URL || localStorage.getItem("veil-backend-url") || "http://127.0.0.1:8787";

const state = {
  token: localStorage.getItem("veil-token") || null,
  handle: localStorage.getItem("veil-handle") || null,
};

function $(sel) {
  return document.querySelector(sel);
}

function showError(message) {
  const el = $("#error");
  if (!message) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = message;
}

async function api(path, { method = "GET", body, auth = false } = {}) {
  const headers = { "content-type": "application/json" };
  if (auth) {
    if (!state.token) throw new Error("not logged in");
    headers.authorization = `Bearer ${state.token}`;
  }
  const res = await fetch(`${BACKEND_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    // No/invalid JSON body (e.g. a 204) — fine, leave data null.
  }
  if (!res.ok) {
    throw new Error((data && data.error) || `request failed (${res.status})`);
  }
  return data;
}

// A placeholder identity key, clearly labeled as such server-side isn't
// possible (the backend just stores whatever string it's given as
// `pubkey`), so it's labeled here instead: prefixed so it's obviously not
// a real base64-encoded X25519 key to anyone inspecting the account.
function placeholderPubkey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const b64 = btoa(String.fromCharCode(...bytes));
  return `WEB-PLACEHOLDER-NOT-A-REAL-KEY:${b64}`;
}

function setSession(handle, token) {
  state.handle = handle;
  state.token = token;
  localStorage.setItem("veil-handle", handle);
  localStorage.setItem("veil-token", token);
  render();
}

function clearSession() {
  state.handle = null;
  state.token = null;
  localStorage.removeItem("veil-handle");
  localStorage.removeItem("veil-token");
  render();
}

function render() {
  const loggedIn = Boolean(state.token);
  $("#auth-view").hidden = loggedIn;
  $("#main-view").hidden = !loggedIn;
  $("#whoami").textContent = loggedIn ? `logged in as ${state.handle}` : "not logged in";
  if (loggedIn) {
    refreshChambers();
  }
}

async function refreshChambers() {
  try {
    const chambers = await api("/chambers", { auth: true });
    const list = $("#chamber-list");
    list.innerHTML = "";
    if (chambers.length === 0) {
      const li = document.createElement("li");
      li.textContent = "no chambers yet";
      li.classList.add("muted");
      list.appendChild(li);
    }
    for (const c of chambers) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.textContent = c.name;
      const when = document.createElement("span");
      when.className = "muted";
      when.textContent = new Date(c.createdAt).toLocaleDateString();
      li.append(name, when);
      list.appendChild(li);
    }
    showError(null);
  } catch (e) {
    showError(e.message);
  }
}

async function refreshInbox() {
  try {
    const rows = await api("/messages", { auth: true });
    $("#inbox-status").textContent =
      rows.length === 0
        ? "nothing waiting."
        : `${rows.length} message(s) waiting — decrypt them with the CLI (or Android app), this page can't.`;
    showError(null);
  } catch (e) {
    showError(e.message);
  }
}

function wireForms() {
  $("#register-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    try {
      const resp = await api("/auth/register", {
        method: "POST",
        body: {
          handle: form.get("handle"),
          pin: form.get("pin"),
          pubkey: placeholderPubkey(),
        },
      });
      setSession(resp.handle, resp.token);
      showError(null);
      ev.target.reset();
    } catch (e) {
      showError(e.message);
    }
  });

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    try {
      const resp = await api("/auth/login", {
        method: "POST",
        body: { handle: form.get("handle"), pin: form.get("pin") },
      });
      setSession(resp.handle, resp.token);
      showError(null);
      ev.target.reset();
    } catch (e) {
      showError(e.message);
    }
  });

  $("#create-chamber-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    try {
      await api("/chambers", { method: "POST", auth: true, body: { name: form.get("name") } });
      ev.target.reset();
      await refreshChambers();
    } catch (e) {
      showError(e.message);
    }
  });

  $("#refresh-chambers").addEventListener("click", refreshChambers);
  $("#refresh-inbox").addEventListener("click", refreshInbox);
  $("#logout").addEventListener("click", clearSession);
}

wireForms();
render();
