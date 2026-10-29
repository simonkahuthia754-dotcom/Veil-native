//! veil — the terminal client. Talks to veil-backend over HTTPS (+ optional
//! Tor SOCKS5 proxy, like the backend's own feed-ingest worker). Local
//! identity and app lock live in `veil-crypto`; this file is wiring: a REPL,
//! HTTP calls, and mapping between veil-crypto's binary key material and
//! the backend's base64 JSON fields.
//!
//! Honesty note: written carefully, not compiled or run in this session
//! (see the crate-level doc comment in veil-crypto for why). The first
//! GitHub Actions run on this repo is the real first build.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Write};
use veil_crypto::{
    accept_session, initiate_session, AppLock, Identity, PrekeyBundle, SealedMessage, SecureStore,
    Session,
};

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    token: Option<String>,
    user_id: Option<String>,
    handle: Option<String>,
    x_secret_b64: Option<String>, // stored so Identity survives restarts (see note in main())
    kem_dk_b64: Option<String>,

    // Forward-secrecy state (session.rs). This device's own medium-term
    // prekey secret — published once (publicly) and kept until rotated;
    // losing this means every contact who already fetched its public half
    // can no longer complete a handshake against it.
    medium_term_x_b64: Option<String>,
    medium_term_kem_b64: Option<String>,
    // One-time prekeys this device has published and not yet had consumed
    // by an incoming handshake, keyed by their public X25519 bytes
    // (base64, matching what the server hands back in an InitialMessage's
    // `one_time_x_public_used`) -> (x secret b64, kem seed b64). Each
    // entry is removed the moment it's used to accept a handshake — a
    // one-time prekey that stays reusable isn't one.
    #[serde(default)]
    one_time_prekeys: HashMap<String, (String, String)>,
    // Live per-contact session state, keyed by the contact's long-term
    // X25519 identity public key (base64) — not by handle, since a handle
    // is only known to the side that initiated the conversation; the
    // identity key is known to both sides from the first message either
    // way.
    #[serde(default)]
    sessions: HashMap<String, Session>,
}

fn data_dir() -> Result<std::path::PathBuf> {
    let dirs = directories::ProjectDirs::from("org", "veil", "veil-cli")
        .ok_or_else(|| anyhow!("couldn't resolve a config directory for this OS"))?;
    let dir = dirs.data_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn backend_base() -> String {
    std::env::var("VEIL_BACKEND_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

fn build_http_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Ok(proxy) = std::env::var("VEIL_SOCKS_PROXY") {
        // e.g. socks5h://127.0.0.1:9050 for Tor, same convention as the
        // backend's feed-ingest worker (TOR_SOCKS_URL).
        builder =
            builder.proxy(reqwest::Proxy::all(proxy.as_str()).context("invalid VEIL_SOCKS_PROXY")?);
        println!("[veil] routing all requests through {proxy}");
    } else {
        println!("[veil] no VEIL_SOCKS_PROXY set — connecting directly, not through Tor. Set VEIL_SOCKS_PROXY=socks5h://127.0.0.1:9050 to route through a local Tor daemon.");
    }
    Ok(builder.build()?)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("veil — terminal client. Type `help` for commands.\n");

    let vault_path = data_dir()?.join("vault.bin");
    let http = build_http_client()?;

    print!("vault passphrase (first run creates it): ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    let store = SecureStore::open_or_create(&vault_path, &passphrase)
        .context("failed to open local vault — wrong passphrase, or a corrupted/tampered store")?;
    let mut data: VaultData = store.load().unwrap_or_default();

    // App-lock state lives inside the same encrypted vault, keyed on the
    // same passphrase used to open it — so "unlock the vault" and "pass
    // the app lock" are the same action here, by design (one real secret,
    // not two independent ones to keep in sync). A standalone, separately-
    // configurable AppLock (duress passphrase + fail-count wipe) is wired
    // in here as a second gate: see `lock` command below for how to turn it
    // on.

    let identity = match (&data.x_secret_b64, &data.kem_dk_b64) {
        (Some(x_b64), Some(kem_b64)) => {
            let x_bytes = B64
                .decode(x_b64)
                .context("corrupted vault: stored X25519 secret isn't valid base64")?;
            let kem_bytes = B64
                .decode(kem_b64)
                .context("corrupted vault: stored ML-KEM seed isn't valid base64")?;
            match Identity::from_secret_bytes(&x_bytes, &kem_bytes) {
                Ok(id) => {
                    println!("[veil] restored existing identity from the vault.");
                    id
                }
                Err(e) => {
                    // A corrupted/truncated stored identity is a real
                    // failure, not silently papered over with a fresh
                    // identity (that would quietly break every contact's
                    // sessions with this device without saying so).
                    return Err(anyhow!(
                        "stored identity in the vault is unreadable ({e}) — the vault file may be corrupted. Refusing to silently replace it; restore from a backup or delete the vault to start over."
                    ));
                }
            }
        }
        _ => {
            println!("[veil] generating a new hybrid identity (X25519 + ML-KEM-768)…");
            let identity = Identity::generate();
            let (x_bytes, kem_bytes) = identity.to_secret_bytes();
            data.x_secret_b64 = Some(B64.encode(x_bytes));
            data.kem_dk_b64 = Some(B64.encode(kem_bytes));
            store
                .save(&data)
                .context("failed to persist the new identity to the vault")?;
            identity
        }
    };

    let mut rl = String::new();
    loop {
        print!("veil> ");
        io::stdout().flush()?;
        rl.clear();
        if io::stdin().read_line(&mut rl)? == 0 {
            break; // EOF
        }
        let line = rl.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();

        let result = match cmd {
            "help" => {
                print_help();
                Ok(())
            }
            "register" => cmd_register(&http, &mut data, &identity, &rest).await,
            "login" => cmd_login(&http, &mut data, &rest).await,
            "whoami" => {
                match (&data.handle, &data.user_id) {
                    (Some(h), Some(id)) => println!("logged in as {h} ({id})"),
                    _ => println!("not logged in — use `register <handle>` or `login <handle>`"),
                }
                Ok(())
            }
            "careers" => cmd_careers(&http).await,
            "chambers" => cmd_chambers(&http, &data).await,
            "create-chamber" => cmd_create_chamber(&http, &data, &rest).await,
            "invite" => cmd_invite(&http, &data, &rest).await,
            "send" => cmd_send(&http, &mut data, &identity, &rest).await,
            "chamber-send" => cmd_chamber_send(&http, &mut data, &identity, &rest).await,
            "inbox" => cmd_inbox(&http, &mut data, &identity).await,
            "lock" => {
                cmd_lock_demo();
                Ok(())
            }
            "quit" | "exit" => break,
            other => {
                println!("unknown command: {other} (try `help`)");
                Ok(())
            }
        };
        if let Err(e) = result {
            eprintln!("error: {e:#}");
        }
        store.save(&data).context("failed to save local vault")?;
    }

    println!("bye.");
    Ok(())
}

fn print_help() {
    println!(
        "commands:
  register <handle>          create an account (prompts for a PIN)
  login <handle>              log into an existing account (prompts for PIN)
  whoami                      show the current session
  careers                     list chamber categories the server knows about
  chambers                    list chambers you've joined / can see
  create-chamber <name>       create a new chamber
  invite <chamber-id> <handle>        invite an existing user into a chamber you're in
  send <handle> <message...>  encrypt and send a direct message
  chamber-send <chamber-id> <message...>  encrypt and fan a message out to every chamber member
  inbox                       fetch + decrypt + ack any waiting messages
  lock                        demo of the Argon2id app-lock + duress + auto-wipe logic
  quit                        exit
Environment:
  VEIL_BACKEND_URL   default http://127.0.0.1:8080
  VEIL_SOCKS_PROXY   e.g. socks5h://127.0.0.1:9050 to route over Tor"
    );
}

#[derive(Deserialize)]
struct AuthResp {
    // The backend's authResponse() (backend/src/app.js) returns the field
    // as plain "id", matching Android's AuthResponse.id — this used to say
    // "userId" here, a guessed field name written before the real backend
    // existed. Fixed now that there's a real contract to check against.
    id: String,
    token: String,
    handle: String,
}

async fn cmd_register(
    http: &reqwest::Client,
    data: &mut VaultData,
    identity: &Identity,
    args: &[&str],
) -> Result<()> {
    let handle = args
        .first()
        .ok_or_else(|| anyhow!("usage: register <handle>"))?;
    print!("choose a PIN (4-8 digits): ");
    io::stdout().flush()?;
    let pin = rpassword::read_password()?;

    let (x_pub, kem_ek) = identity.public_bundle();
    let body = serde_json::json!({
        "handle": handle,
        "pin": pin,
        "pubkey": B64.encode(x_pub),
        "pqPubkey": B64.encode(kem_ek),
    });
    let resp = http
        .post(format!("{}/auth/register", backend_base()))
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let msg: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "register failed: {}",
            msg.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
        ));
    }
    let auth: AuthResp = resp.json().await?;
    println!("registered as {} — you're logged in.", auth.handle);
    data.token = Some(auth.token);
    data.user_id = Some(auth.id);
    data.handle = Some(auth.handle);
    ensure_prekeys_published(http, data).await?;
    Ok(())
}

async fn cmd_login(http: &reqwest::Client, data: &mut VaultData, args: &[&str]) -> Result<()> {
    let handle = args
        .first()
        .ok_or_else(|| anyhow!("usage: login <handle>"))?;
    print!("PIN: ");
    io::stdout().flush()?;
    let pin = rpassword::read_password()?;

    let body = serde_json::json!({ "handle": handle, "pin": pin });
    let resp = http
        .post(format!("{}/auth/login", backend_base()))
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("login failed — check handle/PIN"));
    }
    let auth: AuthResp = resp.json().await?;
    println!("logged in as {}.", auth.handle);
    data.token = Some(auth.token);
    data.user_id = Some(auth.id);
    data.handle = Some(auth.handle);
    ensure_prekeys_published(http, data).await?;
    Ok(())
}

/// Publishes a medium-term prekey + a batch of one-time prekeys the first
/// time this device ever logs in (if `data` already has a medium-term
/// prekey, this is a no-op — rotating it is separate, deliberate future
/// work, not done automatically on every login). Without this, nobody can
/// ever start a forward-secret session with this device: `POST /prekeys`
/// is what makes `GET /prekeys/:handle/bundle` return something other than
/// nulls for it.
async fn ensure_prekeys_published(http: &reqwest::Client, data: &mut VaultData) -> Result<()> {
    if data.medium_term_x_b64.is_some() {
        return Ok(());
    }
    let token = require_token(data)?.to_string();

    let medium_term = veil_crypto::Prekey::generate();
    let (mt_x_secret, mt_kem_secret) = medium_term.to_secret_bytes();
    let (mt_x_pub, mt_kem_pub) = medium_term.public_bundle();
    data.medium_term_x_b64 = Some(B64.encode(mt_x_secret));
    data.medium_term_kem_b64 = Some(B64.encode(mt_kem_secret));

    const ONE_TIME_COUNT: usize = 10;
    let mut otpks_public = Vec::with_capacity(ONE_TIME_COUNT);
    for _ in 0..ONE_TIME_COUNT {
        let otpk = veil_crypto::Prekey::generate();
        let (x_secret, kem_secret) = otpk.to_secret_bytes();
        let (x_pub, kem_pub) = otpk.public_bundle();
        data.one_time_prekeys.insert(
            B64.encode(&x_pub),
            (B64.encode(x_secret), B64.encode(kem_secret)),
        );
        otpks_public.push(serde_json::json!({
            "xPub": B64.encode(x_pub),
            "kemPub": B64.encode(kem_pub),
        }));
    }

    let body = serde_json::json!({
        "mediumTermPrekey": { "xPub": B64.encode(mt_x_pub), "kemPub": B64.encode(mt_kem_pub) },
        "oneTimePrekeys": otpks_public,
    });
    let resp = http
        .post(format!("{}/prekeys", backend_base()))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "logged in, but failed to publish prekeys — contacts won't be able to start forward-secret sessions with you until this succeeds"
        ));
    }
    println!(
        "[veil] published a medium-term prekey + {ONE_TIME_COUNT} one-time prekeys for forward-secret handshakes."
    );
    Ok(())
}

fn require_token(data: &VaultData) -> Result<&str> {
    data.token
        .as_deref()
        .ok_or_else(|| anyhow!("not logged in — use `register` or `login` first"))
}

async fn cmd_careers(http: &reqwest::Client) -> Result<()> {
    let resp = http
        .get(format!("{}/chambers/careers", backend_base()))
        .send()
        .await?;
    let careers: Vec<String> = resp.json().await?;
    println!("{}", careers.join(", "));
    Ok(())
}

#[derive(Deserialize)]
struct ChamberRow {
    id: String,
    name: String,
    #[serde(rename = "memberCount")]
    member_count: i64,
    // A real JSON boolean from the backend (backend/src/app.js's
    // `isMember: true`), not a number — this struct previously declared
    // it as `i64`, which would have failed to deserialize the moment the
    // backend actually started sending the field (it never had before
    // now: GET /chambers returning memberCount/isMember at all was a
    // named README gap until this change closed it). Caught by actually
    // implementing the backend side instead of just the client-side
    // shape.
    #[serde(rename = "isMember")]
    is_member: bool,
}

async fn cmd_chambers(http: &reqwest::Client, data: &VaultData) -> Result<()> {
    let token = require_token(data)?;
    let resp = http
        .get(format!("{}/chambers", backend_base()))
        .bearer_auth(token)
        .send()
        .await?;
    let rows: Vec<ChamberRow> = resp.json().await?;
    if rows.is_empty() {
        println!("no chambers yet — try `create-chamber <name>`");
    }
    for r in rows {
        println!(
            "{}  {} members  {}  [{}]",
            r.name,
            r.member_count,
            if r.is_member { "joined" } else { "not joined" },
            r.id
        );
    }
    Ok(())
}

async fn cmd_create_chamber(http: &reqwest::Client, data: &VaultData, args: &[&str]) -> Result<()> {
    let token = require_token(data)?;
    let name = args.join(" ");
    if name.is_empty() {
        return Err(anyhow!("usage: create-chamber <name>"));
    }
    let resp = http
        .post(format!("{}/chambers", backend_base()))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": name, "icon": "bolt" }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let msg: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "{}",
            msg.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("could not create chamber")
        ));
    }
    println!("chamber created.");
    Ok(())
}

#[derive(Deserialize)]
struct UserBundle {
    id: String,
    pubkey: String,
    #[serde(rename = "pqPubkey")]
    pq_pubkey: Option<String>,
}

#[derive(Deserialize, Clone)]
struct ChamberMember {
    id: String,
    handle: String,
    pubkey: String,
    #[serde(rename = "pqPubkey")]
    pq_pubkey: Option<String>,
}

// Wire envelope sent as the JSON-encoded "ciphertext" field: three shapes,
// told apart by which keys are present rather than a strict tag, so a
// message sent by an old build (plain {kemCt, ct}, no "kind" field at all)
// still parses:
//   - {"kemCt","ct"}        — legacy static hybrid scheme (e2e.rs), no
//                             forward secrecy. Kept for contacts who
//                             haven't published prekeys yet.
//   - {"init","msg"}        — first message of a new forward-secret
//                             session: an X3DH InitialMessage plus the
//                             first RatchetedMessage sealed with it.
//   - {"msg"}                — a subsequent message in an already-
//                             established session.
//
// Shared by both DM send and chamber fan-out send (below): sealing is
// always pairwise (this is X3DH + a per-pair ratchet, not a group key),
// so fanning a message out to a chamber means calling this once per
// member and POSTing once per member too — never one POST with multiple
// recipientIds and one shared ciphertext, which would be cryptographically
// wrong for this scheme (every recipient needs their own sealed copy).
async fn cmd_send(
    http: &reqwest::Client,
    data: &mut VaultData,
    identity: &Identity,
    args: &[&str],
) -> Result<()> {
    let token = require_token(data)?.to_string();
    let handle = args
        .first()
        .ok_or_else(|| anyhow!("usage: send <handle> <message...>"))?;
    let message = args[1..].join(" ");
    if message.is_empty() {
        return Err(anyhow!("usage: send <handle> <message...>"));
    }

    let resp = http
        .get(format!("{}/auth/users/{}", backend_base(), handle))
        .bearer_auth(&token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("no such user: {handle}"));
    }
    let contact: UserBundle = resp.json().await?;

    let (packed, nonce_b64, used_forward_secrecy) = seal_for_one(
        http,
        data,
        identity,
        &token,
        handle,
        &contact.pubkey,
        contact.pq_pubkey.as_deref(),
        &message,
    )
    .await?;

    let my_x_pub_b64 = B64.encode(identity.public_bundle().0);
    let body = serde_json::json!({
        "scope": "dm",
        "scopeId": handle,
        "recipientIds": [contact.id],
        "ciphertext": packed,
        "nonce": nonce_b64,
        "senderPubkey": my_x_pub_b64,
    });
    let resp = http
        .post(format!("{}/messages", backend_base()))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("send failed"));
    }
    println!(
        "sent{}.",
        if used_forward_secrecy {
            " (forward-secret ratchet)"
        } else {
            " (static hybrid, no forward secrecy)"
        }
    );
    Ok(())
}

/// The actual per-recipient sealing logic (session lookup, X3DH handshake,
/// or static-scheme fallback) shared by `cmd_send` (one DM) and
/// `cmd_chamber_send` (one call per chamber member). Returns
/// (packed ciphertext JSON, nonce b64, used_forward_secrecy).
async fn seal_for_one(
    http: &reqwest::Client,
    data: &mut VaultData,
    identity: &Identity,
    token: &str,
    recipient_handle: &str,
    recipient_pubkey_b64: &str,
    recipient_pq_pubkey_b64: Option<&str>,
    message: &str,
) -> Result<(String, String, bool)> {
    // The session map is keyed by the recipient's long-term X25519
    // identity key (base64), not by handle — see VaultData's doc comment
    // on `sessions` for why.
    let session_key = recipient_pubkey_b64.to_string();

    if let Some(session) = data.sessions.get_mut(&session_key) {
        let msg = session.seal(message.as_bytes())?;
        let nonce_b64 = B64.encode(&msg.nonce);
        return Ok((
            serde_json::json!({ "msg": msg }).to_string(),
            nonce_b64,
            true,
        ));
    }

    let bundle_resp = http
        .get(format!(
            "{}/prekeys/{}/bundle",
            backend_base(),
            recipient_handle
        ))
        .bearer_auth(token)
        .send()
        .await?;
    let bundle_json: serde_json::Value = if bundle_resp.status().is_success() {
        bundle_resp.json().await.unwrap_or_default()
    } else {
        serde_json::Value::Null
    };
    let medium_term = bundle_json.get("mediumTermPrekey").filter(|v| !v.is_null());

    if let Some(mt) = medium_term {
        let identity_x = bundle_json["identityPubkey"].as_str().unwrap_or_default();
        let mt_x = mt["xPub"].as_str().unwrap_or_default();
        let mt_kem = mt["kemPub"].as_str().unwrap_or_default();
        let one_time = bundle_json.get("oneTimePrekey").filter(|v| !v.is_null());
        let otpk_x = one_time.and_then(|o| o["xPub"].as_str());

        let prekey_bundle = PrekeyBundle {
            identity_x_public: B64.decode(identity_x)?,
            medium_term_x_public: B64.decode(mt_x)?,
            medium_term_kem_public: B64.decode(mt_kem)?,
            one_time_x_public: match otpk_x {
                Some(s) => Some(B64.decode(s)?),
                None => None,
            },
        };
        let (mut session, init) = initiate_session(identity, &prekey_bundle)?;
        let msg = session.seal(message.as_bytes())?;
        let nonce_b64 = B64.encode(&msg.nonce);
        data.sessions.insert(session_key.clone(), session);
        return Ok((
            serde_json::json!({ "init": init, "msg": msg }).to_string(),
            nonce_b64,
            true,
        ));
    }

    let pq_pubkey = recipient_pq_pubkey_b64.ok_or_else(|| {
        anyhow!("{recipient_handle} has no ML-KEM public key on file and no published prekeys — can't reach them at all")
    })?;
    let sealed: SealedMessage = veil_crypto::e2e::seal(
        identity,
        &B64.decode(recipient_pubkey_b64)?,
        &B64.decode(pq_pubkey)?,
        message.as_bytes(),
    )?;
    println!("[veil] NOTE: {recipient_handle} hasn't published forward-secret prekeys yet — sent with the static hybrid scheme instead (no forward secrecy for this one message).");
    let nonce_b64 = B64.encode(&sealed.nonce);
    let packed = serde_json::json!({
        "kemCt": B64.encode(&sealed.kem_ciphertext),
        "ct": B64.encode(&sealed.ciphertext),
    })
    .to_string();
    Ok((packed, nonce_b64, false))
}

async fn cmd_chamber_send(
    http: &reqwest::Client,
    data: &mut VaultData,
    identity: &Identity,
    args: &[&str],
) -> Result<()> {
    let token = require_token(data)?.to_string();
    let chamber_id = args
        .first()
        .ok_or_else(|| anyhow!("usage: chamber-send <chamber-id> <message...>"))?
        .to_string();
    let message = args[1..].join(" ");
    if message.is_empty() {
        return Err(anyhow!("usage: chamber-send <chamber-id> <message...>"));
    }

    let resp = http
        .get(format!(
            "{}/chambers/{}/members",
            backend_base(),
            chamber_id
        ))
        .bearer_auth(&token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "no such chamber, or you aren't a member of it: {chamber_id}"
        ));
    }
    let members: Vec<ChamberMember> = resp.json().await?;
    let my_id = data.user_id.clone();
    let my_x_pub_b64 = B64.encode(identity.public_bundle().0);

    // Sealing is pairwise, so this is genuinely one handshake-or-ratchet
    // step and one POST per member — not one shared ciphertext, which
    // would be wrong for this scheme (see seal_for_one's doc comment).
    // Each member's failure (no prekeys AND no PQ key on file, a network
    // hiccup, whatever) is reported and skipped rather than aborting the
    // whole send — a chamber with nine reachable members and one
    // unreachable one should still deliver to the nine.
    let mut sent = 0;
    let mut failed = Vec::new();
    for member in &members {
        if Some(&member.id) == my_id.as_ref() {
            continue; // never seal a copy to ourselves
        }
        let result = seal_for_one(
            http,
            data,
            identity,
            &token,
            &member.handle,
            &member.pubkey,
            member.pq_pubkey.as_deref(),
            &message,
        )
        .await;
        let (packed, nonce_b64, _used_forward_secrecy) = match result {
            Ok(v) => v,
            Err(e) => {
                failed.push(member.handle.clone());
                eprintln!("  (couldn't seal for {}: {e})", member.handle);
                continue;
            }
        };
        let body = serde_json::json!({
            "scope": "chamber",
            "scopeId": chamber_id,
            "recipientIds": [member.id],
            "ciphertext": packed,
            "nonce": nonce_b64,
            "senderPubkey": my_x_pub_b64,
        });
        let send_resp = http
            .post(format!("{}/messages", backend_base()))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        if send_resp.status().is_success() {
            sent += 1;
        } else {
            failed.push(member.handle.clone());
        }
    }

    println!(
        "sent to {sent}/{} chamber member(s){}.",
        members.len().saturating_sub(my_id.is_some() as usize),
        if failed.is_empty() {
            String::new()
        } else {
            format!(" — failed: {}", failed.join(", "))
        }
    );
    Ok(())
}

async fn cmd_invite(http: &reqwest::Client, data: &VaultData, args: &[&str]) -> Result<()> {
    let token = require_token(data)?;
    let chamber_id = args
        .first()
        .ok_or_else(|| anyhow!("usage: invite <chamber-id> <handle>"))?;
    let handle = args
        .get(1)
        .ok_or_else(|| anyhow!("usage: invite <chamber-id> <handle>"))?;
    let resp = http
        .post(format!(
            "{}/chambers/{}/members",
            backend_base(),
            chamber_id
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({ "handle": handle }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let msg: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!(
            "{}",
            msg.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("could not invite")
        ));
    }
    println!("invited {handle}.");
    Ok(())
}

// NOTE: GET /messages returns raw SQLite rows (snake_case column names,
// since better-sqlite3 doesn't transform them), unlike most of this API
// which is camelCase JSON — a real inconsistency in veil-backend worth
// normalizing there later. Matched as-is here rather than papered over.
#[derive(Deserialize)]
struct InboxRow {
    id: String,
    ciphertext: String,
    nonce: String,
    sender_pubkey: String,
}

async fn cmd_inbox(
    http: &reqwest::Client,
    data: &mut VaultData,
    identity: &Identity,
) -> Result<()> {
    let token = require_token(data)?.to_string();
    let resp = http
        .get(format!("{}/messages", backend_base()))
        .bearer_auth(&token)
        .send()
        .await?;
    let rows: Vec<InboxRow> = resp.json().await?;
    if rows.is_empty() {
        println!("nothing waiting.");
        return Ok(());
    }

    // Reconstruct this device's medium-term prekey + one-time prekey pool
    // once for the whole inbox pass, not once per message — handshakes
    // only ever need them, never the per-message ratchet logic itself.
    let my_medium_term = match (&data.medium_term_x_b64, &data.medium_term_kem_b64) {
        (Some(x), Some(k)) => Some(
            veil_crypto::Prekey::from_secret_bytes(&B64.decode(x)?, &B64.decode(k)?)
                .map_err(|e| anyhow!("corrupted medium-term prekey in vault: {e}"))?,
        ),
        _ => None,
    };
    let mut my_otpks: HashMap<Vec<u8>, veil_crypto::Prekey> = HashMap::new();
    for (x_pub_b64, (x_secret_b64, kem_secret_b64)) in &data.one_time_prekeys {
        let prekey = veil_crypto::Prekey::from_secret_bytes(
            &B64.decode(x_secret_b64)?,
            &B64.decode(kem_secret_b64)?,
        )
        .map_err(|e| anyhow!("corrupted one-time prekey in vault: {e}"))?;
        my_otpks.insert(B64.decode(x_pub_b64)?, prekey);
    }
    let otpk_count_before = my_otpks.len();

    let mut acked = Vec::new();
    for row in &rows {
        let packed: serde_json::Value = match serde_json::from_str(&row.ciphertext) {
            Ok(v) => v,
            Err(_) => {
                println!("[{}] (unreadable message body — skipping)", row.id);
                continue;
            }
        };

        let plaintext: Result<Vec<u8>> = if packed.get("kemCt").is_some() {
            (|| -> Result<Vec<u8>> {
                let kem_ct = B64.decode(packed["kemCt"].as_str().unwrap_or_default())?;
                let ct = B64.decode(packed["ct"].as_str().unwrap_or_default())?;
                let sealed = SealedMessage {
                    sender_x_public: B64.decode(&row.sender_pubkey)?,
                    kem_ciphertext: kem_ct,
                    nonce: B64.decode(&row.nonce)?,
                    ciphertext: ct,
                };
                Ok(veil_crypto::e2e::open(identity, &sealed)?)
            })()
        } else if let Some(init_val) = packed.get("init") {
            (|| -> Result<Vec<u8>> {
                let my_mt = my_medium_term.as_ref().ok_or_else(|| {
                    anyhow!("received a handshake but this device has no medium-term prekey — run `register`/`login` again to publish one")
                })?;
                let init: veil_crypto::InitialMessage = serde_json::from_value(init_val.clone())?;
                let msg: veil_crypto::RatchetedMessage =
                    serde_json::from_value(packed["msg"].clone())?;
                let mut session = accept_session(identity, my_mt, &mut my_otpks, &init)?;
                let plaintext = session.open(&msg)?;
                data.sessions.insert(row.sender_pubkey.clone(), session);
                Ok(plaintext)
            })()
        } else if let Some(msg_val) = packed.get("msg") {
            (|| -> Result<Vec<u8>> {
                let msg: veil_crypto::RatchetedMessage = serde_json::from_value(msg_val.clone())?;
                let session = data.sessions.get_mut(&row.sender_pubkey).ok_or_else(|| {
                    anyhow!("no session for this sender yet (their handshake message may have arrived out of order, or wasn't received) — can't decrypt")
                })?;
                Ok(session.open(&msg)?)
            })()
        } else {
            Err(anyhow!("unrecognized message envelope shape"))
        };

        match plaintext {
            Ok(plaintext) => println!("  {}", String::from_utf8_lossy(&plaintext)),
            Err(e) => println!("  (could not decrypt {}: {e})", row.id),
        }
        acked.push(row.id.clone());
    }

    // Persist any one-time prekeys consumed by handshakes accepted above —
    // removed from the live map, removed from the vault too, so a reused
    // `InitialMessage` can never be accepted twice.
    if my_otpks.len() != otpk_count_before {
        let still_live: std::collections::HashSet<String> =
            my_otpks.keys().map(|k| B64.encode(k)).collect();
        data.one_time_prekeys.retain(|k, _| still_live.contains(k));
    }

    if !acked.is_empty() {
        http.post(format!("{}/messages/ack", backend_base()))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "ids": acked }))
            .send()
            .await?;
    }
    Ok(())
}

fn cmd_lock_demo() {
    use veil_crypto::lock::Verdict;
    println!("[demo] AppLock: Argon2id passphrase + optional duress passphrase + auto-wipe after N fails.");
    let mut lock =
        AppLock::new("correct horse battery staple", Some("i-am-under-duress"), 3).unwrap();
    println!("  wrong attempt:   {:?}", lock.check("nope", 0));
    println!("  wrong attempt:   {:?}", lock.check("nope", 0));
    match lock.check("i-am-under-duress", 0) {
        Verdict::Duress => {
            println!("  duress phrase:   Duress — caller must now call SecureStore::wipe()")
        }
        other => println!("  duress phrase:   unexpected {other:?}"),
    }
    println!(
        "  correct phrase:  {:?}",
        lock.check("correct horse battery staple", 0)
    );
    println!(
        "  (this demo never touches the real vault — it's illustrating the state machine only)"
    );
}
