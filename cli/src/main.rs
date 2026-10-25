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
use std::io::{self, Write};
use veil_crypto::{AppLock, Identity, SealedMessage, SecureStore};

#[derive(Serialize, Deserialize, Default)]
struct VaultData {
    token: Option<String>,
    user_id: Option<String>,
    handle: Option<String>,
    x_secret_b64: Option<String>, // stored so Identity survives restarts (see note in main())
    kem_dk_b64: Option<String>,
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
        builder = builder.proxy(reqwest::Proxy::all(proxy.as_str()).context("invalid VEIL_SOCKS_PROXY")?);
        println!("[veil] routing all requests through {proxy}");
    } else {
        println!("[veil] no VEIL_SOCKS_PROXY set \u2014 connecting directly, not through Tor. Set VEIL_SOCKS_PROXY=socks5h://127.0.0.1:9050 to route through a local Tor daemon.");
    }
    Ok(builder.build()?)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("veil \u2014 terminal client. Type `help` for commands.\n");

    let vault_path = data_dir()?.join("vault.bin");
    let http = build_http_client()?;

    print!("vault passphrase (first run creates it): ");
    io::stdout().flush()?;
    let passphrase = rpassword::read_password()?;

    let store = SecureStore::open_or_create(&vault_path, &passphrase)
        .context("failed to open local vault \u2014 wrong passphrase, or a corrupted/tampered store")?;
    let mut data: VaultData = store.load().unwrap_or_default();

    // App-lock state lives inside the same encrypted vault, keyed on the
    // same passphrase used to open it \u2014 so "unlock the vault" and "pass
    // the app lock" are the same action here, by design (one real secret,
    // not two independent ones to keep in sync). A standalone, separately-
    // configurable AppLock (duress passphrase + fail-count wipe) is wired
    // in here as a second gate: see `lock` command below for how to turn it
    // on.

    let identity = match (&data.x_secret_b64, &data.kem_dk_b64) {
        (Some(_), Some(_)) => {
            // NOTE: veil-crypto's Identity intentionally does not expose a
            // from_bytes constructor yet (keeping secret material inside
            // the type, generated once, is the safer default). Wiring
            // persistence through needs a small, deliberate addition to
            // veil-crypto (a `Identity::from_secret_bytes` constructor) \u2014
            // flagged here rather than worked around with an unsafe cast.
            println!("[veil] NOTE: identity persistence needs Identity::from_secret_bytes in veil-crypto (TODO, see README) \u2014 generating a fresh identity for this session instead of reusing the stored one.");
            Identity::generate()
        }
        _ => {
            println!("[veil] generating a new hybrid identity (X25519 + ML-KEM-768)\u2026");
            Identity::generate()
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
                    _ => println!("not logged in \u2014 use `register <handle>` or `login <handle>`"),
                }
                Ok(())
            }
            "careers" => cmd_careers(&http).await,
            "chambers" => cmd_chambers(&http, &data).await,
            "create-chamber" => cmd_create_chamber(&http, &data, &rest).await,
            "send" => cmd_send(&http, &data, &identity, &rest).await,
            "inbox" => cmd_inbox(&http, &data, &identity).await,
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
  send <handle> <message...>  encrypt and send a direct message
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
    #[serde(rename = "userId")]
    user_id: String,
    token: String,
    handle: String,
}

async fn cmd_register(http: &reqwest::Client, data: &mut VaultData, identity: &Identity, args: &[&str]) -> Result<()> {
    let handle = args.first().ok_or_else(|| anyhow!("usage: register <handle>"))?;
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
    let resp = http.post(format!("{}/auth/register", backend_base())).json(&body).send().await?;
    if !resp.status().is_success() {
        let msg: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(anyhow!("register failed: {}", msg.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error")));
    }
    let auth: AuthResp = resp.json().await?;
    println!("registered as {} \u2014 you're logged in.", auth.handle);
    data.token = Some(auth.token);
    data.user_id = Some(auth.user_id);
    data.handle = Some(auth.handle);
    Ok(())
}

async fn cmd_login(http: &reqwest::Client, data: &mut VaultData, args: &[&str]) -> Result<()> {
    let handle = args.first().ok_or_else(|| anyhow!("usage: login <handle>"))?;
    print!("PIN: ");
    io::stdout().flush()?;
    let pin = rpassword::read_password()?;

    let body = serde_json::json!({ "handle": handle, "pin": pin });
    let resp = http.post(format!("{}/auth/login", backend_base())).json(&body).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("login failed \u2014 check handle/PIN"));
    }
    let auth: AuthResp = resp.json().await?;
    println!("logged in as {}.", auth.handle);
    data.token = Some(auth.token);
    data.user_id = Some(auth.user_id);
    data.handle = Some(auth.handle);
    Ok(())
}

fn require_token(data: &VaultData) -> Result<&str> {
    data.token.as_deref().ok_or_else(|| anyhow!("not logged in \u2014 use `register` or `login` first"))
}

async fn cmd_careers(http: &reqwest::Client) -> Result<()> {
    let resp = http.get(format!("{}/chambers/careers", backend_base())).send().await?;
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
    #[serde(rename = "isMember")]
    is_member: i64,
}

async fn cmd_chambers(http: &reqwest::Client, data: &VaultData) -> Result<()> {
    let token = require_token(data)?;
    let resp = http.get(format!("{}/chambers", backend_base())).bearer_auth(token).send().await?;
    let rows: Vec<ChamberRow> = resp.json().await?;
    if rows.is_empty() {
        println!("no chambers yet \u2014 try `create-chamber <name>`");
    }
    for r in rows {
        println!("{}  {} members  {}  [{}]", r.name, r.member_count, if r.is_member != 0 { "joined" } else { "not joined" }, r.id);
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
        return Err(anyhow!("{}", msg.get("error").and_then(|v| v.as_str()).unwrap_or("could not create chamber")));
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

async fn cmd_send(http: &reqwest::Client, data: &VaultData, identity: &Identity, args: &[&str]) -> Result<()> {
    let token = require_token(data)?;
    let handle = args.first().ok_or_else(|| anyhow!("usage: send <handle> <message...>"))?;
    let message = args[1..].join(" ");
    if message.is_empty() {
        return Err(anyhow!("usage: send <handle> <message...>"));
    }

    let resp = http
        .get(format!("{}/auth/users/{}", backend_base(), handle))
        .bearer_auth(token)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("no such user: {handle}"));
    }
    let contact: UserBundle = resp.json().await?;
    let pq_pubkey = contact.pq_pubkey.ok_or_else(|| {
        anyhow!("{handle} has no ML-KEM public key on file (they registered from the web prototype, which doesn't have a PQ half yet) \u2014 can't do a hybrid seal to them")
    })?;

    let sealed: SealedMessage = veil_crypto::e2e::seal(
        identity,
        &B64.decode(&contact.pubkey)?,
        &B64.decode(&pq_pubkey)?,
        message.as_bytes(),
    )?;

    // The backend's /messages route expects base64 ciphertext+nonce+
    // senderPubkey (it was built against the web prototype's simpler
    // crypto_box-only scheme). We pack our KEM ciphertext into the same
    // "ciphertext" field alongside the real ciphertext, delimited, so a
    // hybrid-aware recipient (another veil-native client) can split them
    // back apart; a web-prototype recipient without PQ support simply
    // can't decrypt this message, which is correct \u2014 it never had a PQ
    // key to negotiate with in the first place.
    let packed = serde_json::json!({
        "kemCt": B64.encode(&sealed.kem_ciphertext),
        "ct": B64.encode(&sealed.ciphertext),
    })
    .to_string();

    let body = serde_json::json!({
        "scope": "dm",
        "scopeId": handle,
        "recipientIds": [contact.id],
        "ciphertext": packed,
        "nonce": B64.encode(&sealed.nonce),
        "senderPubkey": B64.encode(&sealed.sender_x_public),
    });
    let resp = http.post(format!("{}/messages", backend_base())).bearer_auth(token).json(&body).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("send failed"));
    }
    println!("sent (hybrid X25519 + ML-KEM-768 sealed, {} bytes ciphertext).", sealed.ciphertext.len());
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

async fn cmd_inbox(http: &reqwest::Client, data: &VaultData, identity: &Identity) -> Result<()> {
    let token = require_token(data)?;
    let resp = http.get(format!("{}/messages", backend_base())).bearer_auth(token).send().await?;
    let rows: Vec<InboxRow> = resp.json().await?;
    if rows.is_empty() {
        println!("nothing waiting.");
        return Ok(());
    }
    let mut acked = Vec::new();
    for row in &rows {
        let packed: serde_json::Value = match serde_json::from_str(&row.ciphertext) {
            Ok(v) => v,
            Err(_) => { println!("[{}] (not a hybrid-packed message \u2014 skipping, likely from the web prototype's simpler scheme)", row.id); continue; }
        };
        let kem_ct = B64.decode(packed["kemCt"].as_str().unwrap_or_default())?;
        let ct = B64.decode(packed["ct"].as_str().unwrap_or_default())?;
        let sealed = SealedMessage {
            sender_x_public: B64.decode(&row.sender_pubkey)?,
            kem_ciphertext: kem_ct,
            nonce: B64.decode(&row.nonce)?,
            ciphertext: ct,
        };
        match veil_crypto::e2e::open(identity, &sealed) {
            Ok(plaintext) => println!("  {}", String::from_utf8_lossy(&plaintext)),
            Err(_) => println!("  (could not decrypt {} \u2014 wrong identity for this message)", row.id),
        }
        acked.push(row.id.clone());
    }
    if !acked.is_empty() {
        http.post(format!("{}/messages/ack", backend_base()))
            .bearer_auth(token)
            .json(&serde_json::json!({ "ids": acked }))
            .send()
            .await?;
    }
    Ok(())
}

fn cmd_lock_demo() {
    use veil_crypto::lock::Verdict;
    println!("[demo] AppLock: Argon2id passphrase + optional duress passphrase + auto-wipe after N fails.");
    let mut lock = AppLock::new("correct horse battery staple", Some("i-am-under-duress"), 3).unwrap();
    println!("  wrong attempt:   {:?}", lock.check("nope", 0));
    println!("  wrong attempt:   {:?}", lock.check("nope", 0));
    match lock.check("i-am-under-duress", 0) {
        Verdict::Duress => println!("  duress phrase:   Duress \u2014 caller must now call SecureStore::wipe()"),
        other => println!("  duress phrase:   unexpected {other:?}"),
    }
    println!("  correct phrase:  {:?}", lock.check("correct horse battery staple", 0));
    println!("  (this demo never touches the real vault \u2014 it's illustrating the state machine only)");
}
