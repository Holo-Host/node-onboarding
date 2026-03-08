use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

// ── Version & path constants ───────────────────────────────────────────────────

const VERSION: &str = "5.2.6";
const STATE_FILE: &str = "/etc/node-manager/state";
const AUTH_FILE: &str = "/etc/node-manager/auth";
const PROVIDER_FILE: &str = "/etc/node-manager/provider";
const SKILLS_DIR: &str = "/etc/openclaw/skills";
const QUADLET_DIR: &str = "/etc/containers/systemd";
const WORKSPACE_DIR: &str = "/var/lib/openclaw/workspace";
const AUTHORIZED_KEYS: &str = "/home/holo/.ssh/authorized_keys";
const OPENCLAW_CONFIG: &str = "/etc/openclaw/config.toml";
const UPDATE_REPO_ENV: &str = "UPDATE_REPO";
const UPDATE_REPO_DEFAULT: &str = "holo-host/node-manager";
const SESSION_TTL_SECS: u64 = 86400;
const UPDATE_INTERVAL_SECS: u64 = 3600;

// ── OpenClaw fork abstraction ──────────────────────────────────────────────────

struct OpenClawFork {
    id:           &'static str,
    display_name: &'static str,
    repo:         &'static str,
    asset_prefix: &'static str,
    binary_name:  &'static str,
}

const OPENCLAW_FORKS: &[OpenClawFork] = &[
    OpenClawFork {
        id:           "zeroclaw",
        display_name: "ZeroClaw",
        repo:         "zeroclaw-labs/zeroclaw",
        asset_prefix: "zeroclaw",
        binary_name:  "zeroclaw",
    },
];

const ACTIVE_OPENCLAW_FORK: &str = "zeroclaw";
const OPENCLAW_UPDATE_SCRIPT: &str = "/usr/local/bin/openclaw-update.sh";

fn active_fork() -> &'static OpenClawFork {
    OPENCLAW_FORKS
        .iter()
        .find(|f| f.id == ACTIVE_OPENCLAW_FORK)
        .expect("ACTIVE_OPENCLAW_FORK must match an entry in OPENCLAW_FORKS")
}

fn patch_openclaw_update_script() {
    let fork = active_fork();
    let current = match fs::read_to_string(OPENCLAW_UPDATE_SCRIPT) {
        Ok(c) => c,
        Err(e) => { eprintln!("[openclaw] Could not read {}: {}", OPENCLAW_UPDATE_SCRIPT, e); return; }
    };
    let patched: String = current.lines().map(|line| {
        let t = line.trim_start();
        if      t.starts_with("OPENCLAW_FORK_ID=")     { format!("OPENCLAW_FORK_ID=\"{}\"",     fork.id) }
        else if t.starts_with("OPENCLAW_REPO=")         { format!("OPENCLAW_REPO=\"{}\"",         fork.repo) }
        else if t.starts_with("OPENCLAW_ASSET_PREFIX=") { format!("OPENCLAW_ASSET_PREFIX=\"{}\"", fork.asset_prefix) }
        else if t.starts_with("OPENCLAW_BINARY_NAME=")  { format!("OPENCLAW_BINARY_NAME=\"{}\"",  fork.binary_name) }
        else { line.to_string() }
    }).collect::<Vec<_>>().join("\n");
    if patched != current {
        eprintln!("[openclaw] Patching {} → fork={}", OPENCLAW_UPDATE_SCRIPT, fork.display_name);
        let _ = fs::write(OPENCLAW_UPDATE_SCRIPT, &patched);
        let _ = Command::new("chmod").args(["+x", OPENCLAW_UPDATE_SCRIPT]).output();
    }
}

// ── Embedded skill + allowed commands ─────────────────────────────────────────

const HOLO_NODE_SKILL: &str = include_str!("../holo-node.md");

const ALLOWED_COMMANDS: &str = concat!(
    r#"["ls", "cat", "grep", "find", "head", "tail", "wc", "echo", "#,
    r#""pwd", "date", "git", "#,
    r#""podman", "docker", "systemctl", "journalctl", "#,
    r#""chmod", "chown", "mkdir", "rm", "cp", "mv", "touch", "#,
    r#""df", "du", "ps", "free", "uname", "env", "which"]"#
);

// ── Shared application state ───────────────────────────────────────────────────

struct AppState {
    ap_mode:       bool,
    start_time:    SystemTime,
    sessions:      Mutex<HashMap<String, SystemTime>>,
    onboarded:     AtomicBool,
    agent_enabled: AtomicBool,
    node_name:     Mutex<String>,
    hw_mode:       Mutex<String>,
    channel:       Mutex<String>,
    provider:      Mutex<String>,
    model:         Mutex<String>,
}

impl AppState {
    fn new(ap_mode: bool) -> Self {
        let kv = read_state_file();
        AppState {
            ap_mode,
            start_time:    SystemTime::now(),
            sessions:      Mutex::new(HashMap::new()),
            onboarded:     AtomicBool::new(kv.get("onboarded").map(|v| v == "true").unwrap_or(false)),
            agent_enabled: AtomicBool::new(kv.get("agent_enabled").map(|v| v == "true").unwrap_or(false)),
            node_name:     Mutex::new(kv.get("node_name").cloned().unwrap_or_default()),
            hw_mode:       Mutex::new(kv.get("hw_mode").cloned().unwrap_or_else(|| "STANDARD".into())),
            channel:       Mutex::new(kv.get("channel").cloned().unwrap_or_default()),
            provider:      Mutex::new(kv.get("provider").cloned().unwrap_or_default()),
            model:         Mutex::new(kv.get("model").cloned().unwrap_or_default()),
        }
    }
}

// ── State file helpers ─────────────────────────────────────────────────────────

fn read_state_file() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in fs::read_to_string(STATE_FILE).unwrap_or_default().lines() {
        if let Some(eq) = line.find('=') {
            map.insert(line[..eq].trim().to_string(), line[eq + 1..].to_string());
        }
    }
    map
}

fn write_state_file(kv: &HashMap<String, String>) {
    let _ = fs::create_dir_all("/etc/node-manager");
    let content: String = kv.iter().map(|(k, v)| format!("{}={}\n", k, v)).collect();
    let _ = fs::write(STATE_FILE, content);
    let _ = Command::new("chmod").args(["600", STATE_FILE]).output();
}

fn update_state_key(key: &str, value: &str) {
    let mut kv = read_state_file();
    kv.insert(key.to_string(), value.to_string());
    write_state_file(&kv);
}

// ── Crypto / auth helpers ──────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = fs::File::open("/dev/urandom") { let _ = f.read_exact(&mut buf); }
    buf
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_password() -> String {
    let alpha: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    random_bytes(12).iter().map(|&b| alpha[(b as usize) % alpha.len()] as char).collect()
}

fn sha256_of(input: &str) -> String {
    let mut child = match Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    { Ok(c) => c, Err(_) => return String::new() };
    if let Some(mut s) = child.stdin.take() { let _ = s.write_all(input.as_bytes()); }
    let out = child.wait_with_output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    out.split_whitespace().next().unwrap_or("").to_string()
}

fn hash_password(password: &str) -> String {
    let salt = random_hex(8);
    let hash = sha256_of(&format!("{}:{}", salt, password));
    format!("sha256:{}:{}", salt, hash)
}

fn verify_password(input: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.trim().splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "sha256" { return false; }
    let actual = sha256_of(&format!("{}:{}", parts[1], input));
    !actual.is_empty() && actual == parts[2].trim()
}

fn load_or_create_auth() -> String {
    if let Ok(h) = fs::read_to_string(AUTH_FILE) {
        let h = h.trim().to_string();
        if !h.is_empty() { return h; }
    }
    let password = generate_password();
    let hash = hash_password(&password);
    let _ = fs::create_dir_all("/etc/node-manager");
    let _ = fs::write(AUTH_FILE, &hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    display_password_on_tty(&password);
    hash
}

fn get_local_ip() -> String {
    Command::new("sh")
        .args(["-c", "ip -4 addr show scope global | grep -oP '(?<=inet )\\d+\\.\\d+\\.\\d+\\.\\d+' | head -1"])
        .output().ok()
        .and_then(|o| { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if s.is_empty() { None } else { Some(s) } })
        .unwrap_or_else(|| "<node-ip>".to_string())
}

fn display_password_on_tty(password: &str) {
    let ip = get_local_ip();
    let msg = format!(
        "\x1b[2J\x1b[H\n\
         \x1b[1;36m  ╔══════════════════════════════════════════╗\n\
         \x1b[1;36m  ║      🜲  HOLO NODE SETUP                 ║\n\
         \x1b[1;36m  ╚══════════════════════════════════════════╝\x1b[0m\n\n\
         \x1b[1m  Open a browser on your local network and visit:\x1b[0m\n\
         \x1b[1;33m  http://{}:8080\x1b[0m\n\n\
         \x1b[1m  One-time setup password:\x1b[0m\n\
         \x1b[1;32m  {}\x1b[0m\n\n\
         \x1b[31m  ⚠  Write this password down. It will NOT show again.\x1b[0m\n\n",
        ip, password
    );
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty1") { let _ = tty.write_all(msg.as_bytes()); }
    let issue = format!("\n\x1b[1;36m╔═══════════════════════════════╗\x1b[0m\n\x1b[1;36m║  HOLO NODE SETUP              ║\x1b[0m\n\x1b[1;36m╚═══════════════════════════════╝\x1b[0m\n\x1b[1mURL:\x1b[0m      http://{}:8080\n\x1b[1mPassword:\x1b[0m \x1b[1;32m{}\x1b[0m\n\n", ip, password);
    let _ = fs::create_dir_all("/run/issue.d");
    let _ = fs::write("/run/issue.d/51-node-manager.issue", issue.as_bytes());
    eprintln!("[onboard] *** SETUP PASSWORD: {} | URL: http://{}:8080 ***", password, ip);
}

// ── Session management ─────────────────────────────────────────────────────────

fn create_session(state: &AppState) -> String {
    let token = random_hex(32);
    let exp = SystemTime::now() + Duration::from_secs(SESSION_TTL_SECS);
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, &mut e| SystemTime::now() < e);
    sessions.insert(token.clone(), exp);
    token
}

fn is_authenticated(req: &Req, state: &AppState) -> bool {
    let token = match get_cookie(&req.headers, "session") { Some(t) => t, None => return false };
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(&token) {
        Some(&exp) if SystemTime::now() < exp => true,
        Some(_) => { sessions.remove(&token); false }
        None => false,
    }
}

fn session_cookie(token: &str) -> String { format!("session={}; HttpOnly; SameSite=Strict; Path=/", token) }
fn clear_cookie() -> String { "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string() }

// ── SSH key management ─────────────────────────────────────────────────────────

fn read_ssh_keys() -> Vec<String> {
    fs::read_to_string(AUTHORIZED_KEYS).unwrap_or_default()
        .lines().map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
}

fn write_ssh_keys(keys: &[String]) -> Result<(), String> {
    let _ = fs::create_dir_all("/home/holo/.ssh");
    fs::write(AUTHORIZED_KEYS, keys.join("\n") + "\n").map_err(|e| e.to_string())?;
    let _ = Command::new("chown").args(["-R", "holo:holo", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["700", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["600", AUTHORIZED_KEYS]).output();
    Ok(())
}

fn is_valid_ssh_pubkey(key: &str) -> bool {
    let k = key.trim();
    k.starts_with("ssh-ed25519 ") || k.starts_with("ssh-rsa ") || k.starts_with("ecdsa-sha2-") || k.starts_with("sk-ssh-")
}

// ── Image resolvers ────────────────────────────────────────────────────────────

fn detect_arch() -> String {
    Command::new("uname").arg("-m").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string())
}

fn resolve_image(image_ref: &str, arm64_prefix: &str) -> String {
    let arch = detect_arch();
    if arch != "aarch64" { return format!("{}:latest", image_ref); }
    let manifest = Command::new("skopeo")
        .args(["inspect", "--raw", &format!("docker://{}:latest", image_ref)])
        .output().ok().filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if manifest.contains("arm64") || manifest.contains("aarch64") { return format!("{}:latest", image_ref); }
    let repo_path = image_ref.trim_start_matches("ghcr.io/");
    let token_json = Command::new("curl")
        .args(["-sf", &format!("https://ghcr.io/token?scope=repository:{}:pull&service=ghcr.io", repo_path)])
        .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let token = extract_json_str(&token_json, "token");
    if token.is_empty() { return format!("{}:latest", image_ref); }
    let tags_json = Command::new("curl")
        .args(["-sf", "-H", &format!("Authorization: Bearer {}", token),
            &format!("https://ghcr.io/v2/{}/tags/list", repo_path)])
        .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    match pick_arm64_tag(&tags_json, arm64_prefix) {
        Some(tag) => format!("{}:{}", image_ref, tag),
        None => format!("{}:latest", image_ref),
    }
}

fn resolve_edgenode_image() -> String { resolve_image("ghcr.io/holo-host/edgenode", "latest-hc") }
fn resolve_wind_tunnel_image() -> String { resolve_image("ghcr.io/holochain/wind-tunnel-runner", "latest-") }

fn extract_json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].trim_start();
    if after.starts_with('"') { let inner = &after[1..]; &inner[..inner.find('"').unwrap_or(0)] } else { "" }
}

fn pick_arm64_tag(tags_json: &str, prefix: &str) -> Option<String> {
    let start = tags_json.find('[')?; let end = tags_json.rfind(']')?;
    let array = &tags_json[start + 1..end];
    let mut candidates = Vec::new();
    let mut rest = array;
    while let Some(q1) = rest.find('"') {
        let after = &rest[q1 + 1..];
        if let Some(q2) = after.find('"') {
            let tag = &after[..q2];
            if tag.starts_with(prefix) && tag != "latest" { candidates.push(tag.to_string()); }
            rest = &after[q2 + 1..];
        } else { break; }
    }
    candidates.sort_by(|a, b| b.cmp(a));
    candidates.into_iter().next()
}

// ── Quadlet builders ───────────────────────────────────────────────────────────

fn build_edgenode_quadlet(image: &str) -> String {
    format!("[Unit]\nDescription=Holo EdgeNode\nAfter=network-online.target\nConflicts=wind-tunnel.service\n\n[Container]\nImage={image}\nContainerName=edgenode\nVolume=/var/lib/edgenode:/data:Z\nLabel=io.containers.autoupdate=registry\n\n[Service]\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n", image=image)
}

fn build_wind_tunnel_quadlet(hostname: &str, image: &str) -> String {
    format!("[Unit]\nDescription=Holochain Wind Tunnel Runner\nAfter=network-online.target\nConflicts=edgenode.service\n\n[Container]\nImage={image}\nContainerName=wind-tunnel\nHostName={hostname}\nNetwork=host\nPodmanArgs=--cgroupns=host --privileged\nLabel=io.containers.autoupdate=registry\n\n[Service]\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n", hostname=hostname, image=image)
}

// ── Channel config functions ───────────────────────────────────────────────────

/// Core channel TOML builder. `get` maps a clean field name (e.g. "bot_token") to its value.
/// Used by both build_channel_toml (onboarding, prefixed keys) and
/// build_channel_section (manage endpoint, clean keys).
fn build_channel_from_resolver<F>(channel_type: &str, get: F) -> String
where F: Fn(&str) -> String
{
    macro_rules! e { ($k:expr) => { toml_escape(&get($k)) } }
    macro_rules! a { ($k:expr) => { csv_to_toml_array(&get($k)) } }
    macro_rules! p { ($k:expr, $d:expr) => { get($k).parse::<u16>().unwrap_or($d) } }
    macro_rules! opt_str { ($buf:expr, $k:expr, $toml_key:expr) => {
        let v = get($k); if !v.is_empty() { $buf.push_str(&format!("{} = \"{}\"\n", $toml_key, toml_escape(&v))); }
    } }

    match channel_type {
        "cli" => String::new(), // handled via inject_cli_into_config

        "telegram" => format!(
            "[channels_config.telegram]\nbot_token = \"{}\"\nallowed_users = {}\n",
            e!("bot_token"), a!("allowed_users")
        ),

        "discord" => {
            let mut t = format!(
                "[channels_config.discord]\nbot_token = \"{}\"\nallowed_users = {}\n",
                e!("bot_token"), a!("allowed_users")
            );
            opt_str!(t, "guild_id", "guild_id");
            t
        },

        "slack" => format!(
            "[channels_config.slack]\nbot_token = \"{}\"\napp_token = \"{}\"\nallowed_users = {}\n",
            e!("bot_token"), e!("app_token"), a!("allowed_users")
        ),

        "mattermost" => format!(
            "[channels_config.mattermost]\nurl = \"{}\"\nbot_token = \"{}\"\nchannel_id = \"{}\"\nallowed_users = {}\n",
            e!("url"), e!("bot_token"), e!("channel_id"), a!("allowed_users")
        ),

        "matrix" => {
            let mut t = format!(
                "[channels_config.matrix]\nhomeserver = \"{}\"\naccess_token = \"{}\"\nroom_id = \"{}\"\nallowed_users = {}\n",
                e!("homeserver"), e!("access_token"), e!("room_id"), a!("allowed_users")
            );
            opt_str!(t, "user_id",   "user_id");
            opt_str!(t, "device_id", "device_id");
            t
        },

        "signal" => {
            let mut t = format!(
                "[channels_config.signal]\nhttp_url = \"{}\"\naccount = \"{}\"\nallowed_from = {}\n",
                e!("http_url"), e!("account"), a!("allowed_from")
            );
            opt_str!(t, "group_id", "group_id");
            t
        },

        "whatsapp" => format!(
            "[channels_config.whatsapp]\naccess_token = \"{}\"\nphone_number_id = \"{}\"\nverify_token = \"{}\"\nallowed_numbers = {}\n",
            e!("access_token"), e!("phone_number_id"), e!("verify_token"), a!("allowed_numbers")
        ),

        "webhook" => {
            let port = p!("port", 8080);
            let mut t = format!("[channels_config.webhook]\nport = {}\n", port);
            opt_str!(t, "secret", "secret");
            t
        },

        "email" => format!(
            "[channels_config.email]\nimap_host = \"{}\"\nimap_port = {}\nimap_folder = \"INBOX\"\nsmtp_host = \"{}\"\nsmtp_port = {}\nsmtp_tls = true\nusername = \"{}\"\npassword = \"{}\"\nfrom_address = \"{}\"\npoll_interval_secs = 60\nallowed_senders = {}\n",
            e!("imap_host"), p!("imap_port", 993),
            e!("smtp_host"), p!("smtp_port", 465),
            e!("username"), e!("password"), e!("from_address"),
            a!("allowed_senders")
        ),

        "irc" => {
            let irc_channels = csv_to_toml_array(&get("channels"));
            let mut t = format!(
                "[channels_config.irc]\nserver = \"{}\"\nport = {}\nnickname = \"{}\"\nchannels = {}\nallowed_users = {}\nverify_tls = true\n",
                e!("server"), p!("port", 6697), e!("nickname"), irc_channels, a!("allowed_users")
            );
            opt_str!(t, "server_password",   "server_password");
            opt_str!(t, "nickserv_password",  "nickserv_password");
            opt_str!(t, "sasl_password",      "sasl_password");
            t
        },

        "lark" => {
            let rm = get("receive_mode");
            let rm_val = if rm == "webhook" { "webhook" } else { "websocket" };
            let mut t = format!(
                "[channels_config.lark]\napp_id = \"{}\"\napp_secret = \"{}\"\nallowed_users = {}\nreceive_mode = \"{}\"\n",
                e!("app_id"), e!("app_secret"), a!("allowed_users"), rm_val
            );
            if rm_val == "webhook" { t.push_str(&format!("port = {}\n", p!("port", 8081))); }
            opt_str!(t, "encrypt_key",         "encrypt_key");
            opt_str!(t, "verification_token",  "verification_token");
            t
        },

        "feishu" => {
            let rm = get("receive_mode");
            let rm_val = if rm == "webhook" { "webhook" } else { "websocket" };
            let mut t = format!(
                "[channels_config.feishu]\napp_id = \"{}\"\napp_secret = \"{}\"\nallowed_users = {}\nreceive_mode = \"{}\"\n",
                e!("app_id"), e!("app_secret"), a!("allowed_users"), rm_val
            );
            if rm_val == "webhook" { t.push_str(&format!("port = {}\n", p!("port", 8081))); }
            opt_str!(t, "encrypt_key",        "encrypt_key");
            opt_str!(t, "verification_token", "verification_token");
            t
        },

        "nostr" => {
            let mut t = format!(
                "[channels_config.nostr]\nprivate_key = \"{}\"\nallowed_pubkeys = {}\n",
                e!("private_key"), a!("allowed_pubkeys")
            );
            let relays = get("relays");
            if !relays.is_empty() { t.push_str(&format!("relays = {}\n", csv_to_toml_array(&relays))); }
            t
        },

        "dingtalk" => format!(
            "[channels_config.dingtalk]\nclient_id = \"{}\"\nclient_secret = \"{}\"\nallowed_users = {}\n",
            e!("client_id"), e!("client_secret"), a!("allowed_users")
        ),

        "qq" => format!(
            "[channels_config.qq]\napp_id = \"{}\"\napp_secret = \"{}\"\nallowed_users = {}\n",
            e!("app_id"), e!("app_secret"), a!("allowed_users")
        ),

        "nextcloud_talk" => {
            let mut t = format!(
                "[channels_config.nextcloud_talk]\nbase_url = \"{}\"\napp_token = \"{}\"\nallowed_users = {}\n",
                e!("base_url"), e!("app_token"), a!("allowed_users")
            );
            opt_str!(t, "webhook_secret", "webhook_secret");
            t
        },

        "linq" => {
            let mut t = format!(
                "[channels_config.linq]\napi_token = \"{}\"\nfrom_phone = \"{}\"\nallowed_senders = {}\n",
                e!("api_token"), e!("from_phone"), a!("allowed_senders")
            );
            opt_str!(t, "signing_secret", "signing_secret");
            t
        },

        "imessage" => format!(
            "[channels_config.imessage]\nallowed_contacts = {}\n",
            a!("allowed_contacts")
        ),

        _ => String::new(),
    }
}

/// Build channel TOML for onboarding submission.
/// Onboarding sends field names prefixed with channel type: `{channel_type}_{field}`.
fn build_channel_toml(body: &str, channel: &str) -> String {
    if channel == "cli" {
        return String::new();
    }
    let pfx = channel.to_string();
    build_channel_from_resolver(channel, move |field| {
        json_str(body, &format!("{}_{}", pfx, field)).to_string()
    })
}

/// Build channel TOML for the /manage/channels/add endpoint.
/// Expects clean field names in the JSON body alongside `channel_type`.
fn build_channel_section(channel_type: &str, body: &str) -> String {
    build_channel_from_resolver(channel_type, |field| json_str(body, field).to_string())
}

/// Return list of channel names configured in config.toml.
fn list_configured_channels(config: &str) -> Vec<String> {
    let mut channels = Vec::new();
    let mut in_channels_root = false;
    for line in config.lines() {
        let t = line.trim();
        if t == "[channels_config]" { in_channels_root = true; continue; }
        if t.starts_with('[') { in_channels_root = false; }
        if in_channels_root && (t == "cli = true" || t == "cli=true") {
            if !channels.contains(&"cli".to_string()) { channels.insert(0, "cli".to_string()); }
        }
        if t.starts_with("[channels_config.") && t.ends_with(']') {
            let name = t["[channels_config.".len()..t.len()-1].to_string();
            channels.push(name);
        }
    }
    channels
}

/// Extract all channel config sections (including cli) to reapply after openclaw onboard
/// rewrites config.toml with a fresh skeleton.
fn extract_channel_config(config: &str) -> String {
    let mut result = String::new();
    let mut cli_present = false;
    let mut in_channels_root = false;
    let mut in_channel_sub = false;

    for line in config.lines() {
        let t = line.trim();
        if t == "[channels_config]" { in_channels_root = true; in_channel_sub = false; continue; }
        if t.starts_with("[channels_config.") && t.ends_with(']') {
            in_channels_root = false; in_channel_sub = true;
        } else if t.starts_with('[') && !t.starts_with("[[") {
            in_channels_root = false; in_channel_sub = false;
        }
        if in_channels_root && (t == "cli = true" || t == "cli=true") { cli_present = true; }
        if in_channel_sub { result.push_str(line); result.push('\n'); }
    }

    let mut out = String::new();
    if cli_present { out.push_str("\n[channels_config]\ncli = true\n\n"); }
    out.push_str(&result);
    out
}

/// Extract a quoted string value from a TOML section.
/// e.g. extract_toml_value(config, "channels_config.telegram", "bot_token") → "abc123"
fn extract_toml_value(config: &str, section: &str, key: &str) -> String {
    let target = format!("[{}]", section);
    let mut in_section = false;
    for line in config.lines() {
        let t = line.trim();
        if t == target { in_section = true; continue; }
        if in_section && t.starts_with('[') { break; }
        if in_section && t.starts_with(key) {
            if let Some(eq) = t.find('=') {
                let val = t[eq + 1..].trim().trim_matches('"');
                return val.to_string();
            }
        }
    }
    String::new()
}

/// Extract a TOML array value as comma-separated string.
/// e.g. extract_toml_array(config, "channels_config.telegram", "allowed_users") → "123,456"
fn extract_toml_array_first(config: &str, section: &str, key: &str) -> String {
    let target = format!("[{}]", section);
    let mut in_section = false;
    for line in config.lines() {
        let t = line.trim();
        if t == target { in_section = true; continue; }
        if in_section && t.starts_with('[') { break; }
        if in_section && t.starts_with(key) {
            if let Some(start) = t.find('[') {
                if let Some(end) = t.find(']') {
                    let inner = &t[start + 1..end];
                    // Return first non-wildcard entry
                    for item in inner.split(',') {
                        let item = item.trim().trim_matches('"').trim();
                        if !item.is_empty() && item != "*" { return item.to_string(); }
                    }
                    // If only wildcard, return it
                    return inner.trim().trim_matches('"').trim().to_string();
                }
            }
        }
    }
    String::new()
}

/// Remove a channel section from config.toml by channel name.
fn remove_channel_from_config(config: &str, channel_name: &str) -> String {
    if channel_name == "cli" {
        return config.lines()
            .filter(|l| { let t = l.trim(); t != "cli = true" && t != "cli=true" })
            .collect::<Vec<_>>().join("\n");
    }
    let target = format!("[channels_config.{}]", channel_name);
    let mut out: Vec<&str> = Vec::new();
    let mut skip = false;
    for line in config.lines() {
        let t = line.trim();
        if t == target { skip = true; continue; }
        if skip && t.starts_with('[') && !t.starts_with("[[") { skip = false; }
        if !skip { out.push(line); }
    }
    out.join("\n")
}

/// Add (or replace) a channel section in config.toml.
fn add_channel_to_config(config: &str, channel_type: &str, channel_toml: &str) -> String {
    let cleaned = remove_channel_from_config(config, channel_type);
    if channel_type == "cli" {
        // Inject cli=true under [channels_config] section
        let mut out = Vec::new();
        let mut added = false;
        for line in cleaned.lines() {
            out.push(line.to_string());
            if line.trim() == "[channels_config]" && !added {
                out.push("cli = true".to_string());
                added = true;
            }
        }
        if !added { out.push("\n[channels_config]\ncli = true".to_string()); }
        return out.join("\n");
    }
    let mut result = cleaned.trim_end().to_string();
    result.push_str("\n\n");
    result.push_str(channel_toml.trim());
    result.push('\n');
    result
}

fn channel_display_name(name: &str) -> &str {
    match name {
        "cli"            => "CLI",
        "telegram"       => "Telegram",
        "discord"        => "Discord",
        "slack"          => "Slack",
        "mattermost"     => "Mattermost",
        "matrix"         => "Matrix",
        "signal"         => "Signal",
        "whatsapp"       => "WhatsApp",
        "webhook"        => "Webhook",
        "email"          => "Email",
        "irc"            => "IRC",
        "lark"           => "Lark",
        "feishu"         => "Feishu",
        "nostr"          => "Nostr",
        "dingtalk"       => "DingTalk",
        "qq"             => "QQ",
        "nextcloud_talk" => "Nextcloud Talk",
        "linq"           => "Linq",
        "imessage"       => "iMessage",
        _                => name,
    }
}

fn channel_icon(name: &str) -> &'static str {
    match name {
        "cli"            => "💻",
        "telegram"       => "✈️",
        "discord"        => "🎮",
        "slack"          => "💼",
        "mattermost"     => "🔵",
        "matrix"         => "🔷",
        "signal"         => "🔒",
        "whatsapp"       => "💬",
        "webhook"        => "🔗",
        "email"          => "📧",
        "irc"            => "🖥️",
        "lark"           => "🦅",
        "feishu"         => "🪶",
        "nostr"          => "⚡",
        "dingtalk"       => "🔔",
        "qq"             => "🐧",
        "nextcloud_talk" => "☁️",
        "linq"           => "📱",
        "imessage"       => "🍎",
        _                => "💬",
    }
}

// ── OpenClaw config patching ───────────────────────────────────────────────────

fn patch_openclaw_config(config: &str, level: &str) -> String {
    let mut out = String::with_capacity(config.len() + 512);
    let mut lines = config.lines().peekable();
    let mut in_skills = false;
    let mut skills_dir_written = false;
    let mut skills_section_seen = false;

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("allowed_commands") {
            out.push_str("allowed_commands = "); out.push_str(ALLOWED_COMMANDS); out.push('\n');
            if !trimmed.contains(']') { for cont in lines.by_ref() { if cont.contains(']') { break; } } }
            continue;
        }
        if trimmed.starts_with("level = ") { out.push_str(&format!("level = \"{level}\"\n")); continue; }
        if trimmed.starts_with("allowed_roots") {
            out.push_str(&format!("allowed_roots = [\"{WORKSPACE_DIR}\"]\n"));
            if !trimmed.contains(']') { for cont in lines.by_ref() { if cont.contains(']') { break; } } }
            continue;
        }
        if trimmed.starts_with("require_pairing") { out.push_str("require_pairing = false\n"); continue; }
        if trimmed == "[skills]" {
            in_skills = true; skills_section_seen = true;
            out.push_str(line); out.push('\n'); continue;
        }
        if in_skills {
            if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
                if !skills_dir_written { out.push_str(&format!("open_skills_dir = \"{SKILLS_DIR}\"\n")); }
                in_skills = false;
            } else {
                if trimmed.starts_with("open_skills_enabled") { out.push_str("open_skills_enabled = true\n"); continue; }
                if trimmed.starts_with("open_skills_dir") {
                    out.push_str(&format!("open_skills_dir = \"{SKILLS_DIR}\"\n")); skills_dir_written = true; continue;
                }
                out.push_str(line); out.push('\n'); continue;
            }
        }
        out.push_str(line); out.push('\n');
    }
    if in_skills && !skills_dir_written { out.push_str(&format!("open_skills_dir = \"{SKILLS_DIR}\"\n")); }
    if !skills_section_seen { out.push_str(&format!("\n[skills]\nopen_skills_enabled = true\nopen_skills_dir = \"{SKILLS_DIR}\"\n")); }
    out
}

// ── Welcome message (Telegram / Discord / Slack) ───────────────────────────────

fn send_welcome_message(channel: &str, body: &str, hw_mode: &str) {
    let mode_desc = if hw_mode == "WIND_TUNNEL" { "Holochain Wind Tunnel stress-test runner" } else { "Holo EdgeNode — always-on Holochain peer" };
    let welcome = format!("Your Holo Node is online!\n\nI'm your on-device AI agent.\n\nCurrent mode: {}\n\nTry asking me:\n• what containers are running?\n• show me the node health\n• switch to wind tunnel mode\n\nI'll always ask for your approval before taking action.", mode_desc);
    fn je(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n") }
    match channel {
        "telegram" => {
            let tok = json_str(body, "telegram_bot_token");
            let uid_raw = json_str(body, "telegram_allowed_users");
            let uid = uid_raw.split(',').next().unwrap_or("").trim();
            if tok.is_empty() || uid.is_empty() || uid == "*" { return; }
            let payload = format!("{{\"chat_id\":\"{}\",\"text\":\"{}\"}}", uid, je(&welcome));
            let _ = Command::new("curl").args(["-sf", "-X", "POST",
                &format!("https://api.telegram.org/bot{}/sendMessage", tok),
                "-H", "Content-Type: application/json", "-d", &payload]).output();
        },
        "discord" => {
            let tok = json_str(body, "discord_bot_token");
            let uid = json_str(body, "discord_allowed_users").split(',').next().unwrap_or("").trim().to_string();
            if tok.is_empty() || uid.is_empty() || uid == "*" { return; }
            let ch_payload = format!("{{\"recipient_id\":\"{}\"}}", uid);
            let ch_out = Command::new("curl").args(["-sf", "-X", "POST",
                "https://discord.com/api/v10/users/@me/channels",
                "-H", "Content-Type: application/json",
                "-H", &format!("Authorization: Bot {}", tok), "-d", &ch_payload])
                .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
            let dm_id = extract_json_str(&ch_out, "id");
            if dm_id.is_empty() { return; }
            let msg = format!("{{\"content\":\"{}\"}}", je(&welcome));
            let _ = Command::new("curl").args(["-sf", "-X", "POST",
                &format!("https://discord.com/api/v10/channels/{}/messages", dm_id),
                "-H", "Content-Type: application/json",
                "-H", &format!("Authorization: Bot {}", tok), "-d", &msg]).output();
        },
        "slack" => {
            let tok = json_str(body, "slack_bot_token");
            let uid = json_str(body, "slack_allowed_users").split(',').next().unwrap_or("").trim().to_string();
            if tok.is_empty() || uid.is_empty() || uid == "*" { return; }
            let payload = format!("{{\"channel\":\"{}\",\"text\":\"{}\"}}", uid, je(&welcome));
            let _ = Command::new("curl").args(["-sf", "-X", "POST",
                "https://slack.com/api/chat.postMessage",
                "-H", "Content-Type: application/json",
                "-H", &format!("Authorization: Bearer {}", tok), "-d", &payload]).output();
        },
        other => eprintln!("[onboard] Welcome message not implemented for channel: {}", other),
    }
}

/// Send a notification message to all configured chat channels.
/// Reads credentials from config.toml rather than from a request body.
/// Used by /manage handlers to confirm changes or report errors.
fn send_manage_notification(message: &str) {
    let config = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c) => c,
        Err(_) => return,
    };
    let channels = list_configured_channels(&config);
    if channels.is_empty() { return; }

    fn je(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n") }
    let escaped = je(message);

    for ch in &channels {
        match ch.as_str() {
            "telegram" => {
                let tok = extract_toml_value(&config, "channels_config.telegram", "bot_token");
                let uid = extract_toml_array_first(&config, "channels_config.telegram", "allowed_users");
                if tok.is_empty() || uid.is_empty() || uid == "*" { continue; }
                let payload = format!("{{\"chat_id\":\"{}\",\"text\":\"{}\",\"parse_mode\":\"Markdown\"}}", uid, escaped);
                let _ = Command::new("curl").args(["-sf", "-X", "POST",
                    &format!("https://api.telegram.org/bot{}/sendMessage", tok),
                    "-H", "Content-Type: application/json", "-d", &payload]).output();
            },
            "discord" => {
                let tok = extract_toml_value(&config, "channels_config.discord", "bot_token");
                let uid = extract_toml_array_first(&config, "channels_config.discord", "allowed_users");
                if tok.is_empty() || uid.is_empty() || uid == "*" { continue; }
                let ch_payload = format!("{{\"recipient_id\":\"{}\"}}", uid);
                let ch_out = Command::new("curl").args(["-sf", "-X", "POST",
                    "https://discord.com/api/v10/users/@me/channels",
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bot {}", tok), "-d", &ch_payload])
                    .output().ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
                let dm_id = extract_json_str(&ch_out, "id");
                if dm_id.is_empty() { continue; }
                let msg = format!("{{\"content\":\"{}\"}}", escaped);
                let _ = Command::new("curl").args(["-sf", "-X", "POST",
                    &format!("https://discord.com/api/v10/channels/{}/messages", dm_id),
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bot {}", tok), "-d", &msg]).output();
            },
            "slack" => {
                let tok = extract_toml_value(&config, "channels_config.slack", "bot_token");
                let uid = extract_toml_array_first(&config, "channels_config.slack", "allowed_users");
                if tok.is_empty() || uid.is_empty() || uid == "*" { continue; }
                let payload = format!("{{\"channel\":\"{}\",\"text\":\"{}\"}}", uid, escaped);
                let _ = Command::new("curl").args(["-sf", "-X", "POST",
                    "https://slack.com/api/chat.postMessage",
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bearer {}", tok), "-d", &payload]).output();
            },
            "matrix" => {
                let hs = extract_toml_value(&config, "channels_config.matrix", "homeserver");
                let token = extract_toml_value(&config, "channels_config.matrix", "access_token");
                let room = extract_toml_value(&config, "channels_config.matrix", "room_id");
                if hs.is_empty() || token.is_empty() || room.is_empty() { continue; }
                let txn_id = random_hex(8);
                let room_encoded = room.replace('!', "%21").replace(':', "%3A");
                let url = format!("{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}", hs, room_encoded, txn_id);
                let payload = format!("{{\"msgtype\":\"m.text\",\"body\":\"{}\"}}", escaped);
                let _ = Command::new("curl").args(["-sf", "-X", "PUT", &url,
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bearer {}", token), "-d", &payload]).output();
            },
            "mattermost" => {
                let base_url = extract_toml_value(&config, "channels_config.mattermost", "url");
                let tok = extract_toml_value(&config, "channels_config.mattermost", "bot_token");
                let channel_id = extract_toml_value(&config, "channels_config.mattermost", "channel_id");
                if base_url.is_empty() || tok.is_empty() || channel_id.is_empty() { continue; }
                let payload = format!("{{\"channel_id\":\"{}\",\"message\":\"{}\"}}", channel_id, escaped);
                let _ = Command::new("curl").args(["-sf", "-X", "POST",
                    &format!("{}/api/v4/posts", base_url),
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bearer {}", tok), "-d", &payload]).output();
            },
            "cli" => { /* CLI users see changes on next interaction — no push needed */ },
            other => {
                eprintln!("[notify] Push notification not yet implemented for channel: {}", other);
            },
        }
    }
}

/// Fire-and-forget notification on a background thread (so handlers don't block on curl).
fn notify_async(message: String) {
    thread::spawn(move || {
        send_manage_notification(&message);
    });
}

// ── Self-update ────────────────────────────────────────────────────────────────

fn check_and_apply_update(repo: &str) {
    eprintln!("[update] Checking {} (current: v{})", repo, VERSION);
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let json = match Command::new("curl").args(["-sf", "-H", "Accept: application/vnd.github+json", "-H", "User-Agent: holo-node-manager", &api_url]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => { eprintln!("[update] Could not reach GitHub Releases API"); return; }
    };
    let tag = extract_json_str(&json, "tag_name");
    if tag.is_empty() { eprintln!("[update] Could not parse tag_name"); return; }
    let tag_ver = tag.trim_start_matches('v');
    if tag_ver == VERSION { eprintln!("[update] Already at v{}", VERSION); return; }
    eprintln!("[update] New version: {} (have: {})", tag_ver, VERSION);
    let arch = detect_arch();
    let asset_name = format!("node-manager-{}", arch);
    let download_url = find_asset_download_url(&json, &asset_name);
    if download_url.is_empty() { eprintln!("[update] No asset '{}' in release {}", asset_name, tag); return; }
    let tmp = "/usr/local/bin/node-manager-update";
    let ok = Command::new("curl").args(["-sfL", "-o", tmp, &download_url]).output().map(|o| o.status.success()).unwrap_or(false);
    if !ok { eprintln!("[update] Download failed"); return; }
    let _ = Command::new("chmod").args(["+x", tmp]).output();
    let self_path = env::current_exe().unwrap_or_else(|_| "/usr/local/bin/node-manager".into());
    if let Err(e) = fs::rename(tmp, &self_path) { eprintln!("[update] Replace failed: {}", e); return; }
    eprintln!("[update] Binary replaced. Restarting...");
    let _ = Command::new("systemctl").args(["restart", "node-manager.service"]).output();
}

fn find_asset_download_url(release_json: &str, asset_name: &str) -> String {
    let needle = format!("\"name\":\"{}\"", asset_name);
    let pos = match release_json.find(&needle) { Some(p) => p, None => return String::new() };
    let url_key = "\"browser_download_url\":\"";
    let window = &release_json[pos..];
    let url_pos = match window.find(url_key) { Some(p) => p, None => return String::new() };
    let after = &window[url_pos + url_key.len()..];
    after[..after.find('"').unwrap_or(0)].to_string()
}

fn spawn_update_checker(repo: String) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(90));
        loop { check_and_apply_update(&repo); thread::sleep(Duration::from_secs(UPDATE_INTERVAL_SECS)); }
    });
}

// ── Node operations ────────────────────────────────────────────────────────────

struct ProviderConfig { id: String, model: String, key: String }

fn make_provider_config(provider: &str, model: &str, api_key: &str, api_url: &str) -> Option<ProviderConfig> {
    let (id, mdl, key) = match provider {
        "google"     => ("google".into(), if model.is_empty() { "gemini-2.5-flash".into() } else { model.into() }, api_key.into()),
        "anthropic"  => ("anthropic".into(), if model.is_empty() { "claude-haiku-4-5-20251001".into() } else { model.into() }, api_key.into()),
        "openai"     => ("openai".into(), if model.is_empty() { "gpt-4o-mini".into() } else { model.into() }, api_key.into()),
        "openrouter" => ("openrouter".into(), if model.is_empty() { "openrouter/auto".into() } else { model.into() }, api_key.into()),
        "ollama"     => {
            let url = if api_url.is_empty() { "http://127.0.0.1:11434" } else { api_url };
            (format!("custom:{}", url), if model.is_empty() { "llama3.2".into() } else { model.into() }, "ollama".into())
        },
        _ => return None,
    };
    Some(ProviderConfig { id, model: mdl, key })
}

/// Ensure the openclaw binary is present, triggering the update service if not.
/// Returns Err with a message if the binary still can't be found after attempting install.
fn ensure_openclaw_binary(stream: &mut TcpStream) -> bool {
    if Path::new("/usr/local/bin/openclaw").exists() { return true; }
    eprintln!("[onboard] openclaw binary missing — triggering openclaw-update.service");
    match Command::new("systemctl").args(["start", "--wait", "openclaw-update.service"]).output() {
        Ok(o) if o.status.success() => {
            eprintln!("[onboard] openclaw-update.service completed");
            if Path::new("/usr/local/bin/openclaw").exists() { return true; }
            eprintln!("[onboard] Binary still absent after update service");
            send_json_err(stream, 500, "openclaw binary not found after install attempt");
            false
        },
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            eprintln!("[onboard] openclaw-update.service failed: {}", err.trim());
            send_json_err(stream, 500, "failed to install openclaw agent binary — check journalctl -u openclaw-update.service");
            false
        },
        Err(e) => {
            eprintln!("[onboard] could not start openclaw-update.service: {}", e);
            send_json_err(stream, 500, "could not start openclaw-update.service");
            false
        }
    }
}

fn run_openclaw_onboard(pv: &ProviderConfig) -> Result<(), String> {
    match Command::new("/usr/local/bin/openclaw")
        .args(["--config-dir", "/etc/openclaw", "onboard", "--force", "--memory", "sqlite",
               "--provider", &pv.id, "--model", &pv.model, "--api-key", &pv.key])
        .env("HOME", "/root").output()
    {
        Err(e)                       => Err(format!("openclaw binary not found: {}", e)),
        Ok(o) if !o.status.success() => {
            let err = String::from_utf8_lossy(&o.stderr);
            Err(format!("openclaw onboard failed: {}", err.replace('"', "'").replace('\n', " ").chars().take(200).collect::<String>()))
        },
        Ok(_) => Ok(()),
    }
}

fn apply_hardware_mode(new_mode: &str, state: &AppState) {
    let current = state.hw_mode.lock().unwrap().clone();
    let stop_svc  = if current == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };
    let start_svc = if new_mode == "WIND_TUNNEL"  { "wind-tunnel.service" } else { "edgenode.service" };
    let _ = fs::write(format!("{}/mode_switch.txt", WORKSPACE_DIR), new_mode);
    if current != new_mode {
        eprintln!("[manage] Stopping {} → starting {}", stop_svc, start_svc);
        let _ = Command::new("systemctl").args(["stop",  stop_svc]).output();
        let _ = Command::new("systemctl").args(["start", start_svc]).output();
    }
    *state.hw_mode.lock().unwrap() = new_mode.to_string();
    update_state_key("hw_mode", new_mode);
}

fn write_openclaw_env(provider: &str, api_key: &str) {
    let dropin_dir = "/etc/systemd/system/openclaw-daemon.service.d";
    let conf_path  = format!("{}/api-key.conf", dropin_dir);
    let env_var = match provider {
        "openrouter" => "OPENROUTER_API_KEY",
        "openai"     => "OPENAI_API_KEY",
        "anthropic"  => "ANTHROPIC_API_KEY",
        "google"     => "GEMINI_API_KEY",
        _ => { let _ = fs::remove_file(&conf_path); let _ = Command::new("systemctl").args(["daemon-reload"]).output(); return; }
    };
    let _ = fs::create_dir_all(dropin_dir);
    let _ = fs::write(&conf_path, format!("[Service]\nEnvironment=\"{}={}\"\n", env_var, api_key));
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();
}

// ── Config safety: backup, validate, rollback ──────────────────────────────────

fn backup_config() {
    let bak = format!("{}.bak", OPENCLAW_CONFIG);
    if Path::new(OPENCLAW_CONFIG).exists() {
        let _ = fs::copy(OPENCLAW_CONFIG, &bak);
        let _ = Command::new("chmod").args(["600", &bak]).output();
    }
}

fn rollback_config() {
    let bak = format!("{}.bak", OPENCLAW_CONFIG);
    if Path::new(&bak).exists() {
        let _ = fs::copy(&bak, OPENCLAW_CONFIG);
        let _ = Command::new("chmod").args(["600", OPENCLAW_CONFIG]).output();
        eprintln!("[config] Rolled back to {}", bak);
    }
}

/// Structural validation — catches duplicate section headers and malformed
/// headers, which are the class of errors that string-based TOML manipulation
/// can introduce. This is NOT a full TOML parser.
fn validate_toml_structure(config: &str) -> Result<(), String> {
    let mut sections: Vec<String> = Vec::new();
    for (i, line) in config.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        // Table header (not array-of-tables [[...]])
        if t.starts_with('[') && !t.starts_with("[[") {
            if !t.ends_with(']') {
                return Err(format!("line {}: malformed section header: {}", i + 1, t));
            }
            let header = t.to_string();
            if sections.contains(&header) {
                return Err(format!("line {}: duplicate section {}", i + 1, header));
            }
            sections.push(header);
        }
    }
    Ok(())
}

/// Insert content immediately after the [channels_config] section and its
/// direct keys, before the next unrelated section header. This keeps channel
/// sub-sections (e.g. [channels_config.telegram]) contiguous with their
/// parent table, which ZeroClaw's config parser requires.
fn insert_after_channels_section(config: &str, content: &str) -> String {
    let trimmed_content = content.trim();
    if trimmed_content.is_empty() { return config.to_string(); }

    let mut out = String::with_capacity(config.len() + trimmed_content.len() + 4);
    let mut found_channels = false;
    let mut inserted = false;

    for line in config.lines() {
        let t = line.trim();

        if t == "[channels_config]" {
            found_channels = true;
            out.push_str(line);
            out.push('\n');
            continue;
        }

        // We passed [channels_config] and its keys; now we hit a new unrelated section.
        // Insert the channel sub-sections here, right before this next header.
        if found_channels && !inserted
            && t.starts_with('[') && !t.starts_with("[[")
            && !t.starts_with("[channels_config")
        {
            out.push_str(trimmed_content);
            out.push_str("\n\n");
            inserted = true;
        }

        out.push_str(line);
        out.push('\n');
    }

    // Edge case: [channels_config] was the last section in the file
    if found_channels && !inserted {
        out.push_str(trimmed_content);
        out.push('\n');
    }

    out
}

/// Write config with validation and rollback. Returns Ok(()) on success,
/// or Err(message) if validation fails (config is rolled back automatically).
fn write_validated_config(config: &str) -> Result<(), String> {
    backup_config();
    if let Err(e) = validate_toml_structure(config) {
        rollback_config();
        return Err(format!("Invalid config: {}. Changes rolled back.", e));
    }
    if let Err(e) = fs::write(OPENCLAW_CONFIG, config) {
        rollback_config();
        return Err(format!("Failed to write config: {}. Changes rolled back.", e));
    }
    let _ = Command::new("chmod").args(["600", OPENCLAW_CONFIG]).output();
    Ok(())
}

fn strip_channel_sections(config: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut in_channels_root = false;
    let mut in_channel_sub = false;
    for line in config.lines() {
        let t = line.trim();
        if t == "[channels_config]" {
            // Keep the header, enter root mode to filter channel-specific keys
            in_channels_root = true;
            in_channel_sub = false;
            out.push(line);
            continue;
        }
        if t.starts_with("[channels_config.") && t.ends_with(']') {
            // Sub-channel sections are stripped entirely
            in_channels_root = false;
            in_channel_sub = true;
            continue;
        }
        if (in_channels_root || in_channel_sub) && t.starts_with('[') && !t.starts_with("[[") && !t.starts_with("[channels_config") {
            in_channels_root = false;
            in_channel_sub = false;
        }
        if in_channel_sub {
            continue; // skip lines inside [channels_config.*] sub-sections
        }
        if in_channels_root {
            // Inside [channels_config]: strip cli = true (re-appended later)
            // but preserve other keys like message_timeout_secs
            if t == "cli = true" || t == "cli=true" { continue; }
        }
        out.push(line);
    }
    out.join("\n")
}

fn restart_openclaw_with_channel_config(channel_config: &str, autonomy: &str) {
    if let Ok(config) = fs::read_to_string(OPENCLAW_CONFIG) {
        // Strip channel sub-sections that onboard may have written into the fresh
        // skeleton; the root [channels_config] header and non-channel keys like
        // message_timeout_secs are preserved to avoid duplicate headers.
        let stripped = strip_channel_sections(&config);
        let mut final_config = patch_openclaw_config(&stripped, autonomy);
        let trimmed_channels = channel_config.trim();
        if !trimmed_channels.is_empty() {
            // Split the extracted channel config into:
            //   1. Root keys (cli = true) → inject into existing [channels_config]
            //   2. Sub-sections ([channels_config.*]) → insert contiguously after it
            let mut root_keys = Vec::new();
            let mut sub_sections = String::new();

            for ch_line in trimmed_channels.lines() {
                let ct = ch_line.trim();
                if ct == "[channels_config]" { continue; } // header already exists
                if ct.starts_with("[channels_config.") {
                    // Start of a sub-section — collect it and everything after
                    sub_sections.push_str(ch_line);
                    sub_sections.push('\n');
                } else if !sub_sections.is_empty() {
                    // Key inside a sub-section
                    sub_sections.push_str(ch_line);
                    sub_sections.push('\n');
                } else if !ct.is_empty() {
                    // Root key like "cli = true"
                    root_keys.push(ch_line.to_string());
                }
            }

            // Inject root keys (e.g. cli = true) into existing [channels_config]
            for key_line in &root_keys {
                if let Some(pos) = final_config.find("\n[channels_config]\n") {
                    let insert_at = pos + "\n[channels_config]\n".len();
                    final_config.insert_str(insert_at, &format!("{}\n", key_line.trim()));
                } else if let Some(pos) = final_config.find("[channels_config]\n") {
                    let insert_at = pos + "[channels_config]\n".len();
                    final_config.insert_str(insert_at, &format!("{}\n", key_line.trim()));
                } else {
                    final_config.push_str(&format!("\n[channels_config]\n{}\n", key_line.trim()));
                }
            }

            // Ensure cli field is always present (required by ZeroClaw schema)
            if !final_config.contains("\ncli = true") && !final_config.contains("\ncli=true") {
                if let Some(pos) = final_config.find("[channels_config]\n") {
                    let insert_at = pos + "[channels_config]\n".len();
                    final_config.insert_str(insert_at, "cli = true\n");
                }
            }

            // Insert sub-sections contiguously after [channels_config] block
            if !sub_sections.is_empty() {
                final_config = insert_after_channels_section(&final_config, &sub_sections);
            }
        }
        match write_validated_config(&final_config) {
            Ok(()) => {},
            Err(e) => eprintln!("[config] {}", e),
        }
    }
    let _ = Command::new("systemctl").args(["restart", "openclaw-daemon.service"]).output();
}

// ── JSON / TOML / HTML helpers ─────────────────────────────────────────────────

fn json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\"", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return "" };
    let after = json[pos + needle.len()..].splitn(2, ':').nth(1).unwrap_or("").trim_start();
    if after.starts_with('"') { let inner = &after[1..]; &inner[..inner.find('"').unwrap_or(0)] } else { "" }
}

fn json_bool(json: &str, key: &str) -> bool {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) { Some(p) => p, None => return false };
    json[pos + needle.len()..].trim_start().starts_with("true")
}

fn toml_escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"").replace('\n', r"\n").replace('\r', r"\r").replace('\t', r"\t")
}

fn csv_to_toml_array(csv: &str) -> String {
    if csv.trim().is_empty() { return "[\"*\"]".to_string(); }
    let items: Vec<String> = csv.split(',').map(|s| format!("\"{}\"", toml_escape(s.trim()))).collect();
    format!("[{}]", items.join(", "))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn parse_form(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        if let Some(eq) = pair.find('=') {
            map.insert(url_decode(&pair[..eq]), url_decode(&pair[eq + 1..]));
        }
    }
    map
}

fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'+' { result.push(' '); }
        else if b == b'%' {
            let h1 = bytes.next().unwrap_or(b'0') as char;
            let h2 = bytes.next().unwrap_or(b'0') as char;
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) { result.push(byte as char); }
        } else { result.push(b as char); }
    }
    result
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

fn send_response(stream: &mut TcpStream, status: u16, reason: &str, ctype: &str, body: &[u8]) {
    let hdr = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(hdr.as_bytes()); let _ = stream.write_all(body);
}
fn send_html(stream: &mut TcpStream, html: &str) { send_response(stream, 200, "OK", "text/html; charset=utf-8", html.as_bytes()); }
fn send_json_ok(stream: &mut TcpStream, body: &str) { send_response(stream, 200, "OK", "application/json", body.as_bytes()); }
fn send_json_err(stream: &mut TcpStream, status: u16, msg: &str) {
    let body = format!("{{\"error\":\"{}\"}}", msg.replace('"', "'"));
    send_response(stream, status, "Error", "application/json", body.as_bytes());
}
fn send_redirect(stream: &mut TcpStream, location: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location).as_bytes());
}
fn send_redirect_with_cookie(stream: &mut TcpStream, location: &str, cookie: &str) {
    let _ = stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nSet-Cookie: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location, cookie).as_bytes());
}

struct Req { method: String, path: String, headers: String, body: String }

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut r = BufReader::new(stream.try_clone().ok()?);
    let mut line0 = String::new(); r.read_line(&mut line0).ok()?;
    let mut parts = line0.trim().splitn(3, ' ');
    let method   = parts.next()?.to_string();
    let path_raw = parts.next()?.to_string();
    let path     = path_raw.split('?').next().unwrap_or(&path_raw).to_string();
    let mut cl: usize = 0; let mut headers = String::new();
    loop {
        let mut line = String::new(); r.read_line(&mut line).ok()?;
        if line.trim().is_empty() { break; }
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") { cl = lower["content-length:".len()..].trim().parse().unwrap_or(0); }
        headers.push_str(&line);
    }
    let mut body = vec![0u8; cl.min(1 << 20)];
    if cl > 0 { r.read_exact(&mut body).ok()?; }
    Some(Req { method, path, headers, body: String::from_utf8_lossy(&body).into_owned() })
}

fn get_cookie(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("cookie:") {
            for pair in line["cookie:".len()..].trim().split(';') {
                let p = pair.trim();
                if let Some(eq) = p.find('=') {
                    if p[..eq].trim() == name { return Some(p[eq + 1..].trim().to_string()); }
                }
            }
        }
    }
    None
}

fn fmt_uptime(secs: u64) -> String {
    if secs < 60 { format!("{}s", secs) }
    else if secs < 3600 { format!("{}m", secs / 60) }
    else if secs < 86400 { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
    else { format!("{}d {}h", secs / 86400, (secs % 86400) / 3600) }
}

// ── Common CSS ─────────────────────────────────────────────────────────────────

const COMMON_CSS: &str = r#"
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:32px 16px}
.card{background:#1a1d27;border:1px solid #2d3148;border-radius:16px;width:100%;max-width:600px;overflow:hidden}
.hdr{background:linear-gradient(135deg,#1e2d5a,#2d1e5a);padding:24px 32px}
.hdr h1{font-size:20px;font-weight:700;color:#fff;letter-spacing:-.3px}
.hdr p{color:#94a3b8;font-size:13px;margin-top:4px}
.body{padding:28px 32px}
label{display:block;font-size:13px;font-weight:600;color:#94a3b8;margin-bottom:5px;margin-top:14px}
label:first-of-type{margin-top:0}
input[type=text],input[type=password],input[type=url],input[type=number],textarea,select{width:100%;padding:10px 12px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s;font-family:inherit}
textarea{resize:vertical;min-height:80px;font-size:12px;font-family:monospace}
input:focus,textarea:focus,select:focus{border-color:#6366f1}
select option{background:#1a1d27}
.hint{font-size:12px;color:#475569;margin-top:5px;line-height:1.5}
.hint a{color:#818cf8;text-decoration:none}
.ok-box{background:#0d2618;border:1px solid #166534;border-radius:8px;padding:11px 14px;color:#86efac;font-size:13px;margin-bottom:16px}
.err-box{background:#2d1515;border:1px solid #7f1d1d;border-radius:8px;padding:11px 14px;color:#fca5a5;font-size:13px;margin-bottom:16px}
.info-box{background:#0f172a;border:1px solid #1e40af;border-radius:8px;padding:11px 14px;font-size:12px;color:#93c5fd;line-height:1.6;margin-top:12px}
.btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}
.btn-primary:hover{opacity:.9;transform:translateY(-1px)}
.btn-primary:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn-secondary{background:#0f1117;border:1px solid #2d3148;color:#94a3b8}
.btn-secondary:hover{border-color:#6366f1;color:#e2e8f0}
.btn-danger{background:#7f1d1d;border:1px solid #991b1b;color:#fca5a5}
.btn-danger:hover{background:#991b1b}
.divider{height:1px;background:#2d3148;margin:20px 0}
code{background:#1e2740;padding:1px 5px;border-radius:4px;font-family:monospace;color:#a5b4fc;font-size:12px}
.hw-opts{display:flex;gap:8px;margin-bottom:10px}
.hw-opt{flex:1;padding:12px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;transition:all .2s}
.hw-opt:hover,.hw-opt.sel{border-color:#6366f1}.hw-opt.sel{background:#1e1d3f}
.hw-opt-name{font-size:13px;font-weight:600;color:#e2e8f0}.hw-opt-desc{font-size:11px;color:#475569;margin-top:2px}
"#;

// ── Login page ─────────────────────────────────────────────────────────────────

fn build_login_html(error: bool) -> String {
    let err = if error { r#"<div class="err-box">Incorrect password. Try again.</div>"# } else { "" };
    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — Login</title>
<style>{css}body{{align-items:center}}.card{{max-width:400px}}.hdr{{text-align:center}}.icon{{font-size:42px;margin-bottom:10px}}form .btn{{width:100%;margin-top:18px}}</style></head><body>
<div class="card">
  <div class="hdr"><div class="icon">🜲</div><h1>Holo Node</h1><p>Enter your node password to continue.</p></div>
  <div class="body">{err}
    <form method="POST" action="/login">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
      <button type="submit" class="btn btn-primary">Unlock →</button>
    </form>
  </div>
</div></body></html>"#, css=COMMON_CSS, err=err)
}

// ── Onboarding page ────────────────────────────────────────────────────────────

fn build_onboarding_html(ap_mode: bool) -> String {
    let wifi_block = if ap_mode {
        r#"<div class="err-box">⚠ No Ethernet — connect to Wi-Fi to continue.</div>
<label>Wi-Fi SSID</label><input type="text" id="wifiSsid" placeholder="Network name">
<label>Wi-Fi Password</label><input type="password" id="wifiPass">"#
    } else {
        r#"<div class="ok-box">✓ Ethernet connected — you're online.</div>"#
    };

    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node Setup</title>
<style>
{css}
.prog{{height:3px;background:#0f1117}}.prog-fill{{height:100%;background:linear-gradient(90deg,#6366f1,#8b5cf6);transition:width .4s ease}}
.step{{display:none}}.step.active{{display:block}}
.slbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6366f1;margin-bottom:12px}}
.stit{{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:5px}}
.sdsc{{font-size:13px;color:#64748b;margin-bottom:20px;line-height:1.6}}
.cat-lbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin:16px 0 8px}}
.cg{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px}}
.cb{{padding:12px 8px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;text-align:center;transition:all .2s;color:#94a3b8}}
.cb:hover,.cb.sel{{border-color:#6366f1;color:#a5b4fc}}.cb.sel{{background:#1e1d3f}}
.cb-icon{{font-size:20px;margin-bottom:4px}}.cb-name{{font-size:12px;font-weight:600}}
.ch-form{{margin-top:16px;display:none}}.ch-form.vis{{display:block}}
.inst{{background:#0f172a;border:1px solid #1e40af;border-radius:8px;padding:12px;margin-bottom:12px}}
.inst b{{font-size:12px;color:#818cf8}}.inst ol{{padding-left:18px;margin-top:6px}}.inst li{{font-size:12px;color:#94a3b8;line-height:1.8}}
.pl{{display:flex;flex-direction:column;gap:8px}}
.pb{{padding:12px 14px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;display:flex;align-items:center;gap:12px;transition:all .2s;color:#94a3b8}}
.pb:hover,.pb.sel{{border-color:#6366f1;color:#a5b4fc}}.pb.sel{{background:#1e1d3f}}
.pi{{font-size:18px;flex-shrink:0}}.pn{{font-size:13px;font-weight:600}}.pd{{font-size:11px;color:#475569;margin-top:2px}}
.pc{{margin-top:16px;display:none}}.pc.vis{{display:block}}
.ao{{display:flex;flex-direction:column;gap:8px}}
.ab{{padding:12px 14px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;display:flex;align-items:flex-start;gap:10px;transition:all .2s}}
.ab:hover{{border-color:#6366f1}}.ab.sel{{border-color:#6366f1;background:#1e1d3f}}
.ar{{width:18px;height:18px;border-radius:50%;border:2px solid #4b5563;flex-shrink:0;margin-top:2px;display:flex;align-items:center;justify-content:center}}
.ab.sel .ar{{border-color:#6366f1;background:#6366f1}}.ab.sel .ar::after{{content:'';width:6px;height:6px;border-radius:50%;background:#fff}}
.an{{font-size:13px;font-weight:600;color:#e2e8f0}}.ad{{font-size:12px;color:#64748b;margin-top:2px;line-height:1.5}}
.toggle-row{{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:#0f1117;border:1px solid #2d3148;border-radius:10px;margin-bottom:14px}}
.toggle-label{{font-size:14px;font-weight:600;color:#e2e8f0}}.toggle-sub{{font-size:12px;color:#64748b;margin-top:2px}}
.toggle{{position:relative;width:48px;height:26px;flex-shrink:0}}.toggle input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#2d3148;border-radius:13px;transition:.3s}}
.slider:before{{position:absolute;content:'';height:18px;width:18px;left:4px;bottom:4px;background:#64748b;border-radius:50%;transition:.3s}}
input:checked+.slider{{background:#6366f1}}input:checked+.slider:before{{transform:translateX(22px);background:#fff}}
.agent-config{{display:none;margin-top:16px}}.agent-config.vis{{display:block}}
.fw{{display:none;background:#2d1515;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-top:12px;font-size:12px;color:#fca5a5;line-height:1.6}}
.fw.vis{{display:block}}.fw label{{color:#fca5a5;font-size:12px;font-weight:400;display:flex;align-items:flex-start;gap:8px;cursor:pointer;margin:10px 0 0}}
.fw input[type=checkbox]{{width:auto;flex-shrink:0;margin-top:2px}}
.brow{{display:flex;gap:10px;margin-top:24px}}.brow .btn{{flex:1}}
.spin{{display:none;width:20px;height:20px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite;margin:0 auto}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
.suc{{text-align:center;padding:24px 0}}.suc h2{{font-size:24px;font-weight:700;color:#86efac;margin-bottom:12px}}.suc p{{color:#64748b;font-size:14px;line-height:1.7}}
.rt{{width:100%;border-collapse:collapse;font-size:13px}}.rt tr{{border-bottom:1px solid #2d3148}}.rt tr:last-child{{border-bottom:none}}
.rt td{{padding:9px 0;vertical-align:top}}.rt td:first-child{{color:#64748b;width:130px;padding-right:12px}}.rt td:last-child{{color:#e2e8f0;font-weight:500;word-break:break-all}}
</style></head><body>
<div class="card">
  <div class="hdr"><h1>🜲 Holo Node</h1><p>One-time setup — about 3 minutes.</p></div>
  <div class="prog"><div class="prog-fill" id="prog" style="width:0%"></div></div>
  <div class="body">
    {wifi_block}

    <!-- STEP 1: IDENTITY + SSH -->
    <div class="step active" id="s1">
      <div class="slbl">Step 1 of 4</div>
      <div class="stit">Node identity &amp; SSH access</div>
      <div class="sdsc">Name your node and optionally add your SSH public key for emergency access.</div>
      <label>Node name *</label>
      <input type="text" id="nodeName" placeholder="e.g. alice, home-node-01" oninput="chkS1()">
      <div class="hint">Lowercase letters, numbers and hyphens only. Used as hostname slug.</div>
      <label>SSH public key <span style="color:#475569;font-weight:400">(recommended)</span></label>
      <textarea id="sshKey" placeholder="ssh-ed25519 AAAA...&#10;Leave blank to add keys later in /manage"></textarea>
      <div class="brow"><button class="btn btn-primary" id="b1" onclick="gTo(2)" disabled>Continue →</button></div>
    </div>

    <!-- STEP 2: AI AGENT + CHANNEL -->
    <div class="step" id="s2">
      <div class="slbl">Step 2 of 4</div>
      <div class="stit">AI agent &amp; channel</div>
      <div class="sdsc">The AI agent is completely optional. If enabled, pick a chat platform to control your node.</div>
      <div class="toggle-row">
        <div><div class="toggle-label">Enable AI agent</div><div class="toggle-sub">Installs OpenClaw and connects to your chosen platform</div></div>
        <label class="toggle"><input type="checkbox" id="agentToggle" onchange="onAgentToggle()"><span class="slider"></span></label>
      </div>
      <div class="agent-config" id="agentConfig">
        <label style="margin-top:0">Chat platform</label>
        <div class="cat-lbl">Messaging</div>
        <div class="cg">
          <div class="cb" onclick="sCh('telegram',this)"><div class="cb-icon">✈️</div><div class="cb-name">Telegram</div></div>
          <div class="cb" onclick="sCh('discord',this)"><div class="cb-icon">🎮</div><div class="cb-name">Discord</div></div>
          <div class="cb" onclick="sCh('whatsapp',this)"><div class="cb-icon">💬</div><div class="cb-name">WhatsApp</div></div>
          <div class="cb" onclick="sCh('signal',this)"><div class="cb-icon">🔒</div><div class="cb-name">Signal</div></div>
          <div class="cb" onclick="sCh('slack',this)"><div class="cb-icon">💼</div><div class="cb-name">Slack</div></div>
          <div class="cb" onclick="sCh('imessage',this)"><div class="cb-icon">🍎</div><div class="cb-name">iMessage</div></div>
        </div>
        <div class="cat-lbl">Business / Productivity</div>
        <div class="cg">
          <div class="cb" onclick="sCh('email',this)"><div class="cb-icon">📧</div><div class="cb-name">Email</div></div>
          <div class="cb" onclick="sCh('mattermost',this)"><div class="cb-icon">🔵</div><div class="cb-name">Mattermost</div></div>
          <div class="cb" onclick="sCh('nextcloud_talk',this)"><div class="cb-icon">☁️</div><div class="cb-name">Nextcloud</div></div>
          <div class="cb" onclick="sCh('linq',this)"><div class="cb-icon">📱</div><div class="cb-name">Linq</div></div>
          <div class="cb" onclick="sCh('webhook',this)"><div class="cb-icon">🔗</div><div class="cb-name">Webhook</div></div>
        </div>
        <div class="cat-lbl">Open / Technical</div>
        <div class="cg">
          <div class="cb" onclick="sCh('matrix',this)"><div class="cb-icon">🔷</div><div class="cb-name">Matrix</div></div>
          <div class="cb" onclick="sCh('irc',this)"><div class="cb-icon">🖥️</div><div class="cb-name">IRC</div></div>
          <div class="cb" onclick="sCh('nostr',this)"><div class="cb-icon">⚡</div><div class="cb-name">Nostr</div></div>
          <div class="cb" onclick="sCh('cli',this)"><div class="cb-icon">💻</div><div class="cb-name">CLI only</div></div>
        </div>
        <div class="cat-lbl">Asian Platforms</div>
        <div class="cg">
          <div class="cb" onclick="sCh('dingtalk',this)"><div class="cb-icon">🔔</div><div class="cb-name">DingTalk</div></div>
          <div class="cb" onclick="sCh('qq',this)"><div class="cb-icon">🐧</div><div class="cb-name">QQ</div></div>
          <div class="cb" onclick="sCh('lark',this)"><div class="cb-icon">🦅</div><div class="cb-name">Lark</div></div>
          <div class="cb" onclick="sCh('feishu',this)"><div class="cb-icon">🪶</div><div class="cb-name">Feishu</div></div>
        </div>
        <div id="chFormContainer"></div>
      </div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(1)">← Back</button>
        <button class="btn btn-primary" id="b2" onclick="gTo(3)">Continue →</button>
      </div>
    </div>

    <!-- STEP 3: PROVIDER + HARDWARE -->
    <div class="step" id="s3">
      <div class="slbl">Step 3 of 4</div>
      <div class="stit">AI engine &amp; hardware mode</div>
      <div class="sdsc" id="s3desc">Configure the AI provider and choose the initial container mode.</div>
      <div id="providerSection" style="display:none">
        <label style="margin-top:0">AI Provider</label>
        <div class="pl">
          <div class="pb sel" onclick="sPv('ollama',this)"><div class="pi">🦙</div><div><div class="pn">Ollama (Local)</div><div class="pd">Private, no API cost</div></div></div>
          <div class="pb" onclick="sPv('google',this)"><div class="pi">✦</div><div><div class="pn">Google Gemini</div><div class="pd">Free tier available</div></div></div>
          <div class="pb" onclick="sPv('anthropic',this)"><div class="pi">◆</div><div><div class="pn">Anthropic Claude</div><div class="pd">Best for reasoning</div></div></div>
          <div class="pb" onclick="sPv('openai',this)"><div class="pi">⬡</div><div><div class="pn">OpenAI</div><div class="pd">GPT-4o, o4-mini</div></div></div>
          <div class="pb" onclick="sPv('openrouter',this)"><div class="pi">⇄</div><div><div class="pn">OpenRouter</div><div class="pd">300+ models, one key</div></div></div>
        </div>
        <div id="pc-google" class="pc"><label>Gemini API Key *</label><input type="password" id="pg-key" placeholder="AIzaSy..."><label>Model</label><select id="pg-mdl"><option value="gemini-2.5-flash">gemini-2.5-flash (Recommended)</option><option value="gemini-2.5-pro">gemini-2.5-pro</option><option value="gemini-2.0-flash">gemini-2.0-flash</option></select></div>
        <div id="pc-anthropic" class="pc"><label>Claude API Key *</label><input type="password" id="pa-key" placeholder="sk-ant-..."><label>Model</label><select id="pa-mdl"><option value="claude-haiku-4-5-20251001">claude-haiku (Fast)</option><option value="claude-sonnet-4-6">claude-sonnet (Recommended)</option></select></div>
        <div id="pc-openai" class="pc"><label>OpenAI API Key *</label><input type="password" id="po-key" placeholder="sk-..."><label>Model</label><select id="po-mdl"><option value="gpt-4o-mini">gpt-4o-mini</option><option value="gpt-4o">gpt-4o</option><option value="o4-mini">o4-mini</option></select></div>
        <div id="pc-openrouter" class="pc"><label>OpenRouter API Key *</label><input type="password" id="pr-key" placeholder="sk-or-..."><label>Model ID</label><input type="text" id="pr-mdl" value="openrouter/auto" placeholder="openrouter/auto"></div>
        <div id="pc-ollama" class="pc"><div class="info-box">Ollama must be running on this node or local network.</div><label>Ollama URL</label><input type="url" id="pl-url" value="http://127.0.0.1:11434"><label>Model name *</label><input type="text" id="pl-mdl" placeholder="llama3.2"></div>
        <div class="divider"></div>
        <label>Agent autonomy</label>
        <div class="hw-opts" id="au-opts" style="flex-direction:column">
            <div class="hw-opt{sel_full}" onclick="selAu('full',this)">
            <div class="hw-opt-name">⚡ Full</div>
            <div class="hw-opt-desc">The agent acts autonomously — executes commands and makes decisions without asking for approval first.</div>
            </div>
            <div class="hw-opt{sel_supervised}" onclick="selAu('supervised',this)">
            <div class="hw-opt-name">👁 Supervised</div>
            <div class="hw-opt-desc">The agent proposes actions and waits for your approval before executing anything.</div>
            </div>
            <div class="hw-opt{sel_readonly}" onclick="selAu('readonly',this)">
            <div class="hw-opt-name">🔒 Read-Only</div>
            <div class="hw-opt-desc">The agent has read-only access — it can observe and advise but cannot run any commands.</div>
            </div>
        </div>
        <div class="fw vis" id="fw" style="background:#0f1f2e;border-color:#1e3a5f;color:#93c5fd"><strong>🛡 Risk surface is well contained.</strong> A strict command allowlist is already enforced — <code>curl</code> and <code>wget</code> are blocked. The agent can only write inside <code>/var/lib/zeroclaw/workspace</code> (enforced by <code>allowed_roots</code>) and cannot touch system files (enforced by <code>forbidden_paths</code>).</div>
        <div class="divider"></div>
      </div>
      <label>Hardware mode</label>
      <select id="hw">
        <option value="STANDARD">Standard EdgeNode — always-on Holochain peer</option>
        <option value="WIND_TUNNEL">Holochain Wind Tunnel — network stress-tester</option>
      </select>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(2)">← Back</button>
        <button class="btn btn-primary" id="b3" onclick="gTo(4)">Review →</button>
      </div>
    </div>

    <!-- STEP 4: REVIEW -->
    <div class="step" id="s4">
      <div class="slbl">Step 4 of 4</div>
      <div class="stit">Review &amp; initialize</div>
      <div class="sdsc">Check your settings, then start the node.</div>
      <table class="rt">
        <tr><td>Node Name</td><td id="rv-nn">—</td></tr>
        <tr><td>SSH Key</td><td id="rv-sk">—</td></tr>
        <tr><td>AI Agent</td><td id="rv-ag">—</td></tr>
        <tr><td>Channel</td><td id="rv-ch">—</td></tr>
        <tr><td>AI Provider</td><td id="rv-pv">—</td></tr>
        <tr><td>Model</td><td id="rv-md">—</td></tr>
        <tr><td>Autonomy</td><td id="rv-au">—</td></tr>
        <tr><td>Hardware Mode</td><td id="rv-hw">—</td></tr>
      </table>
      <div class="info-box" style="margin-top:16px">After initialization:<br>
        1. SSH access is configured for the <code>holo</code> user<br>
        2. Podman Quadlet services are registered with systemd<br>
        3. If the AI agent is enabled, OpenClaw connects within ~60 seconds<br>
        4. You will be redirected to the management panel</div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(3)">← Back</button>
        <button class="btn btn-primary" id="bsub" onclick="doSubmit()">
          <span id="slbl">Initialize Node</span>
          <div class="spin" id="spin"></div>
        </button>
      </div>
    </div>

    <!-- SUCCESS -->
    <div class="step" id="suc"><div class="suc"><div style="font-size:48px;margin-bottom:16px">🜲</div><h2>Node Initialized!</h2><p>Redirecting to the management panel…</p></div></div>
  </div>
</div>
<script>
// ── Channel schema (fields for each channel type) ─────────────────────────────
const CH = {{
  cli:{{name:'CLI',icon:'💻',fields:[]}},
  telegram:{{name:'Telegram',icon:'✈️',hint:'<b>Setup:</b><ol><li>Search @BotFather → /newbot → copy token</li><li>Message @getmyid_bot for your numeric user ID</li></ol>',
    fields:[{{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:'123456789:ABC...'}},
            {{id:'allowed_users',label:'Allowed User IDs (comma-sep, * = anyone)',type:'text',ph:'*',def:'*'}}]}},
  discord:{{name:'Discord',icon:'🎮',hint:'<b>Setup:</b><ol><li>discord.com/developers → New App → Bot → Reset Token</li><li>Enable Message Content Intent</li><li>Your User ID: Settings → Advanced → Developer Mode → right-click name</li></ol>',
    fields:[{{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:'MTxx...'}},
            {{id:'guild_id',label:'Guild ID (optional)',type:'text',ph:''}},
            {{id:'allowed_users',label:'Allowed User IDs (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  slack:{{name:'Slack',icon:'💼',hint:'<b>Setup:</b><ol><li>api.slack.com/apps → New App → add chat:write scope → Bot Token</li><li>Socket Mode → enable → App Token (xapp-...)</li><li>Your Member ID: Profile → ⋮ → Copy member ID</li></ol>',
    fields:[{{id:'bot_token',label:'Bot Token (xoxb-...)',type:'password',req:true,ph:'xoxb-...'}},
            {{id:'app_token',label:'App Token (xapp-...)',type:'password',req:true,ph:'xapp-...'}},
            {{id:'allowed_users',label:'Allowed Member IDs (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  mattermost:{{name:'Mattermost',icon:'🔵',
    fields:[{{id:'url',label:'Server URL',type:'url',req:true,ph:'https://mm.example.com'}},
            {{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:'...'}},
            {{id:'channel_id',label:'Channel ID',type:'text',req:true,ph:'...'}},
            {{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  matrix:{{name:'Matrix',icon:'🔷',hint:'<b>Setup:</b><ol><li>Create a bot account on your homeserver</li><li>Get access token from Element: Settings → Help → Access Token</li><li>Invite bot to your room and get the Room ID</li></ol>',
    fields:[{{id:'homeserver',label:'Homeserver URL',type:'url',req:true,ph:'https://matrix.org'}},
            {{id:'access_token',label:'Bot Access Token',type:'password',req:true,ph:'syt_...'}},
            {{id:'room_id',label:'Room ID',type:'text',req:true,ph:'!abc123:matrix.org'}},
            {{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'user_id',label:'Bot User ID (optional, recommended for E2EE)',type:'text',ph:'@bot:matrix.org'}},
            {{id:'device_id',label:'Device ID (optional, for E2EE)',type:'text',ph:'DEVICEID123'}}]}},
  signal:{{name:'Signal',icon:'🔒',hint:'<b>Requires signal-cli:</b><ol><li>Install signal-cli and register your number</li><li>Start: <code>signal-cli -u +1234 daemon --http=127.0.0.1:8686</code></li></ol>',
    fields:[{{id:'http_url',label:'signal-cli URL',type:'url',req:true,ph:'http://127.0.0.1:8686',def:'http://127.0.0.1:8686'}},
            {{id:'account',label:'Registered Number',type:'text',req:true,ph:'+12345678901'}},
            {{id:'allowed_from',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  whatsapp:{{name:'WhatsApp',icon:'💬',hint:'<b>Requires Meta Business account:</b><ol><li>developers.facebook.com → New App → Business → Add WhatsApp</li><li>Copy Phone Number ID and access token</li><li>Set webhook URL in Meta dashboard to your node IP</li></ol>',
    fields:[{{id:'access_token',label:'Access Token',type:'password',req:true,ph:'EAAB...'}},
            {{id:'phone_number_id',label:'Phone Number ID',type:'text',req:true,ph:'123456789012345'}},
            {{id:'verify_token',label:'Verify Token (your choice)',type:'text',req:true,ph:'my-secret-verify-token'}},
            {{id:'allowed_numbers',label:'Allowed Numbers E.164 (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  webhook:{{name:'Webhook',icon:'🔗',
    fields:[{{id:'port',label:'Port',type:'number',ph:'8080',def:'8080'}},
            {{id:'secret',label:'Shared Secret (optional)',type:'password',ph:''}}]}},
  email:{{name:'Email',icon:'📧',
    fields:[{{id:'imap_host',label:'IMAP Host',type:'text',req:true,ph:'imap.example.com'}},
            {{id:'imap_port',label:'IMAP Port',type:'number',req:false,ph:'993',def:'993'}},
            {{id:'smtp_host',label:'SMTP Host',type:'text',req:true,ph:'smtp.example.com'}},
            {{id:'smtp_port',label:'SMTP Port',type:'number',req:false,ph:'465',def:'465'}},
            {{id:'username',label:'Username / Email',type:'text',req:true,ph:'bot@example.com'}},
            {{id:'password',label:'Password',type:'password',req:true,ph:''}},
            {{id:'from_address',label:'From Address',type:'text',req:true,ph:'bot@example.com'}},
            {{id:'allowed_senders',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  irc:{{name:'IRC',icon:'🖥️',
    fields:[{{id:'server',label:'IRC Server',type:'text',req:true,ph:'irc.libera.chat'}},
            {{id:'port',label:'Port',type:'number',ph:'6697',def:'6697'}},
            {{id:'nickname',label:'Bot Nickname',type:'text',req:true,ph:'mybot'}},
            {{id:'channels',label:'Channels (comma-sep)',type:'text',req:true,ph:'#mychannel,#other'}},
            {{id:'allowed_users',label:'Allowed Nicks (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'server_password',label:'Server Password (optional)',type:'password',ph:''}},
            {{id:'nickserv_password',label:'NickServ Password (optional)',type:'password',ph:''}},
            {{id:'sasl_password',label:'SASL Password (optional)',type:'password',ph:''}}]}},
  lark:{{name:'Lark',icon:'🦅',hint:'<b>Setup:</b><ol><li>Open Lark Open Platform → Create Custom App</li><li>Enable Bot feature, copy App ID and App Secret</li><li>Subscribe to Message Received event</li></ol>',
    fields:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:'cli_...'}},
            {{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},
            {{id:'allowed_users',label:'Allowed Open IDs (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'receive_mode',label:'Receive Mode',type:'select',opts:[{{v:'websocket',l:'WebSocket (recommended)'}},{{v:'webhook',l:'Webhook'}}]}},
            {{id:'port',label:'Webhook Port (only if webhook mode)',type:'number',ph:'8081',def:'8081'}},
            {{id:'encrypt_key',label:'Encrypt Key (optional)',type:'password',ph:''}},
            {{id:'verification_token',label:'Verification Token (optional)',type:'text',ph:''}}]}},
  feishu:{{name:'Feishu',icon:'🪶',hint:'<b>Setup:</b><ol><li>Open Feishu Open Platform → Create App</li><li>Enable Bot, copy App ID and App Secret</li><li>Subscribe to Message Received event</li></ol>',
    fields:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:'cli_...'}},
            {{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},
            {{id:'allowed_users',label:'Allowed Open IDs (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'receive_mode',label:'Receive Mode',type:'select',opts:[{{v:'websocket',l:'WebSocket (recommended)'}},{{v:'webhook',l:'Webhook'}}]}},
            {{id:'port',label:'Webhook Port (only if webhook mode)',type:'number',ph:'8081',def:'8081'}},
            {{id:'encrypt_key',label:'Encrypt Key (optional)',type:'password',ph:''}},
            {{id:'verification_token',label:'Verification Token (optional)',type:'text',ph:''}}]}},
  nostr:{{name:'Nostr',icon:'⚡',hint:'<b>Setup:</b><ol><li>Generate a Nostr key pair (nsec / npub)</li><li>The agent listens for DMs on the configured relays</li></ol>',
    fields:[{{id:'private_key',label:'Private Key (nsec or hex)',type:'password',req:true,ph:'nsec1...'}},
            {{id:'allowed_pubkeys',label:'Allowed Pubkeys (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'relays',label:'Relays (comma-sep)',type:'text',ph:'wss://relay.damus.io,wss://nos.lol',def:'wss://relay.damus.io,wss://nos.lol'}}]}},
  dingtalk:{{name:'DingTalk',icon:'🔔',hint:'<b>Setup:</b><ol><li>Open DingTalk Open Platform → Create Internal App</li><li>Enable Robot, copy Client ID and Client Secret</li></ol>',
    fields:[{{id:'client_id',label:'Client ID',type:'text',req:true,ph:'ding...'}},
            {{id:'client_secret',label:'Client Secret',type:'password',req:true,ph:''}},
            {{id:'allowed_users',label:'Allowed Staff IDs (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  qq:{{name:'QQ',icon:'🐧',hint:'<b>Setup:</b><ol><li>Register on QQ Open Platform</li><li>Create a bot, copy App ID and App Secret</li></ol>',
    fields:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:''}},
            {{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},
            {{id:'allowed_users',label:'Allowed QQ IDs (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
  nextcloud_talk:{{name:'Nextcloud Talk',icon:'☁️',
    fields:[{{id:'base_url',label:'Nextcloud URL',type:'url',req:true,ph:'https://cloud.example.com'}},
            {{id:'app_token',label:'App Password / Token',type:'password',req:true,ph:''}},
            {{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'webhook_secret',label:'Webhook Secret (optional)',type:'password',ph:''}}]}},
  linq:{{name:'Linq',icon:'📱',
    fields:[{{id:'api_token',label:'API Token',type:'password',req:true,ph:''}},
            {{id:'from_phone',label:'From Phone (E.164)',type:'text',req:true,ph:'+12025551234'}},
            {{id:'allowed_senders',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}},
            {{id:'signing_secret',label:'Signing Secret (optional)',type:'password',ph:''}}]}},
  imessage:{{name:'iMessage',icon:'🍎',hint:'<b>Requires BlueBubbles or similar macOS bridge</b> accessible from this node.',
    fields:[{{id:'allowed_contacts',label:'Allowed Contacts (* = anyone)',type:'text',ph:'*',def:'*'}}]}},
}};

// ── JS state ───────────────────────────────────────────────────────────────────
const S={{agent:false,ch:'',pv:'ollama',au:'full'}};
const PVN={{google:'Google Gemini',anthropic:'Anthropic Claude',openai:'OpenAI',openrouter:'OpenRouter',ollama:'Ollama (Local)'}};

// ── Dynamic channel form renderer ─────────────────────────────────────────────
function renderChForm(ch){{
  const cfg=CH[ch];
  if(!cfg||!cfg.fields.length)return'';
  let html='<div class="ch-form vis">';
  if(cfg.hint)html+='<div class="inst">'+cfg.hint+'</div>';
  for(const f of cfg.fields){{
    html+='<label>'+f.label+'</label>';
    if(f.opts){{
      html+='<select id="ch_'+f.id+'">';
      for(const o of f.opts)html+='<option value="'+o.v+'">'+o.l+'</option>';
      html+='</select>';
    }}else{{
      html+='<input type="'+(f.type||'text')+'" id="ch_'+f.id+'" placeholder="'+(f.ph||'')+'" value="'+(f.def||'')+'">';
    }}
    if(f.hint)html+='<div class="hint">'+f.hint+'</div>';
  }}
  html+='</div>';
  return html;
}}

// ── Step navigation ────────────────────────────────────────────────────────────
function gTo(n){{
  document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));
  document.getElementById(n===5?'suc':'s'+n).classList.add('active');
  document.getElementById('prog').style.width=(Math.min(n,4)/4*100)+'%';
  if(n===4)bRev();
  window.scrollTo(0,0);
}}

function chkS1(){{
  const ok=/^[a-z0-9-]+$/.test(document.getElementById('nodeName').value.trim());
  document.getElementById('b1').disabled=!ok;
}}

function onAgentToggle(){{
  S.agent=document.getElementById('agentToggle').checked;
  document.getElementById('agentConfig').classList.toggle('vis',S.agent);
  document.getElementById('s3desc').textContent=S.agent
    ?'Configure the AI provider and choose the initial container mode.'
    :'Choose the initial container mode. You can enable the AI agent later from /manage.';
  document.getElementById('providerSection').style.display=S.agent?'block':'none';
  chkS3();
}}

function sCh(ch,el){{
  S.ch=ch;
  document.querySelectorAll('.cb').forEach(b=>b.classList.remove('sel'));
  el.classList.add('sel');
  document.getElementById('chFormContainer').innerHTML=ch==='cli'
    ?'<div class="info-box" style="margin-top:8px">CLI mode: interact via <code>openclaw</code> on the node shell. No chat credentials needed.</div>'
    :renderChForm(ch);
}}

function sPv(pv,el){{
  S.pv=pv;
  document.querySelectorAll('.pb').forEach(b=>b.classList.remove('sel'));
  el.classList.add('sel');
  document.querySelectorAll('.pc').forEach(c=>c.classList.remove('vis'));
  document.getElementById('pc-'+pv).classList.add('vis');
  chkS3();
}}

function selAu(lvl, el) {{
  S.au = lvl;
  document.querySelectorAll('#au-opts .hw-opt').forEach(b => b.classList.remove('sel'));
  el.classList.add('sel');
  document.getElementById('fw').classList.toggle('vis', lvl === 'full' || lvl === 'supervised');
  chkS3();
}}

function chkS3(){{
  let ok=true;
  if(S.agent){{
    if(!S.pv)ok=false;
    if(!S.au)ok=false;
  }}
  document.getElementById('b3').disabled=!ok;
}}

function v(id){{const e=document.getElementById(id);return e?e.value.trim():'';}}

function bRev(){{
  const mask=k=>k?'••••'+k.slice(-4):'—';
  let key='',mdl='';
  if(S.pv==='google'){{key=v('pg-key');mdl=v('pg-mdl');}}
  else if(S.pv==='anthropic'){{key=v('pa-key');mdl=v('pa-mdl');}}
  else if(S.pv==='openai'){{key=v('po-key');mdl=v('po-mdl');}}
  else if(S.pv==='openrouter'){{key=v('pr-key');mdl=v('pr-mdl');}}
  else if(S.pv==='ollama'){{mdl=v('pl-mdl')||'llama3.2';}}
  const sk=v('sshKey');
  const set=(id,t)=>{{const e=document.getElementById(id);if(e)e.textContent=t;}};
  set('rv-nn',v('nodeName')||'—');
  set('rv-sk',sk?sk.split(' ')[0]+' ••••':'(not provided)');
  set('rv-ag',S.agent?'Enabled':'Disabled (SSH / container only)');
  set('rv-ch',S.agent?(CH[S.ch]?CH[S.ch].name:'—'):'—');
  set('rv-pv',S.agent?(PVN[S.pv]||S.pv||'—'):'—');
  set('rv-md',S.agent?(mdl||'(default)'):'—');
  set('rv-au', S.agent ? ({{full:'Full', supervised:'Supervised', readonly:'Read-Only'}}[S.au]||'—') : '—');
  set('rv-hw',v('hw')==='WIND_TUNNEL'?'Wind Tunnel':'Standard EdgeNode');
}}

document.getElementById('b3').disabled=false;

async function doSubmit(){{
  const nodeName=v('nodeName');
  if(!nodeName)return alert('Node name is required.');
  if(!/^[a-z0-9-]+$/.test(nodeName))return alert('Node name must be lowercase letters, numbers and hyphens only.');
  if(S.agent){{
    if(!S.ch)return alert('Please choose a chat platform.');
    if(S.ch!=='cli'&&CH[S.ch]){{
      for(const f of CH[S.ch].fields){{
        if(f.req&&!v('ch_'+f.id)){{alert('Required field missing: '+f.label);return;}}
      }}
    }}
    const needKey=['google','anthropic','openai','openrouter'];
    const keyMap={{google:'pg-key',anthropic:'pa-key',openai:'po-key',openrouter:'pr-key'}};
    if(needKey.includes(S.pv)&&!v(keyMap[S.pv]))return alert('Enter your API key for '+(PVN[S.pv]||S.pv)+'.');
    if(S.pv==='ollama'&&!v('pl-mdl'))return alert('Enter the Ollama model name.');
  }}
  const btn=document.getElementById('bsub');
  btn.disabled=true;
  document.getElementById('slbl').style.display='none';
  document.getElementById('spin').style.display='block';
  const chFields={{}};
  if(S.ch&&S.ch!=='cli'&&CH[S.ch]){{
    for(const f of CH[S.ch].fields){{chFields[S.ch+'_'+f.id]=v('ch_'+f.id);}}
  }}
  const p=Object.assign({{
    nodeName,
    sshKey:v('sshKey'),
    agentEnabled:S.agent,
    channel:S.ch||'',
    provider:S.pv||'',
    autonomyLevel:S.au||'supervised',
    hwMode:v('hw'),
    wifiSsid:v('wifiSsid'),
    wifiPass:v('wifiPass'),
    apiKey:(()=>{{
      if(S.pv==='google')return v('pg-key');
      if(S.pv==='anthropic')return v('pa-key');
      if(S.pv==='openai')return v('po-key');
      if(S.pv==='openrouter')return v('pr-key');
      return '';
    }})(),
    model:(()=>{{
      if(S.pv==='google')return v('pg-mdl');
      if(S.pv==='anthropic')return v('pa-mdl');
      if(S.pv==='openai')return v('po-mdl');
      if(S.pv==='openrouter')return v('pr-mdl');
      if(S.pv==='ollama')return v('pl-mdl')||'llama3.2';
      return '';
    }})(),
    apiUrl:S.pv==='ollama'?v('pl-url'):'',
  }},chFields);
  try{{
    const r=await fetch('/submit',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}});
    if(r.ok){{gTo(5);setTimeout(()=>window.location.href='/manage',2000);}}
    else{{throw new Error('Server error '+r.status+': '+(await r.text()));}}
  }}catch(e){{
    btn.disabled=false;
    document.getElementById('slbl').style.display='inline';
    document.getElementById('spin').style.display='none';
    alert('Error: '+e.message);
  }}
}}
</script>
</body></html>"#,
        css        = COMMON_CSS,
        wifi_block = wifi_block,
        sel_full       = " sel",   
        sel_supervised = "",
        sel_readonly   = "",
)
}

// ── build_manage_html ──────────────────────────────────────────────────────────

fn build_manage_html(state: &AppState) -> String {
    let node_name = state.node_name.lock().unwrap().clone();
    let hw_mode   = state.hw_mode.lock().unwrap().clone();
    let channel   = state.channel.lock().unwrap().clone();
    let provider  = state.provider.lock().unwrap().clone();
    let agent_on  = state.agent_enabled.load(Ordering::Relaxed);
    let autonomy = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c) => c.lines()
            .find(|l| l.trim_start().starts_with("level = "))
            .and_then(|l| l.split('"').nth(1))
            .unwrap_or("supervised").to_string(),
        Err(_) => "supervised".to_string(),
    };
    let autonomy_display = match autonomy.as_str() {
    "full"       => "Full",
    "supervised" => "Supervised",
    "readonly"   => "Read-Only",
    _            => "Supervised",
    };
    let au_badge_class = match autonomy.as_str() {
    "full"       => "badge-green",
    "supervised" => "badge-orange",
    _            => "badge-gray",
    };
    let sel_full       = if autonomy == "full"       { " sel" } else { "" };
    let sel_supervised = if autonomy == "supervised" { " sel" } else { "" };
    let sel_readonly   = if autonomy == "readonly"   { " sel" } else { "" };
    let ssh_keys  = read_ssh_keys();
    let uptime_s  = state.start_time.elapsed().unwrap_or_default().as_secs();
    let ip        = get_local_ip();

    // SSH key list HTML
    let keys_html: String = if ssh_keys.is_empty() {
        r#"<div class="no-keys">No SSH keys configured. Add one below to enable SSH access.</div>"#.to_string()
    } else {
        ssh_keys.iter().enumerate().map(|(i, k)| {
            let short = if k.len() > 72 { format!("{}…", &k[..72]) } else { k.clone() };
            format!(
                r#"<div class="key-row"><span class="key-type">{}</span><span class="key-val">{}</span><button class="btn btn-danger btn-sm" onclick="removeKey({})">Remove</button></div>"#,
                html_escape(k.split_whitespace().next().unwrap_or("key")),
                html_escape(&short), i
            )
        }).collect()
    };

    // Configured channels — read from live openclaw config
    let configured_channels = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c)  => list_configured_channels(&c),
        Err(_) => Vec::new(),
    };
    let ch_chips_html: String = if configured_channels.is_empty() {
        r#"<div class="no-keys" style="margin-bottom:0">No channels configured.</div>"#.to_string()
    } else {
        configured_channels.iter().map(|ch| format!(
            r#"<div class="ch-chip">{} {}<button class="ch-remove" onclick="removeCh('{}')">✕</button></div>"#,
            channel_icon(ch), channel_display_name(ch), html_escape(ch)
        )).collect::<Vec<_>>().join("")
    };
    let ch_count_display = format!("{} active", configured_channels.len());

    // Provider panel visibility
    let vis      = |p: &str| if provider == p { " vis" } else { "" };
    let sel_card = |p: &str| if provider == p { " sel" } else { "" };

    // Hardware selectors
    let sel_std = if hw_mode != "WIND_TUNNEL" { " sel" } else { "" };
    let sel_wt  = if hw_mode == "WIND_TUNNEL"  { " sel" } else { "" };
    let hw_mode_display = if hw_mode == "WIND_TUNNEL" { "Wind Tunnel" } else { "EdgeNode" };

    // Agent badge
    let agent_badge       = if agent_on { "Enabled" } else { "Disabled" };
    let agent_badge_class = if agent_on { "badge-green" } else { "badge-gray" };
    let agent_chk         = if agent_on { " checked" } else { "" };
    let agent_vis         = if agent_on { "" } else { "display:none" };

    let ssh_count  = ssh_keys.len();
    let ssh_plural = if ssh_count == 1 { "" } else { "s" };

    let channel_display  = if channel.is_empty()  { "None".to_string() } else { channel_display_name(&channel).to_string() };
    let provider_display = if provider.is_empty() { "None".to_string() } else { provider.clone() };

    format!(r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — {node_name}</title>
<style>
{css}
.toast{{position:fixed;bottom:24px;right:24px;padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;opacity:0;transform:translateY(8px);transition:all .3s;pointer-events:none;z-index:999}}
.toast.ok{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.toast.err{{background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5}}
.toast.vis{{opacity:1;transform:none}}
.page-hdr{{background:linear-gradient(135deg,#1e2d5a,#2d1e5a);padding:20px 32px;display:flex;align-items:center;justify-content:space-between}}
.page-hdr h1{{font-size:18px;font-weight:700;color:#fff}}
.page-hdr p{{color:#94a3b8;font-size:12px;margin-top:2px}}
.logout{{background:transparent;border:1px solid #3d4468;color:#94a3b8;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-family:inherit}}
.logout:hover{{border-color:#6366f1;color:#e2e8f0}}
.info-row{{display:flex;flex-wrap:wrap;gap:8px;padding:14px 32px;background:#13162a;border-bottom:1px solid #2d3148}}
.info-item{{font-size:12px;color:#64748b;display:flex;align-items:center;gap:6px}}
.info-item span{{background:#1a1d27;border:1px solid #2d3148;border-radius:6px;padding:2px 8px;color:#94a3b8;font-size:12px}}
.section{{border-bottom:1px solid #2d3148}}
.section:last-child{{border-bottom:none}}
.section-hdr{{padding:16px 32px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;user-select:none}}
.section-hdr:hover{{background:#1e2030}}
.section-title{{font-size:14px;font-weight:600;color:#e2e8f0;display:flex;align-items:center;gap:8px}}
.section-badge{{font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px}}
.badge-green{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.badge-orange{{background:#44250a;color:#fb923c}}
.badge-gray{{background:#1a1d27;border:1px solid #3d4468;color:#64748b}}
.section-arrow{{color:#475569;font-size:12px}}
.section-body{{padding:4px 32px 20px;display:none}}
.key-row{{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #1e2030}}
.key-row:last-child{{border-bottom:none}}
.key-type{{font-size:11px;font-weight:700;color:#6366f1;background:#1e1d3f;padding:2px 6px;border-radius:4px;flex-shrink:0}}
.key-val{{flex:1;font-size:12px;font-family:monospace;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.btn-sm{{padding:5px 10px;font-size:12px}}
.no-keys{{font-size:13px;color:#475569;padding:8px 0;margin-bottom:8px}}
.toggle-row{{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#0f1117;border:1px solid #2d3148;border-radius:10px;margin-bottom:10px}}
.toggle-label{{font-size:14px;font-weight:600;color:#e2e8f0}}
.toggle{{position:relative;width:48px;height:26px;flex-shrink:0}}.toggle input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#2d3148;border-radius:13px;transition:.3s}}
.slider:before{{position:absolute;content:'';height:18px;width:18px;left:4px;bottom:4px;background:#64748b;border-radius:50%;transition:.3s}}
input:checked+.slider{{background:#6366f1}}input:checked+.slider:before{{transform:translateX(22px);background:#fff}}
.provider-grid{{display:flex;flex-direction:column;gap:6px;margin-bottom:10px}}
.pcard{{padding:10px 14px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:all .2s;color:#94a3b8}}
.pcard:hover,.pcard.sel{{border-color:#6366f1;color:#a5b4fc}}.pcard.sel{{background:#1e1d3f}}
.pcard-name{{font-size:13px;font-weight:600}}.pcard-desc{{font-size:11px;color:#475569;margin-top:1px}}
.provider-creds{{display:none;margin-top:8px}}.provider-creds.vis{{display:block}}
.ch-chips{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:4px;min-height:24px}}
.ch-chip{{display:inline-flex;align-items:center;gap:6px;background:#1a1d27;border:1px solid #2d3148;border-radius:20px;padding:5px 10px 5px 12px;font-size:13px;color:#e2e8f0}}
.ch-remove{{background:none;border:none;color:#475569;cursor:pointer;font-size:15px;padding:0 0 0 4px;line-height:1}}.ch-remove:hover{{color:#fca5a5}}
.modal-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px}}
.modal{{background:#1a1d27;border:1px solid #2d3148;border-radius:16px;width:100%;max-width:720px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden}}
.modal-hdr{{padding:16px 20px;border-bottom:1px solid #2d3148;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}}
.modal-hdr h3{{font-size:15px;font-weight:700;color:#e2e8f0}}
.modal-close{{background:none;border:none;color:#64748b;font-size:22px;cursor:pointer;line-height:1;padding:0}}.modal-close:hover{{color:#e2e8f0}}
.modal-body{{overflow-y:auto;flex:1}}
.diff-hunk{{margin-bottom:0}}
.diff-hunk-hdr{{background:#1e2030;padding:3px 12px;font-size:11px;font-family:monospace;color:#475569;border-top:1px solid #2d3148;border-bottom:1px solid #2d3148}}
.diff-line{{display:flex;font-size:12px;font-family:monospace;line-height:1.7;padding:0 12px}}
.diff-line.ctx{{color:#64748b}}.diff-line.add{{background:#0d2618;color:#86efac}}.diff-line.del{{background:#2d1515;color:#fca5a5}}
.diff-gutter{{width:14px;flex-shrink:0;user-select:none;opacity:.5}}.diff-text{{flex:1;white-space:pre;overflow-x:auto}}
.cfg-viewer{{background:#0f1117;border-radius:8px;overflow:hidden;margin-bottom:10px;border:1px solid #2d3148}}
.cfg-pre{{margin:0;padding:14px;font-size:12px;font-family:monospace;color:#94a3b8;max-height:420px;overflow-y:auto;white-space:pre}}
.cfg-actions{{display:flex;gap:8px;margin-top:8px}}
.toast-link{{color:#818cf8;background:none;border:none;cursor:pointer;font-size:13px;text-decoration:underline;padding:0;margin-left:10px;font-family:inherit}}
</style></head><body style="align-items:flex-start;padding:0">
<div class="card" style="max-width:680px;border-radius:0 0 16px 16px;min-height:100vh">
  <div class="page-hdr">
    <div>
      <h1>🜲 {node_name}</h1>
      <p>Node Manager v{version} &nbsp;·&nbsp; {ip} &nbsp;·&nbsp; up {uptime}</p>
    </div>
    <form method="POST" action="/logout" style="margin:0"><button type="submit" class="logout">Log out</button></form>
  </div>
  <div class="info-row">
    <div class="info-item">Agent <span id="info-agent">{agent_badge}</span></div>
    <div class="info-item">Hardware <span id="info-hw">{hw_mode_display}</span></div>
    <div class="info-item">Channel <span>{channel_display}</span></div>
    <div class="info-item">Provider <span>{provider_display}</span></div>
    <div class="info-item">Autonomy <span>{autonomy_display}</span></div>
  </div>

  <!-- SSH KEYS -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('ssh')">
      <div class="section-title"><span>🔑</span> SSH Keys <span class="section-badge badge-green">{ssh_count} key{ssh_plural}</span></div>
      <span class="section-arrow" id="arr-ssh">▼</span>
    </div>
    <div class="section-body" id="sec-ssh" style="display:block">
      <div id="key-list">{keys_html}</div>
      <div style="margin-top:12px">
        <label>Add SSH public key</label>
        <textarea id="newKey" placeholder="ssh-ed25519 AAAA… or ssh-rsa AAAA…"></textarea>
        <div style="margin-top:8px"><button class="btn btn-primary" onclick="addKey()">Add Key</button></div>
      </div>
    </div>
  </div>

  <!-- AI AGENT -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('agent')">
      <div class="section-title"><span>🤖</span> AI Agent <span class="section-badge {agent_badge_class}" id="badge-agent">{agent_badge}</span></div>
      <span class="section-arrow" id="arr-agent">▼</span>
    </div>
    <div class="section-body" id="sec-agent">
      <div class="toggle-row">
        <div class="toggle-label">Enable OpenClaw AI agent</div>
        <label class="toggle"><input type="checkbox" id="agentToggle"{agent_chk} onchange="toggleAgent(this.checked)"><span class="slider"></span></label>
      </div>
      <div id="agentDetails" style="{agent_vis}">
        <div class="info-box" style="margin-top:0">Agent is running. Use the Channels section below to add or remove integrations without re-onboarding, or the Provider section to hot-swap the AI engine.</div>
      </div>
    </div>
  </div>

  <!-- AUTONOMY -->
  <div class="section" id="sec-autonomy-wrap" style="{autonomy_section_vis}">
    <div class="section-hdr" onclick="toggleSection('au')">
      <div class="section-title"><span>🎚️</span> Agent Autonomy <span class="section-badge {au_badge_class}" id="badge-au">{autonomy_display}</span></div>
      <span class="section-arrow" id="arr-au">▼</span>
    </div>
    <div class="section-body" id="sec-au">
     <div class="hw-opts" id="au-opts" style="flex-direction:column">
        <div class="hw-opt{sel_full}" onclick="selAu('full',this)">
        <div class="hw-opt-name">⚡ Full</div>
        <div class="hw-opt-desc">The agent acts autonomously — executes commands and makes decisions without asking for approval first.</div>
        </div>
        <div class="hw-opt{sel_supervised}" onclick="selAu('supervised',this)">
        <div class="hw-opt-name">👁 Supervised</div>
        <div class="hw-opt-desc">The agent proposes actions and waits for your approval before executing anything.</div>
        </div>
        <div class="hw-opt{sel_readonly}" onclick="selAu('readonly',this)">
        <div class="hw-opt-name">🔒 Read-Only</div>
        <div class="hw-opt-desc">The agent has read-only access — it can observe and advise but cannot run any commands.</div>
        </div>
        </div>
      <div class="info-box" id="au-info" style="margin-top:0;background:#0f1f2e;border-color:#1e3a5f;color:#93c5fd;display:{au_info_vis}"><strong>🛡 Risk surface is well contained.</strong> A strict command allowlist is already enforced — <code>curl</code> and <code>wget</code> are blocked. The agent can only write inside <code>/var/lib/zeroclaw/workspace</code> (enforced by <code>allowed_roots</code>) and cannot touch system files (enforced by <code>forbidden_paths</code>).</div>
      <div style="margin-top:12px"><button class="btn btn-primary" id="au-save-btn" onclick="saveAutonomy()">Save Autonomy</button></div>
    </div>
  </div>

  <!-- CHANNELS -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('ch')">
      <div class="section-title"><span>💬</span> Channels <span class="section-badge badge-gray" id="badge-ch">{ch_count_display}</span></div>
      <span class="section-arrow" id="arr-ch">▼</span>
    </div>
    <div class="section-body" id="sec-ch">
      <div class="ch-chips" id="ch-chips">{ch_chips_html}</div>
      <div class="divider" style="margin:16px 0 12px"></div>
      <label>Add or replace a channel</label>
      <select id="new-ch-sel" onchange="onNewCh()">
        <option value="">— select channel —</option>
        <optgroup label="Messaging">
          <option value="telegram">✈️ Telegram</option>
          <option value="discord">🎮 Discord</option>
          <option value="whatsapp">💬 WhatsApp</option>
          <option value="signal">🔒 Signal</option>
          <option value="slack">💼 Slack</option>
          <option value="imessage">🍎 iMessage</option>
        </optgroup>
        <optgroup label="Business / Productivity">
          <option value="email">📧 Email</option>
          <option value="mattermost">🔵 Mattermost</option>
          <option value="nextcloud_talk">☁️ Nextcloud Talk</option>
          <option value="linq">📱 Linq</option>
          <option value="webhook">🔗 Webhook</option>
        </optgroup>
        <optgroup label="Open / Technical">
          <option value="matrix">🔷 Matrix</option>
          <option value="irc">🖥️ IRC</option>
          <option value="nostr">⚡ Nostr</option>
          <option value="cli">💻 CLI</option>
        </optgroup>
        <optgroup label="Asian Platforms">
          <option value="dingtalk">🔔 DingTalk</option>
          <option value="qq">🐧 QQ</option>
          <option value="lark">🦅 Lark</option>
          <option value="feishu">🪶 Feishu</option>
        </optgroup>
      </select>
      <div id="new-ch-fields" style="margin-top:8px"></div>
      <div style="margin-top:12px">
        <button class="btn btn-primary" id="new-ch-btn" onclick="addCh()" disabled>Add Channel</button>
      </div>
    </div>
  </div>

  <!-- AI PROVIDER -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('pv')">
      <div class="section-title"><span>✦</span> AI Provider <span class="section-badge badge-gray">{provider_display}</span></div>
      <span class="section-arrow" id="arr-pv">▼</span>
    </div>
    <div class="section-body" id="sec-pv">
      <div class="provider-grid">
        <div class="pcard{sel_google}" onclick="selPv('google',this)"><div><div class="pcard-name">✦ Google Gemini</div><div class="pcard-desc">Free tier available</div></div></div>
        <div class="pcard{sel_anthropic}" onclick="selPv('anthropic',this)"><div><div class="pcard-name">◆ Anthropic Claude</div><div class="pcard-desc">Best for reasoning</div></div></div>
        <div class="pcard{sel_openai}" onclick="selPv('openai',this)"><div><div class="pcard-name">⬡ OpenAI</div><div class="pcard-desc">GPT-4o, o4-mini</div></div></div>
        <div class="pcard{sel_openrouter}" onclick="selPv('openrouter',this)"><div><div class="pcard-name">⇄ OpenRouter</div><div class="pcard-desc">300+ models, one key</div></div></div>
        <div class="pcard{sel_ollama}" onclick="selPv('ollama',this)"><div><div class="pcard-name">🦙 Ollama (Local)</div><div class="pcard-desc">Private, no API cost</div></div></div>
      </div>
      <div id="mp-google" class="provider-creds{vis_google}"><label>Gemini API Key</label><input type="password" id="m-gkey" placeholder="AIzaSy..."><label>Model</label><select id="m-gmdl"><option value="gemini-2.5-flash">gemini-2.5-flash</option><option value="gemini-2.5-pro">gemini-2.5-pro</option><option value="gemini-2.0-flash">gemini-2.0-flash</option></select></div>
      <div id="mp-anthropic" class="provider-creds{vis_anthropic}"><label>Claude API Key</label><input type="password" id="m-akey" placeholder="sk-ant-..."><label>Model</label><select id="m-amdl"><option value="claude-haiku-4-5-20251001">claude-haiku (Fast)</option><option value="claude-sonnet-4-6">claude-sonnet (Recommended)</option></select></div>
      <div id="mp-openai" class="provider-creds{vis_openai}"><label>OpenAI API Key</label><input type="password" id="m-okey" placeholder="sk-..."><label>Model</label><select id="m-omdl"><option value="gpt-4o-mini">gpt-4o-mini</option><option value="gpt-4o">gpt-4o</option><option value="o4-mini">o4-mini</option></select></div>
      <div id="mp-openrouter" class="provider-creds{vis_openrouter}"><label>OpenRouter API Key</label><input type="password" id="m-rkey" placeholder="sk-or-..."><label>Model ID</label><input type="text" id="m-rmdl" placeholder="openrouter/auto"></div>
      <div id="mp-ollama" class="provider-creds{vis_ollama}"><label>Ollama URL</label><input type="url" id="m-lurl" value="http://127.0.0.1:11434"><label>Model name</label><input type="text" id="m-lmdl" placeholder="llama3.2"></div>
      <div style="margin-top:14px"><button class="btn btn-primary" onclick="saveProvider()">Save &amp; Restart Agent</button></div>
    </div>
  </div>

  <!-- HARDWARE MODE -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('hw')">
      <div class="section-title"><span>⚙️</span> Hardware Mode <span class="section-badge badge-green" id="hw-badge">{hw_mode_display}</span></div>
      <span class="section-arrow" id="arr-hw">▼</span>
    </div>
    <div class="section-body" id="sec-hw">
      <div class="hw-opts">
        <div class="hw-opt{sel_std}" onclick="selHw('STANDARD',this)">
          <div class="hw-opt-name">🌐 Standard EdgeNode</div>
          <div class="hw-opt-desc">Always-on Holochain peer</div>
        </div>
        <div class="hw-opt{sel_wt}" onclick="selHw('WIND_TUNNEL',this)">
          <div class="hw-opt-name">🌀 Wind Tunnel</div>
          <div class="hw-opt-desc">Network stress-tester</div>
        </div>
      </div>
      <div style="margin-top:10px"><button class="btn btn-primary" onclick="saveHardware()">Apply Mode</button></div>
    </div>
  </div>

  <!-- PASSWORD -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('pw')">
      <div class="section-title"><span>🔐</span> Change Password</div>
      <span class="section-arrow" id="arr-pw">▼</span>
    </div>
    <div class="section-body" id="sec-pw">
      <div class="info-box" style="margin-top:0;margin-bottom:14px">Store your new password securely. It cannot be recovered if lost.</div>
      <label>Current password</label><input type="password" id="pw-cur" autocomplete="current-password">
      <label>New password</label><input type="password" id="pw-new" autocomplete="new-password">
      <label>Confirm new password</label><input type="password" id="pw-cfm" autocomplete="new-password">
      <div style="margin-top:14px"><button class="btn btn-primary" onclick="changePassword()">Update Password</button></div>
    </div>
  </div>

  <!-- SOFTWARE UPDATE -->
  <div class="section">
    <div class="section-hdr" onclick="toggleSection('upd')">
      <div class="section-title"><span>🔄</span> Software Update <span class="section-badge badge-gray">v{version}</span></div>
      <span class="section-arrow" id="arr-upd">▼</span>
    </div>
    <div class="section-body" id="sec-upd">
      <p style="font-size:13px;color:#64748b;margin-bottom:14px">Nodes check for updates automatically every hour from GitHub Releases. You can also trigger an immediate check.</p>
      <button class="btn btn-primary" onclick="triggerUpdate()" id="upd-btn">Check for Updates Now</button>
      <div id="upd-msg" style="margin-top:10px;font-size:13px;color:#64748b;display:none"></div>
    </div>
  </div>
<!-- RAW CONFIG -->
  <div class="section">
    <div class="section-hdr" onclick="loadCfgSection()">
      <div class="section-title"><span>📄</span> Raw Config</div>
      <span class="section-arrow" id="arr-cfg">▶</span>
    </div>
    <div class="section-body" id="sec-cfg">
      <div class="info-box" style="margin-top:0;margin-bottom:10px;background:#1a1d27;border-color:#2d3148;color:#64748b;font-size:12px"><strong>About browser warnings:</strong> Your node manager is served over your local network (HTTP). Some browsers may warn when downloading files from HTTP sites — this is safe to ignore. The connection stays on your private network.</div><div class="cfg-viewer"><pre class="cfg-pre" id="cfg-pre">Loading…</pre></div>
      <div class="cfg-actions">
        <button class="btn btn-secondary" onclick="copyCfg()">Copy</button>
        <a id="cfg-dl" href="/manage/config" download="config.toml" class="btn btn-secondary">Download</a>
        <button class="btn btn-secondary" onclick="fetchCfg()">↺ Refresh</button>
      </div>
    </div>
  </div>
</div>
<div class="modal-overlay" id="diff-modal" style="display:none" onclick="if(event.target===this)closeDiff()">
  <div class="modal">
    <div class="modal-hdr">
      <h3>⬅ Config diff</h3>
      <button class="modal-close" onclick="closeDiff()">✕</button>
    </div>
    <div class="modal-body" id="diff-body"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
let curPv='{provider_js}';
let curHw='{hw_mode}';

function toggleSection(id){{
  const body=document.getElementById('sec-'+id);
  const arr=document.getElementById('arr-'+id);
  if(!body)return;
  const open=body.style.display==='block';
  body.style.display=open?'none':'block';
  arr.textContent=open?'▶':'▼';
}}
['agent','ch','pv','hw','pw','upd'].forEach(id=>toggleSection(id));

function toast(msg,ok,before,after){{
  const t=document.getElementById('toast');
  t.innerHTML='';
  const span=document.createElement('span');span.textContent=msg;t.appendChild(span);
  if(ok&&before!==undefined&&after!==undefined&&before!==after){{
    const btn=document.createElement('button');
    btn.className='toast-link';btn.textContent='View diff';
    btn.onclick=()=>openDiff(before,after);
    t.appendChild(btn);
  }}
  t.className='toast '+(ok?'ok':'err')+' vis';
  const hasDiff=ok&&before!==undefined&&after!==undefined&&before!==after;
  clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove('vis'),hasDiff?7000:4000);
}}

async function api(path,payload){{
  const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(payload)}});
  const text=await r.text();
  if(!r.ok)throw new Error(text||'Server error '+r.status);
  try{{return JSON.parse(text);}}catch{{return {{}};}}
}}

function v(id){{const e=document.getElementById(id);return e?e.value.trim():'';}}

async function addKey(){{
  const key=document.getElementById('newKey').value.trim();
  if(!key)return toast('Paste a public key first',false);
  try{{await api('/manage/ssh/add',{{key}});document.getElementById('newKey').value='';toast('Key added — reloading…',true);setTimeout(()=>location.reload(),800);}}
  catch(e){{toast('Error: '+e.message,false);}}
}}
async function removeKey(i){{
  if(!confirm('Remove this SSH key?'))return;
  try{{await api('/manage/ssh/remove',{{index:i}});toast('Key removed — reloading…',true);setTimeout(()=>location.reload(),800);}}
  catch(e){{toast('Error: '+e.message,false);}}
}}

function toggleAgent(on){{
  document.getElementById('agentDetails').style.display=on?'block':'none';
  document.getElementById('badge-agent').textContent=on?'Enabled':'Disabled';
  document.getElementById('badge-agent').className='section-badge '+(on?'badge-green':'badge-gray');
  const auSec=document.getElementById('sec-autonomy-wrap');
  if(auSec)auSec.style.display=on?'':'none';
  api('/manage/agent',{{enabled:on}})
    .then(d=>toast(on?'Agent enabled — restarting…':'Agent disabled',true,d.diff_before,d.diff_after))
    .catch(e=>toast('Error: '+e.message,false));
}}

// ── Channels (field schema mirrors the onboarding CH object) ──────────────────
const CH_F={{
  cli:[],
  telegram:[{{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:'123456789:ABC...'}},{{id:'allowed_users',label:'Allowed User IDs (* = anyone)',type:'text',ph:'*',def:'*'}}],
  discord:[{{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:'MTxx...'}},{{id:'guild_id',label:'Guild ID (optional)',type:'text',ph:''}},{{id:'allowed_users',label:'Allowed User IDs (* = anyone)',type:'text',ph:'*',def:'*'}}],
  slack:[{{id:'bot_token',label:'Bot Token (xoxb-...)',type:'password',req:true,ph:'xoxb-...'}},{{id:'app_token',label:'App Token (xapp-...)',type:'password',req:true,ph:'xapp-...'}},{{id:'allowed_users',label:'Allowed Member IDs (* = anyone)',type:'text',ph:'*',def:'*'}}],
  mattermost:[{{id:'url',label:'Server URL',type:'url',req:true,ph:'https://mm.example.com'}},{{id:'bot_token',label:'Bot Token',type:'password',req:true,ph:''}},{{id:'channel_id',label:'Channel ID',type:'text',req:true,ph:''}},{{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}}],
  matrix:[{{id:'homeserver',label:'Homeserver URL',type:'url',req:true,ph:'https://matrix.org'}},{{id:'access_token',label:'Bot Access Token',type:'password',req:true,ph:'syt_...'}},{{id:'room_id',label:'Room ID',type:'text',req:true,ph:'!abc123:matrix.org'}},{{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}},{{id:'user_id',label:'Bot User ID (optional)',type:'text',ph:'@bot:matrix.org'}},{{id:'device_id',label:'Device ID (optional, for E2EE)',type:'text',ph:''}}],
  signal:[{{id:'http_url',label:'signal-cli URL',type:'url',req:true,ph:'http://127.0.0.1:8686',def:'http://127.0.0.1:8686'}},{{id:'account',label:'Registered Number',type:'text',req:true,ph:'+12345678901'}},{{id:'allowed_from',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}}],
  whatsapp:[{{id:'access_token',label:'Access Token',type:'password',req:true,ph:'EAAB...'}},{{id:'phone_number_id',label:'Phone Number ID',type:'text',req:true,ph:'123456789012345'}},{{id:'verify_token',label:'Verify Token',type:'text',req:true,ph:'my-verify-token'}},{{id:'allowed_numbers',label:'Allowed Numbers E.164 (* = anyone)',type:'text',ph:'*',def:'*'}}],
  webhook:[{{id:'port',label:'Port',type:'number',ph:'8080',def:'8080'}},{{id:'secret',label:'Shared Secret (optional)',type:'password',ph:''}}],
  email:[{{id:'imap_host',label:'IMAP Host',type:'text',req:true,ph:'imap.example.com'}},{{id:'imap_port',label:'IMAP Port',type:'number',ph:'993',def:'993'}},{{id:'smtp_host',label:'SMTP Host',type:'text',req:true,ph:'smtp.example.com'}},{{id:'smtp_port',label:'SMTP Port',type:'number',ph:'465',def:'465'}},{{id:'username',label:'Username',type:'text',req:true,ph:'bot@example.com'}},{{id:'password',label:'Password',type:'password',req:true,ph:''}},{{id:'from_address',label:'From Address',type:'text',req:true,ph:'bot@example.com'}},{{id:'allowed_senders',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}}],
  irc:[{{id:'server',label:'IRC Server',type:'text',req:true,ph:'irc.libera.chat'}},{{id:'port',label:'Port',type:'number',ph:'6697',def:'6697'}},{{id:'nickname',label:'Bot Nickname',type:'text',req:true,ph:'mybot'}},{{id:'channels',label:'Channels (comma-sep)',type:'text',req:true,ph:'#mychannel'}},{{id:'allowed_users',label:'Allowed Nicks (* = anyone)',type:'text',ph:'*',def:'*'}}],
  lark:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:'cli_...'}},{{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},{{id:'allowed_users',label:'Allowed Open IDs (* = anyone)',type:'text',ph:'*',def:'*'}},{{id:'receive_mode',label:'Receive Mode',type:'select',opts:[{{v:'websocket',l:'WebSocket'}},{{v:'webhook',l:'Webhook'}}]}}],
  feishu:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:'cli_...'}},{{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},{{id:'allowed_users',label:'Allowed Open IDs (* = anyone)',type:'text',ph:'*',def:'*'}},{{id:'receive_mode',label:'Receive Mode',type:'select',opts:[{{v:'websocket',l:'WebSocket'}},{{v:'webhook',l:'Webhook'}}]}}],
  nostr:[{{id:'private_key',label:'Private Key (nsec or hex)',type:'password',req:true,ph:'nsec1...'}},{{id:'allowed_pubkeys',label:'Allowed Pubkeys (* = anyone)',type:'text',ph:'*',def:'*'}},{{id:'relays',label:'Relays (comma-sep)',type:'text',ph:'wss://relay.damus.io',def:'wss://relay.damus.io,wss://nos.lol'}}],
  dingtalk:[{{id:'client_id',label:'Client ID',type:'text',req:true,ph:'ding...'}},{{id:'client_secret',label:'Client Secret',type:'password',req:true,ph:''}},{{id:'allowed_users',label:'Allowed Staff IDs (* = anyone)',type:'text',ph:'*',def:'*'}}],
  qq:[{{id:'app_id',label:'App ID',type:'text',req:true,ph:''}},{{id:'app_secret',label:'App Secret',type:'password',req:true,ph:''}},{{id:'allowed_users',label:'Allowed QQ IDs (* = anyone)',type:'text',ph:'*',def:'*'}}],
  nextcloud_talk:[{{id:'base_url',label:'Nextcloud URL',type:'url',req:true,ph:'https://cloud.example.com'}},{{id:'app_token',label:'App Token',type:'password',req:true,ph:''}},{{id:'allowed_users',label:'Allowed Users (* = anyone)',type:'text',ph:'*',def:'*'}}],
  linq:[{{id:'api_token',label:'API Token',type:'password',req:true,ph:''}},{{id:'from_phone',label:'From Phone (E.164)',type:'text',req:true,ph:'+12025551234'}},{{id:'allowed_senders',label:'Allowed Senders (* = anyone)',type:'text',ph:'*',def:'*'}}],
  imessage:[{{id:'allowed_contacts',label:'Allowed Contacts (* = anyone)',type:'text',ph:'*',def:'*'}}],
}};

function onNewCh(){{
  const t=document.getElementById('new-ch-sel').value;
  document.getElementById('new-ch-btn').disabled=!t;
  const div=document.getElementById('new-ch-fields');
  if(!t){{div.innerHTML='';return;}}
  if(!CH_F[t]||!CH_F[t].length){{div.innerHTML='<div class="info-box" style="margin-top:0">No credentials needed — just click Add Channel.</div>';return;}}
  let html='';
  for(const f of CH_F[t]){{
    html+='<label>'+f.label+'</label>';
    if(f.opts){{
      html+='<select id="nf_'+f.id+'">';
      for(const o of f.opts)html+='<option value="'+o.v+'">'+o.l+'</option>';
      html+='</select>';
    }}else{{
      html+='<input type="'+(f.type||'text')+'" id="nf_'+f.id+'" placeholder="'+(f.ph||'')+'" value="'+(f.def||'')+'">';
    }}
  }}
  div.innerHTML=html;
}}

async function addCh(){{
  const t=document.getElementById('new-ch-sel').value;
  if(!t)return;
  const payload={{channel_type:t}};
  if(CH_F[t]){{for(const f of CH_F[t])payload[f.id]=(document.getElementById('nf_'+f.id)||{{}}).value||'';}}
  try{{
    const d=await api('/manage/channels/add',payload);
    toast('Channel added — agent restarting…',true,d.diff_before,d.diff_after);
    setTimeout(()=>location.reload(),1200);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function removeCh(name){{
  if(!confirm('Remove '+name+' channel? The agent will restart.'))return;
  try{{
    const d=await api('/manage/channels/remove',{{channel:name}});
    toast('Channel removed — agent restarting…',true,d.diff_before,d.diff_after);
    setTimeout(()=>location.reload(),1200);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

function selPv(pv,el){{
  curPv=pv;
  document.querySelectorAll('.pcard').forEach(c=>c.classList.remove('sel'));
  el.classList.add('sel');
  document.querySelectorAll('.provider-creds').forEach(c=>c.classList.remove('vis'));
  document.getElementById('mp-'+pv).classList.add('vis');
}}

async function saveProvider(){{
  let key='',model='',apiUrl='';
  if(curPv==='google'){{key=v('m-gkey');model=v('m-gmdl');}}
  else if(curPv==='anthropic'){{key=v('m-akey');model=v('m-amdl');}}
  else if(curPv==='openai'){{key=v('m-okey');model=v('m-omdl');}}
  else if(curPv==='openrouter'){{key=v('m-rkey');model=v('m-rmdl');}}
  else if(curPv==='ollama'){{apiUrl=v('m-lurl');model=v('m-lmdl');}}
  try{{
    const d=await api('/manage/provider',{{provider:curPv,model,apiKey:key,apiUrl}});
    toast('Provider updated — agent restarting…',true,d.diff_before,d.diff_after);
    setTimeout(()=>location.reload(),1500);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

function selHw(mode,el){{
  curHw=mode;
  document.querySelectorAll('.hw-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
}}

let mAu='{autonomy_key}';
function selAu(lvl,el){{
  mAu=lvl;
  document.querySelectorAll('#au-opts .hw-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
}}
async function saveAutonomy(){{
  const nameMap={{full:'Full',supervised:'Supervised',readonly:'Read-Only'}};
  try{{
    const d=await api('/manage/autonomy',{{level:mAu}});
    document.getElementById('badge-au').textContent=nameMap[mAu]||mAu;
    document.getElementById('badge-au').className='section-badge '+
      (mAu==='full'?'badge-green':mAu==='supervised'?'badge-orange':'badge-gray');
    toast('Autonomy set to '+(nameMap[mAu]||mAu)+' — agent restarting…',true,d.diff_before,d.diff_after);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function saveHardware(){{
  try{{
    await api('/manage/hardware',{{mode:curHw}});
    document.getElementById('hw-badge').textContent=curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    toast('Hardware mode updated',true);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

async function changePassword(){{
  const cur=v('pw-cur'),nw=v('pw-new'),cfm=v('pw-cfm');
  if(!cur||!nw)return toast('Fill in all password fields',false);
  if(nw!==cfm)return toast('New passwords do not match',false);
  if(nw.length<8)return toast('Password must be at least 8 characters',false);
  try{{
    await api('/manage/password',{{current:cur,newPassword:nw}});
    ['pw-cur','pw-new','pw-cfm'].forEach(id=>document.getElementById(id).value='');
    toast('Password updated',true);
  }}catch(e){{toast('Error: '+e.message,false);}}
}}

// ── Diff engine ───────────────────────────────────────────────────────────────
function escHtml(s){{return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}

function computeDiff(before,after){{
  const a=before.split('\n'),b=after.split('\n');
  const n=a.length,m=b.length;
  const dp=Array.from({{length:n+1}},()=>new Int32Array(m+1));
  for(let i=n-1;i>=0;i--)for(let j=m-1;j>=0;j--)
    dp[i][j]=a[i]===b[j]?dp[i+1][j+1]+1:Math.max(dp[i+1][j],dp[i][j+1]);
  const ops=[];let i=0,j=0;
  while(i<n||j<m){{
    if(i<n&&j<m&&a[i]===b[j]){{ops.push(['=',a[i]]);i++;j++;}}
    else if(j<m&&(i>=n||dp[i][j+1]>=dp[i+1][j])){{ops.push(['+',b[j]]);j++;}}
    else{{ops.push(['-',a[i]]);i++;}}
  }}
  const CTX=3;
  const changed=ops.map((o,idx)=>o[0]!=='='?idx:-1).filter(idx=>idx>=0);
  if(!changed.length)return[];
  const ranges=[];
  let rs=Math.max(0,changed[0]-CTX),re=Math.min(ops.length,changed[0]+CTX+1);
  for(let k=1;k<changed.length;k++){{
    const ns=Math.max(0,changed[k]-CTX),ne=Math.min(ops.length,changed[k]+CTX+1);
    if(ns<=re)re=ne;else{{ranges.push([rs,re]);rs=ns;re=ne;}}
  }}
  ranges.push([rs,re]);
  const hunks=[];let al=1,bl=1;
  for(let q=0;q<ranges[0][0];q++){{const o=ops[q];if(o[0]==='='||o[0]==='-')al++;if(o[0]==='='||o[0]==='+')bl++;}}
  for(let ri=0;ri<ranges.length;ri++){{
    const[hs,he]=ranges[ri];
    const ac=ops.slice(hs,he).filter(o=>o[0]==='='||o[0]==='-').length;
    const bc=ops.slice(hs,he).filter(o=>o[0]==='='||o[0]==='+').length;
    const hunk={{header:'@@ -'+al+','+ac+' +'+bl+','+bc+' @@',lines:[]}};
    for(const[k,text] of ops.slice(hs,he)){{
      hunk.lines.push({{kind:k==='='?'ctx':k==='-'?'del':'add',text:(k==='='?' ':k==='-'?'-':'+')+text}});
      if(k==='='||k==='-')al++;if(k==='='||k==='+')bl++;
    }}
    hunks.push(hunk);
    if(ri+1<ranges.length)for(let q=he;q<ranges[ri+1][0];q++){{const o=ops[q];if(o[0]==='='||o[0]==='-')al++;if(o[0]==='='||o[0]==='+')bl++;}}
  }}
  return hunks;
}}

function openDiff(before,after){{
  const modal=document.getElementById('diff-modal');
  const body=document.getElementById('diff-body');
  modal.style.display='flex';
  const hunks=computeDiff(before,after);
  if(!hunks.length){{body.innerHTML='<div style="padding:20px;color:#64748b;font-size:13px">No config changes detected.</div>';return;}}
  let html='';
  for(const h of hunks){{
    html+='<div class="diff-hunk"><div class="diff-hunk-hdr">'+escHtml(h.header)+'</div>';
    for(const l of h.lines){{
      html+='<div class="diff-line '+l.kind+'"><span class="diff-gutter">'+escHtml(l.text[0])+'</span><span class="diff-text">'+escHtml(l.text.slice(1))+'</span></div>';
    }}
    html+='</div>';
  }}
  body.innerHTML=html;
}}
function closeDiff(){{document.getElementById('diff-modal').style.display='none';}}

// ── Raw config viewer ─────────────────────────────────────────────────────────
let cfgLoaded=false;
function loadCfgSection(){{
  toggleSection('cfg');
  const open=document.getElementById('sec-cfg').style.display==='block';
  if(open&&!cfgLoaded){{fetchCfg();cfgLoaded=true;}}
}}
async function fetchCfg(){{
  const pre=document.getElementById('cfg-pre');
  pre.textContent='Loading…';
  try{{
    const r=await fetch('/manage/config');
    if(!r.ok)throw new Error('HTTP '+r.status);
    pre.textContent=await r.text();
  }}catch(e){{pre.textContent='Error: '+e.message;}}
}}
function copyCfg(){{
  const text=document.getElementById('cfg-pre').textContent;
  if(navigator.clipboard&&window.isSecureContext){{
    navigator.clipboard.writeText(text)
      .then(()=>toast('Config copied to clipboard',true))
      .catch(()=>fallbackCopy(text));
  }}else{{fallbackCopy(text);}}
}}
function fallbackCopy(text){{
  const ta=document.createElement('textarea');
  ta.value=text;ta.style.position='fixed';ta.style.left='-9999px';
  document.body.appendChild(ta);ta.select();
  try{{document.execCommand('copy');toast('Config copied to clipboard',true);}}
  catch{{toast('Copy failed — use the Download button instead',false);}}
  document.body.removeChild(ta);
}}

async function triggerUpdate(){{
  const btn=document.getElementById('upd-btn');
  const msg=document.getElementById('upd-msg');
  btn.disabled=true;btn.textContent='Checking…';msg.style.display='none';
  try{{
    await api('/manage/update',{{}});
    msg.textContent='Update check triggered. If a newer version is found the node will restart automatically.';
    msg.style.display='block';
  }}catch(e){{msg.textContent='Error: '+e.message;msg.style.display='block';}}
  finally{{btn.disabled=false;btn.textContent='Check for Updates Now';}}
}}
</script>
</body></html>"#,
        css               = COMMON_CSS,
        node_name         = html_escape(&node_name),
        version           = VERSION,
        ip                = html_escape(&ip),
        uptime            = fmt_uptime(uptime_s),
        keys_html         = keys_html,
        ssh_count         = ssh_count,
        ssh_plural        = ssh_plural,
        ch_chips_html     = ch_chips_html,
        ch_count_display  = ch_count_display,
        agent_badge       = agent_badge,
        agent_badge_class = agent_badge_class,
        agent_chk         = agent_chk,
        agent_vis         = agent_vis,
        provider_display  = html_escape(&provider_display),
        provider_js       = html_escape(&provider),
        channel_display   = html_escape(&channel_display),
        hw_mode           = hw_mode,
        hw_mode_display   = hw_mode_display,
        sel_std           = sel_std,
        sel_wt            = sel_wt,
        sel_google        = sel_card("google"),
        sel_anthropic     = sel_card("anthropic"),
        sel_openai        = sel_card("openai"),
        sel_openrouter    = sel_card("openrouter"),
        sel_ollama        = sel_card("ollama"),
        vis_google        = vis("google"),
        vis_anthropic     = vis("anthropic"),
        vis_openai        = vis("openai"),
        vis_openrouter    = vis("openrouter"),
        autonomy_section_vis = if agent_on { "" } else { "display:none" },
        au_badge_class    = au_badge_class,
        autonomy_display  = autonomy_display,
        sel_full          = sel_full,
        sel_supervised    = sel_supervised,
        sel_readonly      = sel_readonly,
        au_info_vis       = if autonomy == "full" || autonomy == "supervised" { "block" } else { "none" },
        autonomy_key      = &autonomy,
        vis_ollama        = vis("ollama"),
    )
}

// ── Route handlers ─────────────────────────────────────────────────────────────

fn handle_submit(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
    _auth_hash: &Arc<Mutex<String>>,
) {
    let body      = &req.body;
    let node_name = json_str(body, "nodeName");
    let ssh_key   = json_str(body, "sshKey");
    let agent_on  = json_bool(body, "agentEnabled");
    let channel   = json_str(body, "channel");
    let provider  = json_str(body, "provider");
    let api_key   = json_str(body, "apiKey");
    let model     = json_str(body, "model");
    let api_url   = json_str(body, "apiUrl");
    let hw_mode   = json_str(body, "hwMode");
    let level = match json_str(body, "autonomyLevel") {
    "full"     => "full",
    "readonly" => "readonly",
    _          => "supervised",
};

    if node_name.is_empty() { send_json_err(stream, 400, "nodeName is required"); return; }

    // ── WiFi (AP mode) ───────────────────────────────────────────────────────
    let wifi_ssid = json_str(body, "wifiSsid");
    let wifi_pass = json_str(body, "wifiPass");
    if !wifi_ssid.is_empty() && !wifi_pass.is_empty() {
        eprintln!("[onboard] Connecting WiFi: {}", wifi_ssid);
        let _ = Command::new("nmcli")
            .args(["device", "wifi", "connect", wifi_ssid, "password", wifi_pass])
            .output();
        thread::sleep(Duration::from_secs(4));
    }

    // ── Ensure directories ───────────────────────────────────────────────────
    for dir in &["/etc/node-manager", SKILLS_DIR, QUADLET_DIR, WORKSPACE_DIR,
                 "/var/lib/edgenode", "/home/holo/.ssh"] {
        let _ = fs::create_dir_all(dir);
    }

    // ── SSH keys ─────────────────────────────────────────────────────────────
    if !ssh_key.trim().is_empty() {
        if !is_valid_ssh_pubkey(ssh_key) {
            send_json_err(stream, 400, "Invalid SSH public key format"); return;
        }
        if let Err(e) = write_ssh_keys(&[ssh_key.to_string()]) {
            send_json_err(stream, 500, &format!("Failed to write SSH key: {}", e)); return;
        }
        eprintln!("[onboard] SSH key written");
    }

    // ── Quadlets ─────────────────────────────────────────────────────────────
    let wt_hostname    = format!("nomad-client-{}", node_name);
    let edgenode_image = resolve_edgenode_image();
    let wt_image       = resolve_wind_tunnel_image();
    let _ = fs::write(format!("{}/edgenode.container", QUADLET_DIR),    build_edgenode_quadlet(&edgenode_image));
    let _ = fs::write(format!("{}/wind-tunnel.container", QUADLET_DIR), build_wind_tunnel_quadlet(&wt_hostname, &wt_image));
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();

    let _ = fs::write(format!("{}/mode_switch.txt", WORKSPACE_DIR),
        if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" });
    let initial_svc = if hw_mode == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };
    let _ = Command::new("systemctl").args(["start", initial_svc]).output();

    // ── Agent (optional) ─────────────────────────────────────────────────────
    if agent_on {
        if channel.is_empty() || provider.is_empty() {
            send_json_err(stream, 400, "channel and provider required when agent is enabled"); return;
        }
        let pv_cfg = match make_provider_config(provider, model, api_key, api_url) {
            Some(c) => c,
            None    => { send_json_err(stream, 400, "unknown provider"); return; }
        };

        // BUG FIX v5.1.0: ensure openclaw binary is present before calling onboard.
        // If missing, triggers openclaw-update.service --wait so onboarding never
        // races the OnBootSec=10min timer.
        if !ensure_openclaw_binary(stream) { return; }

        eprintln!("[onboard] Running openclaw onboard");
        if let Err(e) = run_openclaw_onboard(&pv_cfg) { send_json_err(stream, 500, &e); return; }
        write_openclaw_env(provider, api_key);

        let config = match fs::read_to_string(OPENCLAW_CONFIG) {
            Ok(c)  => c,
            Err(e) => { send_json_err(stream, 500, &format!("config not found: {}", e)); return; }
        };
        // Build channel TOML; payload uses {channel_type}_{field_id} key names.
        let channel_toml = build_channel_toml(body, channel);
        let config = strip_channel_sections(&config);
        let mut final_config = patch_openclaw_config(&config, level);
        // cli is a required field in ZeroClaw's [channels_config] schema —
        // always inject it, regardless of which channel the user selected.
        final_config = add_channel_to_config(&final_config, "cli", "");
        if channel != "cli" && !channel_toml.trim().is_empty() {
            // Insert channel sub-section right after [channels_config] block
            // so they remain contiguous (required by ZeroClaw's parser).
            final_config = insert_after_channels_section(&final_config, &channel_toml);
        }
        if let Err(e) = write_validated_config(&final_config) {
            send_json_err(stream, 500, &e); return;
        }

        let _ = fs::write(PROVIDER_FILE, format!(
            "provider={}\nmodel={}\napi_key={}\napi_url={}\n",
            toml_escape(provider), toml_escape(&pv_cfg.model),
            toml_escape(api_key), toml_escape(api_url)
        ));
        let _ = Command::new("chmod").args(["600", PROVIDER_FILE]).output();
        let _ = fs::write(format!("{}/holo-node.md", SKILLS_DIR), HOLO_NODE_SKILL);
        let _ = Command::new("systemctl").args(["start", "openclaw-daemon.service"]).output();

        let body_clone  = body.to_string();
        let channel_str = channel.to_string();
        let hw_str      = hw_mode.to_string();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(8));
            send_welcome_message(&channel_str, &body_clone, &hw_str);
        });
    }

    // ── Persist state ────────────────────────────────────────────────────────
    let mut kv = HashMap::new();
    kv.insert("onboarded".into(), "true".into());
    kv.insert("node_name".into(), node_name.to_string());
    kv.insert("hw_mode".into(), if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string());
    kv.insert("agent_enabled".into(), agent_on.to_string());
    kv.insert("channel".into(), channel.to_string());
    kv.insert("provider".into(), provider.to_string());
    kv.insert("model".into(), model.to_string());
    kv.insert("autonomy".into(), level.to_string());
    write_state_file(&kv);

    *state.node_name.lock().unwrap() = node_name.to_string();
    *state.hw_mode.lock().unwrap()   = if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string();
    *state.channel.lock().unwrap()   = channel.to_string();
    *state.provider.lock().unwrap()  = provider.to_string();
    *state.model.lock().unwrap()     = model.to_string();
    state.agent_enabled.store(agent_on, Ordering::Relaxed);
    state.onboarded.store(true, Ordering::Relaxed);

    eprintln!("[onboard] Complete. node={} agent={} hw={}", node_name, agent_on, hw_mode);
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_manage_status(stream: &mut TcpStream, state: &AppState) {
    let node_name = state.node_name.lock().unwrap().clone();
    let hw_mode   = state.hw_mode.lock().unwrap().clone();
    let channel   = state.channel.lock().unwrap().clone();
    let provider  = state.provider.lock().unwrap().clone();
    let model     = state.model.lock().unwrap().clone();
    let agent     = state.agent_enabled.load(Ordering::Relaxed);
    let uptime    = state.start_time.elapsed().unwrap_or_default().as_secs();
    let keys      = read_ssh_keys();
    let keys_json: String = keys.iter()
        .map(|k| format!("\"{}\"", k.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>().join(",");
    let autonomy = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c) => c.lines()
            .find(|l| l.trim_start().starts_with("level = "))
            .and_then(|l| l.split('"').nth(1))
            .unwrap_or("supervised").to_string(),
        Err(_) => "supervised".to_string(),
    };
    send_json_ok(stream, &format!(
        r#"{{"version":"{}","node_name":"{}","hw_mode":"{}","agent_enabled":{},"channel":"{}","provider":"{}","model":"{}","ssh_key_count":{},"ssh_keys":[{}],"uptime_secs":{},"autonomy":"{}"}}"#,
        VERSION, node_name, hw_mode, agent, channel, provider, model,
        keys.len(), keys_json, uptime, autonomy
    ));
}

fn handle_ssh_add(stream: &mut TcpStream, req: &Req) {
    let key = json_str(&req.body, "key");
    if key.is_empty() { send_json_err(stream, 400, "key is required"); return; }
    if !is_valid_ssh_pubkey(key) { send_json_err(stream, 400, "Invalid SSH public key format"); return; }
    let mut keys = read_ssh_keys();
    if keys.iter().any(|k| k == key) { send_json_err(stream, 409, "Key already present"); return; }
    keys.push(key.to_string());
    match write_ssh_keys(&keys) {
        Ok(()) => {
            notify_async("✅ A new SSH key has been added to this node.".to_string());
            send_json_ok(stream, r#"{"status":"added"}"#);
        },
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_ssh_remove(stream: &mut TcpStream, req: &Req) {
    let idx_str = {
        let needle = "\"index\":";
        match req.body.find(needle) {
            None    => { send_json_err(stream, 400, "index is required"); return; }
            Some(p) => req.body[p + needle.len()..].trim_start()
                .split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").to_string(),
        }
    };
    let idx: usize = match idx_str.parse() {
        Ok(i)  => i,
        Err(_) => { send_json_err(stream, 400, "invalid index"); return; }
    };
    let mut keys = read_ssh_keys();
    if idx >= keys.len() { send_json_err(stream, 404, "index out of range"); return; }
    keys.remove(idx);
    match write_ssh_keys(&keys) {
        Ok(()) => {
            notify_async("✅ An SSH key has been removed from this node.".to_string());
            send_json_ok(stream, r#"{"status":"removed"}"#);
        },
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_agent_toggle(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let enabled = json_bool(&req.body, "enabled");
    let before = if enabled { snapshot_config() } else { String::new() };

    let after;
    if enabled {
        // Bug fix v5.1.0: save existing channel config before openclaw onboard
        // (which rewrites config.toml with a fresh skeleton), then reapply after.
        let (channel_config, autonomy) = match fs::read_to_string(OPENCLAW_CONFIG) {
            Ok(c) => {
                let auto = c.lines()
                    .find(|l| l.trim_start().starts_with("level = "))
                    .and_then(|l| l.split('"').nth(1))
                    .unwrap_or("supervised").to_string();
                (extract_channel_config(&c), auto)
            },
            Err(_) => (String::new(), "supervised".to_string()),
        };

        // Read provider info
        let provider = state.provider.lock().unwrap().clone();
        let model = state.model.lock().unwrap().clone();
        let (api_key, api_url) = read_provider_file();

        let pv_cfg = match make_provider_config(&provider, &model, &api_key, &api_url) {
            Some(c) => c,
            None => {
                send_json_err(stream, 400, "no valid provider configured"); return;
            }
        };

        if !ensure_openclaw_binary(stream) { return; }

        if let Err(e) = run_openclaw_onboard(&pv_cfg) {
            send_json_err(stream, 500, &e); return;
        }
        write_openclaw_env(&provider, &api_key);

        // Reapply channel config, patch autonomy, and restart agent
        restart_openclaw_with_channel_config(&channel_config, &autonomy);
        after = snapshot_config();
    } else {
        let _ = Command::new("systemctl").args(["stop", "openclaw-daemon.service"]).output();
        after = String::new();
    }

    state.agent_enabled.store(enabled, Ordering::Relaxed);
    update_state_key("agent_enabled", &enabled.to_string());
    notify_async(format!("✅ AI Agent has been *{}*.", if enabled { "enabled" } else { "disabled" }));
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","agent_enabled":{},"diff_before":"{}","diff_after":"{}"}}"#,
        enabled, json_escape(&before), json_escape(&after)
    ));
}

fn handle_provider_swap(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let provider = json_str(&req.body, "provider");
    let model    = json_str(&req.body, "model");
    let api_key  = json_str(&req.body, "apiKey");
    let api_url  = json_str(&req.body, "apiUrl");

    if provider.is_empty() { send_json_err(stream, 400, "provider is required"); return; }

    let pv_cfg = match make_provider_config(provider, model, api_key, api_url) {
        Some(c) => c,
        None    => { send_json_err(stream, 400, "unknown provider"); return; }
    };

    // Bug fix v5.1.0: save existing channel config before openclaw onboard
    // (which rewrites config.toml with a fresh skeleton), then reapply after.
    let (channel_config, autonomy) = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c) => {
            let auto = c.lines()
                .find(|l| l.trim_start().starts_with("level = "))
                .and_then(|l| l.split('"').nth(1))
                .unwrap_or("supervised").to_string();
            (extract_channel_config(&c), auto)
        },
        Err(_) => (String::new(), "supervised".to_string()),
    };

    if !ensure_openclaw_binary(stream) { return; }

    if let Err(e) = run_openclaw_onboard(&pv_cfg) {
        send_json_err(stream, 500, &e); return;
    }
    write_openclaw_env(provider, api_key);

    let before = snapshot_config();

    // Reapply channel config, patch autonomy, and restart agent
    restart_openclaw_with_channel_config(&channel_config, &autonomy);
    let after = snapshot_config();

    // Persist provider info

    // Persist provider info
    let _ = fs::write(PROVIDER_FILE, format!(
        "provider={}\nmodel={}\napi_key={}\napi_url={}\n",
        toml_escape(provider), toml_escape(&pv_cfg.model),
        toml_escape(api_key), toml_escape(api_url)
    ));
    let _ = Command::new("chmod").args(["600", PROVIDER_FILE]).output();

    *state.provider.lock().unwrap() = provider.to_string();
    *state.model.lock().unwrap()    = pv_cfg.model.clone();
    update_state_key("provider", provider);
    update_state_key("model", &pv_cfg.model);
    notify_async(format!("✅ AI Provider changed to *{}* (model: {}).", provider, &pv_cfg.model));
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","diff_before":"{}","diff_after":"{}"}}"#,
        json_escape(&before), json_escape(&after)
    ));
}

fn handle_channel_add(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let channel_type = json_str(&req.body, "channel_type");
    if channel_type.is_empty() { send_json_err(stream, 400, "channel_type is required"); return; }

    let channel_toml = build_channel_section(channel_type, &req.body);

    let config = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c)  => c,
        Err(e) => { send_json_err(stream, 500, &format!("cannot read config: {}", e)); return; }
    };

    let before = snapshot_config();
    let updated = add_channel_to_config(&config, channel_type, &channel_toml);
    if let Err(e) = write_validated_config(&updated) {
        send_json_err(stream, 500, &e); return;
    }
    let after = snapshot_config();

    // Update state with the first/primary channel
    *state.channel.lock().unwrap() = channel_type.to_string();
    update_state_key("channel", channel_type);

    // Restart agent to pick up new channel
    if state.agent_enabled.load(Ordering::Relaxed) {
        let _ = Command::new("systemctl").args(["restart", "openclaw-daemon.service"]).output();
    }
    notify_async(format!("✅ Channel *{}* has been added.", channel_display_name(channel_type)));
    send_json_ok(stream, &format!(
        r#"{{"status":"added","diff_before":"{}","diff_after":"{}"}}"#,
        json_escape(&before), json_escape(&after)
    ));
}

fn handle_channel_remove(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let channel = json_str(&req.body, "channel");
    if channel.is_empty() { send_json_err(stream, 400, "channel is required"); return; }

    let config = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c)  => c,
        Err(e) => { send_json_err(stream, 500, &format!("cannot read config: {}", e)); return; }
    };

    let before = snapshot_config();
    let updated = remove_channel_from_config(&config, channel);
    if let Err(e) = write_validated_config(&updated) {
        send_json_err(stream, 500, &e); return;
    }
    let after = snapshot_config();

    // If we removed the primary channel, update state
    {
        let current = state.channel.lock().unwrap().clone();
        if current == channel {
            let remaining = list_configured_channels(&updated);
            let new_primary = remaining.first().cloned().unwrap_or_default();
            *state.channel.lock().unwrap() = new_primary.clone();
            update_state_key("channel", &new_primary);
        }
    }

    // Restart agent to pick up change
    if state.agent_enabled.load(Ordering::Relaxed) {
        let _ = Command::new("systemctl").args(["restart", "openclaw-daemon.service"]).output();
    }
    // Notify on remaining channels (the removed one can no longer receive)
    notify_async(format!("✅ Channel *{}* has been removed.", channel_display_name(channel)));
    send_json_ok(stream, &format!(
        r#"{{"status":"removed","diff_before":"{}","diff_after":"{}"}}"#,
        json_escape(&before), json_escape(&after)
    ));
}

fn handle_hardware(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let mode = json_str(&req.body, "mode");
    let mode = if mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" };
    apply_hardware_mode(mode, state);
    let mode_display = if mode == "WIND_TUNNEL" { "Wind Tunnel" } else { "Standard EdgeNode" };
    notify_async(format!("✅ Hardware mode switched to *{}*.", mode_display));
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_autonomy_change(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
) {
    let level = json_str(&req.body, "level");
    if level != "readonly" && level != "supervised" && level != "full" {
        send_json_err(stream, 400, "level must be readonly, supervised, or full");
        return;
    }

    let display = match level {
    "readonly"   => "Read-Only",
    "supervised" => "Supervised",
    "full"       => "Full",
    _            => level,
};

    let config = match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("cannot read config: {}", e);
            send_json_err(stream, 500, &msg);
            notify_async(format!("❌ Failed to change autonomy to {}: {}", display, msg));
            return;
        }
    };

    // patch_openclaw_config rewrites `level = "..."` in-place and passes channel
    // sections through unchanged — no extract/reappend needed here (unlike the
    // onboard/provider flows that call run_openclaw_onboard which wipes the file).
    let before = snapshot_config();
    let final_config = patch_openclaw_config(&config, level);

    if let Err(e) = write_validated_config(&final_config) {
        send_json_err(stream, 500, &e);
        notify_async(format!("❌ Failed to change autonomy to {}: {}", display, e));
        return;
    }
    let after = snapshot_config();

    if state.agent_enabled.load(Ordering::Relaxed) {
        let _ = Command::new("systemctl").args(["restart", "openclaw-daemon.service"]).output();
    }

    notify_async(format!("✅ Autonomy level changed to *{}*.", display));
    send_json_ok(stream, &format!(
        r#"{{"status":"ok","diff_before":"{}","diff_after":"{}"}}"#,
        json_escape(&before), json_escape(&after)
    ));
}

fn handle_password(
    stream: &mut TcpStream,
    req: &Req,
    auth_hash: &Arc<Mutex<String>>,
) {
    let current      = json_str(&req.body, "current");
    let new_password = json_str(&req.body, "newPassword");

    if current.is_empty() || new_password.is_empty() {
        send_json_err(stream, 400, "current and newPassword are required"); return;
    }
    if new_password.len() < 8 {
        send_json_err(stream, 400, "Password must be at least 8 characters"); return;
    }

    let hash = auth_hash.lock().unwrap().clone();
    if !verify_password(current, &hash) {
        send_json_err(stream, 401, "Incorrect current password"); return;
    }

    let new_hash = hash_password(new_password);
    let _ = fs::write(AUTH_FILE, &new_hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    *auth_hash.lock().unwrap() = new_hash;

    notify_async("✅ The Node Manager password has been changed.".to_string());
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_update(stream: &mut TcpStream) {
    let repo = env::var(UPDATE_REPO_ENV).unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
    thread::spawn(move || { check_and_apply_update(&repo); });
    notify_async("ℹ️ A manual software update check has been triggered.".to_string());
    send_json_ok(stream, r#"{"status":"update_triggered"}"#);
}

/// Read provider info from the persisted provider file.
fn read_provider_file() -> (String, String) {
    let content = fs::read_to_string(PROVIDER_FILE).unwrap_or_default();
    let mut api_key = String::new();
    let mut api_url = String::new();
    for line in content.lines() {
        if let Some(eq) = line.find('=') {
            let k = line[..eq].trim();
            let v = line[eq + 1..].to_string();
            match k {
                "api_key" => api_key = v,
                "api_url" => api_url = v,
                _ => {}
            }
        }
    }
    (api_key, api_url)
}
// ── Config snapshot + diff helpers ────────────────────────────────────────────

fn snapshot_config() -> String {
    fs::read_to_string(OPENCLAW_CONFIG).unwrap_or_default()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

fn handle_config_view(stream: &mut TcpStream) {
    match fs::read_to_string(OPENCLAW_CONFIG) {
        Ok(c)  => send_response(stream, 200, "OK", "text/plain; charset=utf-8", c.as_bytes()),
        Err(e) => send_json_err(stream, 500, &format!("cannot read config: {}", e)),
    }
}

// ── Main ───────────────────────────────────────────────────────────────────────

fn main() {
    eprintln!("[node-manager] Starting v{}", VERSION);

    let ap_mode = env::args().any(|a| a == "--ap-mode");
    let auth_hash = Arc::new(Mutex::new(load_or_create_auth()));
    let state = Arc::new(AppState::new(ap_mode));

    // Patch the openclaw update script with the active fork settings
    patch_openclaw_update_script();

    // Spawn background update checker
    let repo = env::var(UPDATE_REPO_ENV).unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
    spawn_update_checker(repo);

    let listener = TcpListener::bind("0.0.0.0:8080").expect("Cannot bind to 0.0.0.0:8080");
    eprintln!("[node-manager] Listening on http://0.0.0.0:8080");

    for stream in listener.incoming() {
        let mut stream = match stream { Ok(s) => s, Err(_) => continue };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

        let state = Arc::clone(&state);
        let auth_hash = Arc::clone(&auth_hash);

        thread::spawn(move || {
            let req = match read_request(&mut stream) { Some(r) => r, None => return };

            match (req.method.as_str(), req.path.as_str()) {
                // ── Public routes ──────────────────────────────────────────────
                ("GET", "/") => {
                    if state.onboarded.load(Ordering::Relaxed) {
                        send_redirect(&mut stream, "/manage");
                    } else {
                        send_html(&mut stream, &build_onboarding_html(state.ap_mode));
                    }
                },

                ("GET", "/login") => {
                    if is_authenticated(&req, &state) {
                        send_redirect(&mut stream, "/manage");
                    } else {
                        send_html(&mut stream, &build_login_html(false));
                    }
                },

                ("POST", "/login") => {
                    let form = parse_form(&req.body);
                    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
                    let hash = auth_hash.lock().unwrap().clone();
                    if verify_password(password, &hash) {
                        let token = create_session(&state);
                        send_redirect_with_cookie(&mut stream, "/manage", &session_cookie(&token));
                    } else {
                        send_html(&mut stream, &build_login_html(true));
                    }
                },

                ("POST", "/logout") => {
                    send_redirect_with_cookie(&mut stream, "/login", &clear_cookie());
                },

                ("POST", "/submit") => {
                    handle_submit(&mut stream, &req, &state, &auth_hash);
                },

                // ── Authenticated routes ───────────────────────────────────────
                ("GET", "/manage") => {
                    if !is_authenticated(&req, &state) {
                        send_redirect(&mut stream, "/login");
                    } else {
                        send_html(&mut stream, &build_manage_html(&state));
                    }
                },

                ("GET", "/manage/status") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_manage_status(&mut stream, &state);
                    }
                },

                ("POST", "/manage/ssh/add") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_ssh_add(&mut stream, &req);
                    }
                },

                ("POST", "/manage/ssh/remove") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_ssh_remove(&mut stream, &req);
                    }
                },

                ("POST", "/manage/agent") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_agent_toggle(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/provider") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_provider_swap(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/hardware") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_hardware(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/autonomy") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_autonomy_change(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/password") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_password(&mut stream, &req, &auth_hash);
                    }
                },

                ("POST", "/manage/update") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_update(&mut stream);
                    }
                },

                ("POST", "/manage/channels/add") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_channel_add(&mut stream, &req, &state);
                    }
                },

                ("POST", "/manage/channels/remove") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_channel_remove(&mut stream, &req, &state);
                    }
                },

                ("GET", "/manage/config") => {
                    if !is_authenticated(&req, &state) {
                        send_json_err(&mut stream, 401, "Not authenticated");
                    } else {
                        handle_config_view(&mut stream);
                    }
                },

                _ => {
                    send_response(&mut stream, 404, "Not Found", "text/plain", b"404 Not Found");
                },
            }
        });
    }
}
