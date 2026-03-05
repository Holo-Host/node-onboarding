// Holo Node Onboarding Server — v5
//
// Changes from v4:
//   - Server stays running permanently. GET / redirects to /manage after onboarding.
//   - Password-protected UI. Password is generated on first run, displayed on HDMI
//     (/dev/tty1) with ANSI colours and the node's local IP address.
//   - SSH key management for the `holo` user (/home/holo/.ssh/authorized_keys).
//     Step 1 of onboarding collects node name + first SSH public key.
//     /manage lets operators add/remove keys without USB access.
//   - AI agent is 100% opt-in. Step 2 has a toggle (default OFF). If off, zeroclaw
//     is never installed; the node is SSH + container management only.
//   - /manage page: SSH keys, agent toggle, provider hot-swap, hardware mode switch,
//     password change, manual software update trigger. All operations functional.
//   - Self-update: background thread polls GitHub Releases API hourly. On a new
//     tag it downloads the arch-matched binary, atomically replaces the running
//     binary and calls `systemctl restart node-onboarding.service`.
//   - node_name replaces tgUid as the hostname slug.
//     Wind-tunnel hostname: nomad-client-{node_name}
//   - Wind-tunnel image also uses resolve_image() for ARM (prefix "latest-").
//   - curl and wget removed from agent allowed_commands.
//
// Routes:
//   GET  /              → onboarding wizard (pre-onboard) or redirect /manage
//   POST /submit        → run onboarding
//   GET  /login         → login page
//   POST /login         → authenticate, set session cookie
//   POST /logout        → clear session cookie
//   GET  /manage        → management panel (auth required)
//   GET  /manage/status → JSON current state (auth required)
//   POST /manage/ssh/add    → add SSH public key
//   POST /manage/ssh/remove → remove SSH key by index
//   POST /manage/agent      → enable/disable agent
//   POST /manage/provider   → hot-swap provider/model/key
//   POST /manage/hardware   → switch STANDARD ↔ WIND_TUNNEL
//   POST /manage/password   → change node password
//   POST /manage/update     → trigger immediate update check
//
// Boot sequence:
//   install-zeroclaw.service  (first boot, only if agent was enabled at onboarding)
//        ↓ After=
//   node-onboarding.service   (permanent — runs indefinitely)

use std::{
    collections::HashMap,
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime},
};

// ── Version & path constants ───────────────────────────────────────────────────

const VERSION: &str = "5.0.0";
const STATE_FILE: &str = "/etc/node-onboarding/state";
const AUTH_FILE: &str = "/etc/node-onboarding/auth";
const PROVIDER_FILE: &str = "/etc/node-onboarding/provider";   // chmod 600
const SKILLS_DIR: &str = "/etc/zeroclaw/skills";
const QUADLET_DIR: &str = "/etc/containers/systemd";
const WORKSPACE_DIR: &str = "/var/lib/zeroclaw/workspace";
const AUTHORIZED_KEYS: &str = "/home/holo/.ssh/authorized_keys";
const UPDATE_REPO_ENV: &str = "UPDATE_REPO";
const UPDATE_REPO_DEFAULT: &str = "holo-host/node-onboarding";
const SESSION_TTL_SECS: u64 = 86400;     // 24 h
const UPDATE_INTERVAL_SECS: u64 = 3600;  // 1 h

// ── Embedded zeroclaw skill ────────────────────────────────────────────────────
const HOLO_NODE_SKILL: &str = include_str!("holo-node.md");

// ── Agent allowed commands — curl and wget removed ────────────────────────────
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

// ── State file helpers (key=value, one per line) ───────────────────────────────

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
    let _ = fs::create_dir_all("/etc/node-onboarding");
    let content: String = kv.iter().map(|(k, v)| format!("{}={}\n", k, v)).collect();
    let _ = fs::write(STATE_FILE, content);
    let _ = Command::new("chmod").args(["600", STATE_FILE]).output();
}

fn update_state_key(key: &str, value: &str) {
    let mut kv = read_state_file();
    kv.insert(key.to_string(), value.to_string());
    write_state_file(&kv);
}

// ── Crypto / random helpers ────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{:02x}", b)).collect()
}

/// 12-char human-readable password; avoids ambiguous characters (0/O, 1/l/I).
fn generate_password() -> String {
    let alpha: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    random_bytes(12)
        .iter()
        .map(|&b| alpha[(b as usize) % alpha.len()] as char)
        .collect()
}

fn sha256_of(input: &str) -> String {
    let mut child = match Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }
    let out = child.wait_with_output().unwrap_or_default();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Stored format: `sha256:<16-hex-salt>:<64-hex-sha256>`
fn hash_password(password: &str) -> String {
    let salt = random_hex(8);
    let hash = sha256_of(&format!("{}:{}", salt, password));
    format!("sha256:{}:{}", salt, hash)
}

fn verify_password(input: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.trim().splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "sha256" {
        return false;
    }
    let actual = sha256_of(&format!("{}:{}", parts[1], input));
    !actual.is_empty() && actual == parts[2].trim()
}

// ── First-run auth: generate or load password hash ────────────────────────────

fn load_or_create_auth() -> String {
    if let Ok(h) = fs::read_to_string(AUTH_FILE) {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    let password = generate_password();
    let hash = hash_password(&password);
    let _ = fs::create_dir_all("/etc/node-onboarding");
    let _ = fs::write(AUTH_FILE, &hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    display_password_on_tty(&password);
    hash
}

fn get_local_ip() -> String {
    Command::new("sh")
        .args(["-c",
            "ip -4 addr show scope global | grep -oP '(?<=inet )\\d+\\.\\d+\\.\\d+\\.\\d+' | head -1"])
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        })
        .unwrap_or_else(|| "<node-ip>".to_string())
}

/// Write password + access instructions to /dev/tty1 (HDMI) in colour.
/// Also logged to stderr so it appears in the systemd journal.
fn display_password_on_tty(password: &str) {
    let ip = get_local_ip();
    let msg = format!(
        "\x1b[2J\x1b[H\
         \n\
         \x1b[1;36m  ╔══════════════════════════════════════════╗\n\
         \x1b[1;36m  ║      🜲  HOLO SOVEREIGN NODE SETUP        ║\n\
         \x1b[1;36m  ╚══════════════════════════════════════════╝\x1b[0m\n\
         \n\
         \x1b[1m  Open a browser on your local network and visit:\x1b[0m\n\
         \x1b[1;33m  http://{}:8080\x1b[0m\n\
         \n\
         \x1b[1m  One-time setup password:\x1b[0m\n\
         \x1b[1;32m  {}\x1b[0m\n\
         \n\
         \x1b[31m  ⚠  Write this password down and store it securely.\x1b[0m\n\
         \x1b[31m     It CANNOT be recovered if lost — there is no reset.\x1b[0m\n\
         \x1b[31m     You can change it later in the /manage panel.\x1b[0m\n\
         \n",
        ip, password
    );
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty1") {
        let _ = tty.write_all(msg.as_bytes());
    }
    // Write to issue file so password appears above login: prompt on all consoles
    let issue = format!(
        "\n\x1b[1;36m╔══════════════════════════════════════════╗\x1b[0m\n         \x1b[1;36m║      HOLO NODE SETUP                     ║\x1b[0m\n         \x1b[1;36m╚══════════════════════════════════════════╝\x1b[0m\n         \x1b[1mURL:\x1b[0m      http://{}:8080\n         \x1b[1mPassword:\x1b[0m \x1b[1;32m{}\x1b[0m\n         \x1b[31m⚠  Write this down — it cannot be recovered.\x1b[0m\n\n",
        ip, password
    );
    let _ = fs::create_dir_all("/run/issue.d");
    let _ = fs::write("/run/issue.d/51-node-onboarding.issue", issue.as_bytes());
    // Always log so it appears in journal
    eprintln!(
        "[onboard] *** SETUP PASSWORD: {} | URL: http://{}:8080 ***",
        password, ip
    );
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
    let token = match get_cookie(&req.headers, "session") {
        Some(t) => t,
        None => return false,
    };
    let mut sessions = state.sessions.lock().unwrap();
    match sessions.get(&token) {
        Some(&exp) if SystemTime::now() < exp => true,
        Some(_) => {
            sessions.remove(&token);
            false
        }
        None => false,
    }
}

fn session_cookie(token: &str) -> String {
    format!("session={}; HttpOnly; SameSite=Strict; Path=/", token)
}

fn clear_cookie() -> String {
    "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

// ── SSH key management ─────────────────────────────────────────────────────────

fn read_ssh_keys() -> Vec<String> {
    fs::read_to_string(AUTHORIZED_KEYS)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn write_ssh_keys(keys: &[String]) -> Result<(), String> {
    let _ = fs::create_dir_all("/home/holo/.ssh");
    let content = keys.join("\n") + "\n";
    fs::write(AUTHORIZED_KEYS, &content).map_err(|e| e.to_string())?;
    let _ = Command::new("chown").args(["-R", "holo:holo", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["700", "/home/holo/.ssh"]).output();
    let _ = Command::new("chmod").args(["600", AUTHORIZED_KEYS]).output();
    Ok(())
}

fn is_valid_ssh_pubkey(key: &str) -> bool {
    let k = key.trim();
    k.starts_with("ssh-ed25519 ")
        || k.starts_with("ssh-rsa ")
        || k.starts_with("ecdsa-sha2-")
        || k.starts_with("sk-ssh-")
}

// ── Image resolvers ────────────────────────────────────────────────────────────

fn detect_arch() -> String {
    Command::new("uname")
        .arg("-m")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string())
}

/// Generic resolver: checks if `:latest` carries an arm64 manifest via skopeo;
/// if not, queries the GHCR tags list and picks the newest tag with `arm64_prefix`.
fn resolve_image(image_ref: &str, arm64_prefix: &str) -> String {
    let arch = detect_arch();
    eprintln!("[onboard] arch={} image={}", arch, image_ref);

    if arch != "aarch64" {
        return format!("{}:latest", image_ref);
    }

    eprintln!("[onboard] aarch64 — inspecting :latest manifest");
    let manifest = Command::new("skopeo")
        .args(["inspect", "--raw", &format!("docker://{}:latest", image_ref)])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    if manifest.contains("arm64") || manifest.contains("aarch64") {
        eprintln!("[onboard] {}:latest has arm64 manifest", image_ref);
        return format!("{}:latest", image_ref);
    }

    eprintln!("[onboard] {}:latest is x86-only — querying GHCR tags", image_ref);
    let repo_path = image_ref.trim_start_matches("ghcr.io/");

    let token_json = Command::new("curl")
        .args(["-sf",
            &format!("https://ghcr.io/token?scope=repository:{}:pull&service=ghcr.io", repo_path)])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let token = extract_json_str(&token_json, "token");
    if token.is_empty() {
        eprintln!("[onboard] Warning: no GHCR token — using :latest");
        return format!("{}:latest", image_ref);
    }

    let tags_json = Command::new("curl")
        .args(["-sf", "-H", &format!("Authorization: Bearer {}", token),
            &format!("https://ghcr.io/v2/{}/tags/list", repo_path)])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    match pick_arm64_tag(&tags_json, arm64_prefix) {
        Some(tag) => {
            eprintln!("[onboard] arm64 tag for {}: {}", image_ref, tag);
            format!("{}:{}", image_ref, tag)
        }
        None => {
            eprintln!("[onboard] No arm64 tag found — using :latest");
            format!("{}:latest", image_ref)
        }
    }
}

fn resolve_edgenode_image() -> String {
    resolve_image("ghcr.io/holo-host/edgenode", "latest-hc")
}

fn resolve_wind_tunnel_image() -> String {
    // Wind-tunnel ARM builds use a plain "latest-" prefix (e.g. "latest-0.6.1")
    resolve_image("ghcr.io/holochain/wind-tunnel-runner", "latest-")
}

fn extract_json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) {
        Some(p) => p,
        None => return "",
    };
    let after = json[pos + needle.len()..].trim_start();
    if after.starts_with('"') {
        let inner = &after[1..];
        &inner[..inner.find('"').unwrap_or(0)]
    } else {
        ""
    }
}

fn pick_arm64_tag(tags_json: &str, prefix: &str) -> Option<String> {
    let start = tags_json.find('[')?;
    let end = tags_json.rfind(']')?;
    let array = &tags_json[start + 1..end];
    let mut candidates = Vec::new();
    let mut rest = array;
    while let Some(q1) = rest.find('"') {
        let after = &rest[q1 + 1..];
        if let Some(q2) = after.find('"') {
            let tag = &after[..q2];
            if tag.starts_with(prefix) && tag != "latest" {
                candidates.push(tag.to_string());
            }
            rest = &after[q2 + 1..];
        } else {
            break;
        }
    }
    candidates.sort_by(|a, b| b.cmp(a));
    candidates.into_iter().next()
}

// ── Quadlet builders ───────────────────────────────────────────────────────────

fn build_edgenode_quadlet(image: &str) -> String {
    format!(
        r#"[Unit]
Description=Holo EdgeNode
After=network-online.target
Conflicts=wind-tunnel.service

[Container]
Image={image}
ContainerName=edgenode
Volume=/var/lib/edgenode:/data:Z
Label=io.containers.autoupdate=registry

[Service]
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
        image = image
    )
}

fn build_wind_tunnel_quadlet(hostname: &str, image: &str) -> String {
    format!(
        r#"[Unit]
Description=Holochain Wind Tunnel Runner
After=network-online.target
Conflicts=edgenode.service

[Container]
Image={image}
ContainerName=wind-tunnel
HostName={hostname}
Network=host
PodmanArgs=--cgroupns=host --privileged
Label=io.containers.autoupdate=registry

[Service]
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
        hostname = hostname,
        image = image
    )
}

// ── zeroclaw config patching ───────────────────────────────────────────────────

fn patch_config(config: &str, level: &str) -> String {
    let mut out = String::with_capacity(config.len() + 512);
    let mut lines = config.lines().peekable();
    let mut in_skills = false;
    let mut skills_dir_written = false;
    let mut skills_section_seen = false;

    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("allowed_commands") {
            out.push_str("allowed_commands = ");
            out.push_str(ALLOWED_COMMANDS);
            out.push('\n');
            if !trimmed.contains(']') {
                for cont in lines.by_ref() {
                    if cont.contains(']') { break; }
                }
            }
            continue;
        }
        if trimmed.starts_with("level = ") {
            out.push_str(&format!("level = \"{level}\"\n"));
            continue;
        }
        if trimmed.starts_with("allowed_roots") {
            out.push_str("allowed_roots = [\"/var/lib/zeroclaw/workspace\"]\n");
            if !trimmed.contains(']') {
                for cont in lines.by_ref() {
                    if cont.contains(']') { break; }
                }
            }
            continue;
        }
        if trimmed.starts_with("require_pairing") {
            out.push_str("require_pairing = false\n");
            continue;
        }
        if trimmed == "[skills]" {
            in_skills = true;
            skills_section_seen = true;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if in_skills {
            if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
                if !skills_dir_written {
                    out.push_str("open_skills_dir = \"/etc/zeroclaw/skills\"\n");
                }
                in_skills = false;
            } else {
                if trimmed.starts_with("open_skills_enabled") {
                    out.push_str("open_skills_enabled = true\n");
                    continue;
                }
                if trimmed.starts_with("open_skills_dir") {
                    out.push_str("open_skills_dir = \"/etc/zeroclaw/skills\"\n");
                    skills_dir_written = true;
                    continue;
                }
                out.push_str(line);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_skills && !skills_dir_written {
        out.push_str("open_skills_dir = \"/etc/zeroclaw/skills\"\n");
    }
    if !skills_section_seen {
        out.push_str("\n[skills]\nopen_skills_enabled = true\nopen_skills_dir = \"/etc/zeroclaw/skills\"\n");
    }
    out
}

fn build_channel_toml(body: &str, channel: &str) -> String {
    match channel {
        "telegram" => {
            let tok = toml_escape(json_str(body, "tgToken"));
            let uid = toml_escape(json_str(body, "tgUid"));
            format!("[channels_config.telegram]\nbot_token = \"{tok}\"\nallowed_users = [\"{uid}\"]\n")
        }
        "discord" => {
            let tok = toml_escape(json_str(body, "dcToken"));
            let uid = toml_escape(json_str(body, "dcUid"));
            format!("[channels_config.discord]\nbot_token = \"{tok}\"\nallowed_users = [\"{uid}\"]\n")
        }
        "slack" => {
            let bot = toml_escape(json_str(body, "slBot"));
            let app = toml_escape(json_str(body, "slApp"));
            let uid = toml_escape(json_str(body, "slUid"));
            format!(
                "[channels_config.slack]\nbot_token = \"{bot}\"\napp_token = \"{app}\"\nallowed_users = [\"{uid}\"]\n"
            )
        }
        "signal" => {
            let url = toml_escape(json_str(body, "sgUrl"));
            let acct = toml_escape(json_str(body, "sgAcct"));
            let alw = csv_to_toml_array(json_str(body, "sgAllowed"));
            format!("[channels_config.signal]\nhttp_url = \"{url}\"\naccount = \"{acct}\"\nallowed_from = {alw}\n")
        }
        "matrix" => {
            let hs = toml_escape(json_str(body, "mxHs"));
            let tok = toml_escape(json_str(body, "mxTok"));
            let room = toml_escape(json_str(body, "mxRoom"));
            let uid = toml_escape(json_str(body, "mxUid"));
            format!(
                "[channels_config.matrix]\nhomeserver = \"{hs}\"\naccess_token = \"{tok}\"\nroom_id = \"{room}\"\nallowed_users = [\"{uid}\"]\n"
            )
        }
        "whatsapp" => {
            let pid = toml_escape(json_str(body, "waPid"));
            let tok = toml_escape(json_str(body, "waTok"));
            let alw = csv_to_toml_array(json_str(body, "waAllowed"));
            format!(
                "[channels_config.whatsapp]\nphone_number_id = \"{pid}\"\naccess_token = \"{tok}\"\nallowed_numbers = {alw}\n"
            )
        }
        _ => String::new(),
    }
}

/// Extract the [channels_config.*] section from an existing config for reuse
/// during provider hot-swap (avoids needing to re-enter channel credentials).
fn extract_channel_config(config: &str) -> String {
    let mut result = String::new();
    let mut in_channel = false;
    for line in config.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[channels_config.") {
            in_channel = true;
        } else if trimmed.starts_with('[') && !trimmed.starts_with("[[") && in_channel {
            in_channel = false;
        }
        if in_channel {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

// ── Welcome message sender ─────────────────────────────────────────────────────

fn send_welcome_message(channel: &str, body: &str, hw_mode: &str) {
    let mode_desc = if hw_mode == "WIND_TUNNEL" {
        "Holochain Wind Tunnel stress-test runner"
    } else {
        "Holo EdgeNode — always-on Holochain peer"
    };
    let welcome = format!(
        "🜲 Your Holo Sovereign Node is online!\n\nI'm your on-device AI agent, powered by ZeroClaw.\n\nCurrent mode: {}\n\nTry asking me:\n• what containers are running?\n• show me the node health\n• switch to wind tunnel mode\n\nI'll always ask for your approval before taking action. Type anything to get started.",
        mode_desc
    );
    fn json_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
    }
    match channel {
        "telegram" => {
            let tok = json_str(body, "tgToken");
            let uid = json_str(body, "tgUid");
            if tok.is_empty() || uid.is_empty() { return; }
            let payload = format!(
                "{{\"chat_id\":\"{}\",\"text\":\"{}\",\"parse_mode\":\"Markdown\"}}",
                uid, json_escape(&welcome)
            );
            let _ = Command::new("curl")
                .args(["-sf", "-X", "POST",
                    &format!("https://api.telegram.org/bot{}/sendMessage", tok),
                    "-H", "Content-Type: application/json", "-d", &payload])
                .output();
        }
        "discord" => {
            let tok = json_str(body, "dcToken");
            let uid = json_str(body, "dcUid");
            if tok.is_empty() || uid.is_empty() { return; }
            let dm_payload = format!("{{\"recipient_id\":\"{}\"}}", uid);
            let ch_out = Command::new("curl")
                .args(["-sf", "-X", "POST",
                    "https://discord.com/api/v10/users/@me/channels",
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bot {}", tok),
                    "-d", &dm_payload])
                .output().ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            let dm_id = extract_json_str(&ch_out, "id");
            if dm_id.is_empty() { return; }
            let msg_payload = format!("{{\"content\":\"{}\"}}", json_escape(&welcome));
            let _ = Command::new("curl")
                .args(["-sf", "-X", "POST",
                    &format!("https://discord.com/api/v10/channels/{}/messages", dm_id),
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bot {}", tok),
                    "-d", &msg_payload])
                .output();
        }
        "slack" => {
            let tok = json_str(body, "slBot");
            let uid = json_str(body, "slUid");
            if tok.is_empty() || uid.is_empty() { return; }
            let payload = format!(
                "{{\"channel\":\"{}\",\"text\":\"{}\"}}",
                uid, json_escape(&welcome)
            );
            let _ = Command::new("curl")
                .args(["-sf", "-X", "POST",
                    "https://slack.com/api/chat.postMessage",
                    "-H", "Content-Type: application/json",
                    "-H", &format!("Authorization: Bearer {}", tok),
                    "-d", &payload])
                .output();
        }
        other => eprintln!("[onboard] Welcome not implemented for channel: {}", other),
    }
}

// ── Self-update ────────────────────────────────────────────────────────────────

fn check_and_apply_update(repo: &str) {
    eprintln!("[update] Checking {} for updates (current: v{})", repo, VERSION);
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    let json = match Command::new("curl")
        .args(["-sf", "-H", "Accept: application/vnd.github+json",
            "-H", "User-Agent: holo-node-onboarding", &api_url])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            eprintln!("[update] Could not reach GitHub Releases API");
            return;
        }
    };

    let tag = extract_json_str(&json, "tag_name");
    if tag.is_empty() {
        eprintln!("[update] Could not parse tag_name");
        return;
    }
    let tag_ver = tag.trim_start_matches('v');
    if tag_ver == VERSION {
        eprintln!("[update] Already at v{}", VERSION);
        return;
    }
    eprintln!("[update] New version: {} (have: {})", tag_ver, VERSION);

    let arch = detect_arch();
    let asset_name = format!("node-onboarding-{}", arch);
    let download_url = find_asset_download_url(&json, &asset_name);
    if download_url.is_empty() {
        eprintln!("[update] No asset '{}' in release {}", asset_name, tag);
        return;
    }

    let tmp = "/tmp/node-onboarding-update";
    eprintln!("[update] Downloading {}", download_url);
    let ok = Command::new("curl")
        .args(["-sfL", "-o", tmp, &download_url])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("[update] Download failed");
        return;
    }

    let _ = Command::new("chmod").args(["+x", tmp]).output();
    let self_path = env::current_exe()
        .unwrap_or_else(|_| "/usr/local/bin/node-onboarding".into());

    if let Err(e) = fs::rename(tmp, &self_path) {
        eprintln!("[update] Replace failed: {}", e);
        return;
    }
    eprintln!("[update] Binary replaced. Triggering systemd restart...");
    let _ = Command::new("systemctl")
        .args(["restart", "node-onboarding.service"])
        .output();
}

fn find_asset_download_url(release_json: &str, asset_name: &str) -> String {
    // Find the asset object by name, then grab browser_download_url nearby.
    let needle = format!("\"name\":\"{}\"", asset_name);
    let pos = match release_json.find(&needle) {
        Some(p) => p,
        None => return String::new(),
    };
    let window_end = (pos + 600).min(release_json.len());
    let window = &release_json[pos..window_end];
    let url_key = "\"browser_download_url\":\"";
    let url_pos = match window.find(url_key) {
        Some(p) => p,
        None => return String::new(),
    };
    let after = &window[url_pos + url_key.len()..];
    after[..after.find('"').unwrap_or(0)].to_string()
}

fn spawn_update_checker(repo: String) {
    thread::spawn(move || {
        // Give the server time to start before first check.
        thread::sleep(Duration::from_secs(90));
        loop {
            check_and_apply_update(&repo);
            thread::sleep(Duration::from_secs(UPDATE_INTERVAL_SECS));
        }
    });
}

// ── Node operations ────────────────────────────────────────────────────────────

struct ProviderConfig {
    id: String,
    model: String,
    key: String,
}

fn make_provider_config(provider: &str, model: &str, api_key: &str, api_url: &str) -> Option<ProviderConfig> {
    let (id, mdl, key) = match provider {
        "holo" => (
            "custom:https://llm.holo.com/v1".to_string(),
            "swiss-ai".to_string(),
            "holo-builtin".to_string(),
        ),
        "google" => (
            "google".to_string(),
            if model.is_empty() { "gemini-2.5-flash".to_string() } else { model.to_string() },
            api_key.to_string(),
        ),
        "anthropic" => (
            "anthropic".to_string(),
            if model.is_empty() { "claude-haiku-4-5-20251001".to_string() } else { model.to_string() },
            api_key.to_string(),
        ),
        "openai" => (
            "openai".to_string(),
            if model.is_empty() { "gpt-4o-mini".to_string() } else { model.to_string() },
            api_key.to_string(),
        ),
        "openrouter" => (
            "openrouter".to_string(),
            if model.is_empty() { "openrouter/auto".to_string() } else { model.to_string() },
            api_key.to_string(),
        ),
        "ollama" => {
            let url = if api_url.is_empty() { "http://127.0.0.1:11434" } else { api_url };
            (
                format!("custom:{}", url),
                if model.is_empty() { "llama3.2".to_string() } else { model.to_string() },
                "ollama".to_string(),
            )
        }
        _ => return None,
    };
    Some(ProviderConfig { id, model: mdl, key })
}

fn run_zeroclaw_onboard(pv: &ProviderConfig) -> Result<(), String> {
    let result = Command::new("/usr/local/bin/zeroclaw")
        .args([
            "--config-dir", "/etc/zeroclaw",
            "onboard", "--force", "--memory", "sqlite",
            "--provider", &pv.id,
            "--model", &pv.model,
            "--api-key", &pv.key,
        ])
        .env("HOME", "/root")
        .output();
    match result {
        Err(e) => Err(format!("zeroclaw binary not found: {}", e)),
        Ok(o) if !o.status.success() => {
            let err = String::from_utf8_lossy(&o.stderr);
            Err(format!("zeroclaw onboard failed: {}",
                err.replace('"', "'").replace('\n', " ").chars().take(200).collect::<String>()))
        }
        Ok(_) => Ok(()),
    }
}

fn apply_hardware_mode(new_mode: &str, state: &AppState) {
    let current = state.hw_mode.lock().unwrap().clone();
    let stop_svc = if current == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };
    let start_svc = if new_mode == "WIND_TUNNEL" { "wind-tunnel.service" } else { "edgenode.service" };

    let _ = fs::write(format!("{}/mode_switch.txt", WORKSPACE_DIR), new_mode);
    if current != new_mode {
        eprintln!("[manage] Stopping {} → starting {}", stop_svc, start_svc);
        let _ = Command::new("systemctl").args(["stop", stop_svc]).output();
        let _ = Command::new("systemctl").args(["start", start_svc]).output();
    }
    *state.hw_mode.lock().unwrap() = new_mode.to_string();
    update_state_key("hw_mode", new_mode);
}

// ── JSON / TOML / HTML helpers ─────────────────────────────────────────────────

fn json_str<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{}\"", key);
    let pos = match json.find(&needle) {
        Some(p) => p,
        None => return "",
    };
    let after = json[pos + needle.len()..]
        .splitn(2, ':')
        .nth(1)
        .unwrap_or("")
        .trim_start();
    if after.starts_with('"') {
        let inner = &after[1..];
        &inner[..inner.find('"').unwrap_or(0)]
    } else {
        ""
    }
}

fn toml_escape(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', r"\n")
        .replace('\r', r"\r")
        .replace('\t', r"\t")
}

fn csv_to_toml_array(csv: &str) -> String {
    if csv.trim().is_empty() {
        return "[\"*\"]".to_string();
    }
    let items: Vec<String> = csv
        .split(',')
        .map(|s| format!("\"{}\"", toml_escape(s.trim())))
        .collect();
    format!("[{}]", items.join(", "))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_bool(json: &str, key: &str) -> bool {
    let needle = format!("\"{}\":", key);
    let pos = match json.find(&needle) {
        Some(p) => p,
        None => return false,
    };
    let after = json[pos + needle.len()..].trim_start();
    after.starts_with("true")
}

// Parse application/x-www-form-urlencoded
fn parse_form(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in body.split('&') {
        if let Some(eq) = pair.find('=') {
            map.insert(
                url_decode(&pair[..eq]),
                url_decode(&pair[eq + 1..]),
            );
        }
    }
    map
}

fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut bytes = s.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'+' {
            result.push(' ');
        } else if b == b'%' {
            let h1 = bytes.next().unwrap_or(b'0') as char;
            let h2 = bytes.next().unwrap_or(b'0') as char;
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                result.push(byte as char);
            }
        } else {
            result.push(b as char);
        }
    }
    result
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

fn send_response(stream: &mut TcpStream, status: u16, reason: &str, ctype: &str, body: &[u8]) {
    let hdr = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes());
    let _ = stream.write_all(body);
}

fn send_html(stream: &mut TcpStream, html: &str) {
    send_response(stream, 200, "OK", "text/html; charset=utf-8", html.as_bytes());
}

fn send_json_ok(stream: &mut TcpStream, body: &str) {
    send_response(stream, 200, "OK", "application/json", body.as_bytes());
}

fn send_json_err(stream: &mut TcpStream, status: u16, msg: &str) {
    let body = format!("{{\"error\":\"{}\"}}", msg.replace('"', "'"));
    send_response(stream, status, "Error", "application/json", body.as_bytes());
}

fn send_redirect(stream: &mut TcpStream, location: &str) {
    let hdr = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        location
    );
    let _ = stream.write_all(hdr.as_bytes());
}

fn send_redirect_with_cookie(stream: &mut TcpStream, location: &str, cookie: &str) {
    let hdr = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nSet-Cookie: {}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
        location, cookie
    );
    let _ = stream.write_all(hdr.as_bytes());
}

struct Req {
    method: String,
    path: String,
    headers: String,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut r = BufReader::new(stream.try_clone().ok()?);
    let mut line0 = String::new();
    r.read_line(&mut line0).ok()?;
    let mut parts = line0.trim().splitn(3, ' ');
    let method = parts.next()?.to_string();
    let path_raw = parts.next()?.to_string();
    // Strip query string
    let path = path_raw.split('?').next().unwrap_or(&path_raw).to_string();

    let mut cl: usize = 0;
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        r.read_line(&mut line).ok()?;
        if line.trim().is_empty() { break; }
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            cl = lower["content-length:".len()..].trim().parse().unwrap_or(0);
        }
        headers.push_str(&line);
    }

    let mut body = vec![0u8; cl.min(1 << 20)]; // cap 1 MB
    if cl > 0 { r.read_exact(&mut body).ok()?; }
    Some(Req {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn get_cookie(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("cookie:") {
            for pair in line["cookie:".len()..].trim().split(';') {
                let p = pair.trim();
                if let Some(eq) = p.find('=') {
                    if p[..eq].trim() == name {
                        return Some(p[eq + 1..].trim().to_string());
                    }
                }
            }
        }
    }
    None
}

// ── HTML pages ─────────────────────────────────────────────────────────────────

// Shared CSS for all pages
const COMMON_CSS: &str = r#"
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:32px 16px}
.card{background:#1a1d27;border:1px solid #2d3148;border-radius:16px;width:100%;max-width:580px;overflow:hidden}
.hdr{background:linear-gradient(135deg,#1e2d5a,#2d1e5a);padding:24px 32px}
.hdr h1{font-size:20px;font-weight:700;color:#fff;letter-spacing:-.3px}
.hdr p{color:#94a3b8;font-size:13px;margin-top:4px}
.body{padding:28px 32px}
label{display:block;font-size:13px;font-weight:600;color:#94a3b8;margin-bottom:5px;margin-top:14px}
label:first-of-type{margin-top:0}
input[type=text],input[type=password],input[type=url],textarea,select{width:100%;padding:10px 12px;background:#0f1117;border:1px solid #2d3148;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .2s;font-family:inherit}
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
"#;

fn build_login_html(error: bool) -> String {
    let err = if error {
        r#"<div class="err-box">Incorrect password. Try again.</div>"#
    } else {
        ""
    };
    format!(r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — Login</title>
<style>{css}
body{{align-items:center}}
.card{{max-width:400px}}
.hdr{{text-align:center}}
.icon{{font-size:42px;margin-bottom:10px}}
form .btn{{width:100%;margin-top:18px}}
</style></head><body>
<div class="card">
  <div class="hdr"><div class="icon">🜲</div><h1>Holo Sovereign Node</h1><p>Enter your node password to continue.</p></div>
  <div class="body">
    {err}
    <form method="POST" action="/login">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
      <button type="submit" class="btn btn-primary">Unlock →</button>
    </form>
  </div>
</div>
</body></html>"#,
        css = COMMON_CSS,
        err = err)
}

fn build_onboarding_html(ap_mode: bool) -> String {
    let wifi_block = if ap_mode {
        r#"<div class="err-box">⚠ No Ethernet — connect to Wi-Fi to continue.</div>
<label>Wi-Fi SSID</label><input type="text" id="wifiSsid" placeholder="Network name">
<label>Wi-Fi Password</label><input type="password" id="wifiPass">"#
    } else {
        r#"<div class="ok-box">✓ Ethernet connected — you're online.</div>"#
    };

    format!(r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node Setup</title>
<style>
{css}
.prog{{height:3px;background:#0f1117}}
.prog-fill{{height:100%;background:linear-gradient(90deg,#6366f1,#8b5cf6);transition:width .4s ease}}
.step{{display:none}}.step.active{{display:block}}
.slbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#6366f1;margin-bottom:12px}}
.stit{{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:5px}}
.sdsc{{font-size:13px;color:#64748b;margin-bottom:20px;line-height:1.6}}
.cg{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}}
.cb{{padding:14px 10px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;text-align:center;transition:all .2s;color:#94a3b8}}
.cb:hover,.cb.sel{{border-color:#6366f1;color:#a5b4fc}}.cb.sel{{background:#1e1d3f}}
.cb-icon{{font-size:22px;margin-bottom:6px}}.cb-name{{font-size:13px;font-weight:600}}.cb-desc{{font-size:11px;color:#475569;margin-top:2px}}
.pl{{display:flex;flex-direction:column;gap:8px}}
.pb{{padding:14px 16px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;display:flex;align-items:center;gap:14px;transition:all .2s;color:#94a3b8}}
.pb:hover,.pb.sel{{border-color:#6366f1;color:#a5b4fc}}.pb.sel{{background:#1e1d3f}}
.pi{{font-size:20px;flex-shrink:0}}.pn{{font-size:14px;font-weight:600}}.pd{{font-size:12px;color:#475569;margin-top:2px}}
.pc{{margin-top:18px;display:none}}.pc.vis{{display:block}}
.ao{{display:flex;flex-direction:column;gap:8px}}
.ab{{padding:14px 16px;background:#0f1117;border:2px solid #2d3148;border-radius:10px;cursor:pointer;display:flex;align-items:flex-start;gap:12px;transition:all .2s}}
.ab:hover{{border-color:#6366f1}}.ab.sel{{border-color:#6366f1;background:#1e1d3f}}
.ar{{width:18px;height:18px;border-radius:50%;border:2px solid #4b5563;flex-shrink:0;margin-top:2px;display:flex;align-items:center;justify-content:center}}
.ab.sel .ar{{border-color:#6366f1;background:#6366f1}}
.ab.sel .ar::after{{content:'';width:6px;height:6px;border-radius:50%;background:#fff}}
.an{{font-size:14px;font-weight:600;color:#e2e8f0}}.ad{{font-size:12px;color:#64748b;margin-top:3px;line-height:1.5}}
.inst{{background:#0f172a;border:1px solid #1e40af;border-radius:8px;padding:13px;margin-bottom:14px}}
.inst b{{font-size:12px;color:#818cf8}}
.inst ol{{padding-left:18px;margin-top:7px}}
.inst li{{font-size:12px;color:#94a3b8;line-height:1.8}}
.inst code{{background:#1e2740;padding:1px 4px;border-radius:4px;font-family:monospace;color:#a5b4fc}}
.rt{{width:100%;border-collapse:collapse;font-size:13px}}
.rt tr{{border-bottom:1px solid #2d3148}}.rt tr:last-child{{border-bottom:none}}
.rt td{{padding:9px 0;vertical-align:top}}
.rt td:first-child{{color:#64748b;width:140px;padding-right:12px}}
.rt td:last-child{{color:#e2e8f0;font-weight:500;word-break:break-all}}
.toggle-row{{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:#0f1117;border:1px solid #2d3148;border-radius:10px;margin-bottom:14px}}
.toggle-label{{font-size:14px;font-weight:600;color:#e2e8f0}}
.toggle-sub{{font-size:12px;color:#64748b;margin-top:2px}}
.toggle{{position:relative;width:48px;height:26px;flex-shrink:0}}
.toggle input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#2d3148;border-radius:13px;transition:.3s}}
.slider:before{{position:absolute;content:'';height:18px;width:18px;left:4px;bottom:4px;background:#64748b;border-radius:50%;transition:.3s}}
input:checked+.slider{{background:#6366f1}}
input:checked+.slider:before{{transform:translateX(22px);background:#fff}}
.agent-config{{display:none;margin-top:16px}}
.agent-config.vis{{display:block}}
.fw{{display:none;background:#2d1515;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-top:12px;font-size:12px;color:#fca5a5;line-height:1.6}}
.fw.vis{{display:block}}
.fw label{{color:#fca5a5;font-size:12px;font-weight:400;display:flex;align-items:flex-start;gap:8px;cursor:pointer;margin:10px 0 0}}
.fw input[type=checkbox]{{width:auto;flex-shrink:0;margin-top:2px}}
.brow{{display:flex;gap:10px;margin-top:24px}}
.brow .btn{{flex:1}}
.spin{{display:none;width:20px;height:20px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite;margin:0 auto}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
.suc{{text-align:center;padding:24px 0}}
.suc h2{{font-size:24px;font-weight:700;color:#86efac;margin-bottom:12px}}
.suc p{{color:#64748b;font-size:14px;line-height:1.7}}
</style></head><body>
<div class="card">
  <div class="hdr"><h1>🜲 Holo Sovereign Node</h1><p>One-time setup — about 3 minutes.</p></div>
  <div class="prog"><div class="prog-fill" id="prog" style="width:0%"></div></div>
  <div class="body">
    {wifi_block}

    <!-- STEP 1: NODE SETUP -->
    <div class="step active" id="s1">
      <div class="slbl">Step 1 of 4</div>
      <div class="stit">Node identity & SSH access</div>
      <div class="sdsc">Give your node a name and add your SSH public key for emergency access.</div>
      <label>Node name *</label>
      <input type="text" id="nodeName" placeholder="e.g. alice, home-node-01" oninput="chkS1()">
      <div class="hint">Used as the hostname slug. Lowercase letters, numbers and hyphens only.</div>
      <label>SSH public key <span style="color:#475569;font-weight:400">(recommended)</span></label>
      <textarea id="sshKey" placeholder="ssh-ed25519 AAAA... or ssh-rsa AAAA...&#10;Leave blank to configure SSH keys later in /manage"></textarea>
      <div class="hint">Paste your <code>~/.ssh/id_ed25519.pub</code> or <code>~/.ssh/id_rsa.pub</code>. Keys are written to <code>/home/holo/.ssh/authorized_keys</code>. Root login is disabled.</div>
      <div class="brow"><button class="btn btn-primary" id="b1" onclick="gTo(2)" disabled>Continue →</button></div>
    </div>

    <!-- STEP 2: AI AGENT -->
    <div class="step" id="s2">
      <div class="slbl">Step 2 of 4</div>
      <div class="stit">AI agent</div>
      <div class="sdsc">The AI agent lets you control this node via a chat app. It is completely optional — the node runs fine without it.</div>
      <div class="toggle-row">
        <div><div class="toggle-label">Enable AI agent</div><div class="toggle-sub">Installs ZeroClaw and connects to your chat app</div></div>
        <label class="toggle"><input type="checkbox" id="agentToggle" onchange="onAgentToggle()"><span class="slider"></span></label>
      </div>
      <div class="agent-config" id="agentConfig">
        <label style="margin-top:0">Chat app</label>
        <div class="cg">
          <div class="cb" onclick="sCh('telegram',this)"><div class="cb-icon">✈️</div><div class="cb-name">Telegram</div><div class="cb-desc">Recommended</div></div>
          <div class="cb" onclick="sCh('discord',this)"><div class="cb-icon">🎮</div><div class="cb-name">Discord</div><div class="cb-desc">Bot in server</div></div>
          <div class="cb" onclick="sCh('slack',this)"><div class="cb-icon">💼</div><div class="cb-name">Slack</div><div class="cb-desc">Workspace</div></div>
          <div class="cb" onclick="sCh('signal',this)"><div class="cb-icon">🔒</div><div class="cb-name">Signal</div><div class="cb-desc">Max privacy</div></div>
          <div class="cb" onclick="sCh('matrix',this)"><div class="cb-icon">🔷</div><div class="cb-name">Matrix</div><div class="cb-desc">Decentralised</div></div>
          <div class="cb" onclick="sCh('whatsapp',this)"><div class="cb-icon">💬</div><div class="cb-name">WhatsApp</div><div class="cb-desc">Meta API</div></div>
        </div>
        <div id="cr-telegram" class="ch-cr" style="display:none">
          <div class="inst"><b>Get Telegram credentials:</b><ol>
            <li>Search <code>@BotFather</code> → send <code>/newbot</code> → copy the token</li>
            <li>Message <code>@getmyid_bot</code> to find your numeric User ID</li>
          </ol></div>
          <label>Bot Token *</label><input type="password" id="tg-tok" placeholder="123456789:ABCDef...">
          <label>Your Telegram User ID *</label><input type="text" id="tg-uid" placeholder="e.g. 7114750915">
          <div class="hint">Numeric ID only — not your @username</div>
        </div>
        <div id="cr-discord" class="ch-cr" style="display:none">
          <div class="inst"><b>Get Discord credentials:</b><ol>
            <li><a href="https://discord.com/developers/applications" target="_blank">discord.com/developers/applications</a> → New App → Bot → Reset Token</li>
            <li>Enable "Message Content Intent" under Privileged Gateway Intents</li>
            <li>Your User ID: Settings → Advanced → Developer Mode → right-click name</li>
          </ol></div>
          <label>Bot Token *</label><input type="password" id="dc-tok" placeholder="MTxxxxxxxx...">
          <label>Your Discord User ID *</label><input type="text" id="dc-uid" placeholder="123456789012345678">
        </div>
        <div id="cr-slack" class="ch-cr" style="display:none">
          <div class="inst"><b>Get Slack credentials:</b><ol>
            <li><a href="https://api.slack.com/apps" target="_blank">api.slack.com/apps</a> → New App → add <code>chat:write</code> scope → Install → copy Bot Token</li>
            <li>Socket Mode → Enable → generate App Token (<code>xapp-...</code>)</li>
            <li>Your Member ID: Profile → ⋮ → Copy member ID</li>
          </ol></div>
          <label>Bot Token (xoxb-...) *</label><input type="password" id="sl-bot" placeholder="xoxb-...">
          <label>App Token (xapp-...) *</label><input type="password" id="sl-app" placeholder="xapp-...">
          <label>Your Slack Member ID *</label><input type="text" id="sl-uid" placeholder="U012AB3CD">
        </div>
        <div id="cr-signal" class="ch-cr" style="display:none">
          <div class="inst"><b>Signal requires signal-cli:</b><ol>
            <li>Install <a href="https://github.com/AsamK/signal-cli" target="_blank">signal-cli</a> and register your number</li>
            <li>Start: <code>signal-cli -u +1234 daemon --http=127.0.0.1:8686</code></li>
          </ol></div>
          <label>signal-cli URL *</label><input type="url" id="sg-url" value="http://127.0.0.1:8686">
          <label>Your Account Number *</label><input type="text" id="sg-acct" placeholder="+12345678901">
          <label>Allowed Senders (comma-sep, blank = anyone)</label><input type="text" id="sg-alw" placeholder="+12345678901">
        </div>
        <div id="cr-matrix" class="ch-cr" style="display:none">
          <label>Homeserver URL *</label><input type="url" id="mx-hs" placeholder="https://matrix.org">
          <label>Bot Access Token *</label><input type="password" id="mx-tok" placeholder="syt_xxxxxxxxxx">
          <div class="hint">Bot account → Element Settings → Help → Access Token</div>
          <label>Room ID *</label><input type="text" id="mx-room" placeholder="!abc123:matrix.org">
          <label>Your Matrix User ID *</label><input type="text" id="mx-uid" placeholder="@you:matrix.org">
        </div>
        <div id="cr-whatsapp" class="ch-cr" style="display:none">
          <div class="inst"><b>Requires Meta Business account:</b><ol>
            <li><a href="https://developers.facebook.com" target="_blank">developers.facebook.com</a> → New App → Business → Add WhatsApp</li>
            <li>Copy Phone Number ID and temporary access token</li>
          </ol></div>
          <label>Phone Number ID *</label><input type="text" id="wa-pid" placeholder="123456789012345">
          <label>Access Token *</label><input type="password" id="wa-tok" placeholder="EAAxxxxxxx...">
          <label>Allowed Numbers (comma-sep, blank = anyone)</label><input type="text" id="wa-alw" placeholder="+12345678901">
        </div>
      </div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(1)">← Back</button>
        <button class="btn btn-primary" id="b2" onclick="gTo(3)">Continue →</button>
      </div>
    </div>

    <!-- STEP 3: PROVIDER + HARDWARE MODE -->
    <div class="step" id="s3">
      <div class="slbl">Step 3 of 4</div>
      <div class="stit">AI engine & hardware mode</div>
      <div class="sdsc">Configure the AI provider and choose the initial container mode.</div>
      <div id="providerSection" style="display:none">
        <label style="margin-top:0">AI Provider</label>
        <div class="pl">
          <div class="pb sel" onclick="sPv('ollama',this)"><div class="pi">🦙</div><div><div class="pn">Ollama (Local)</div><div class="pd">Private, no API cost</div></div></div>
          <div class="pb" onclick="sPv('google',this)"><div class="pi">✦</div><div><div class="pn">Google Gemini</div><div class="pd">Free tier available</div></div></div>
          <div class="pb" onclick="sPv('anthropic',this)"><div class="pi">◆</div><div><div class="pn">Anthropic Claude</div><div class="pd">Best for reasoning tasks</div></div></div>
          <div class="pb" onclick="sPv('openai',this)"><div class="pi">⬡</div><div><div class="pn">OpenAI</div><div class="pd">GPT-4o, o4-mini</div></div></div>
          <div class="pb" onclick="sPv('openrouter',this)"><div class="pi">⇄</div><div><div class="pn">OpenRouter</div><div class="pd">One key, 300+ models</div></div></div>
        </div>
        <div id="pc-google" class="pc">
          <label>Gemini API Key *</label><input type="password" id="pg-key" placeholder="AIzaSy...">
          <div class="hint">Free key at <a href="https://aistudio.google.com/apikey" target="_blank">aistudio.google.com</a></div>
          <label>Model</label><select id="pg-mdl"><option value="gemini-2.5-flash">gemini-2.5-flash (Recommended)</option><option value="gemini-2.5-pro">gemini-2.5-pro</option><option value="gemini-2.0-flash">gemini-2.0-flash</option></select>
        </div>
        <div id="pc-anthropic" class="pc">
          <label>Claude API Key *</label><input type="password" id="pa-key" placeholder="sk-ant-...">
          <div class="hint">Key at <a href="https://console.anthropic.com" target="_blank">console.anthropic.com</a></div>
          <label>Model</label><select id="pa-mdl"><option value="claude-haiku-4-5-20251001">claude-haiku (Fast)</option><option value="claude-sonnet-4-6">claude-sonnet (Recommended)</option></select>
        </div>
        <div id="pc-openai" class="pc">
          <label>OpenAI API Key *</label><input type="password" id="po-key" placeholder="sk-...">
          <div class="hint">Key at <a href="https://platform.openai.com/api-keys" target="_blank">platform.openai.com</a></div>
          <label>Model</label><select id="po-mdl"><option value="gpt-4o-mini">gpt-4o-mini</option><option value="gpt-4o">gpt-4o</option><option value="o4-mini">o4-mini</option></select>
        </div>
        <div id="pc-openrouter" class="pc">
          <label>OpenRouter API Key *</label><input type="password" id="pr-key" placeholder="sk-or-...">
          <div class="hint">Free key at <a href="https://openrouter.ai/keys" target="_blank">openrouter.ai</a></div>
          <label>Model</label><select id="pr-mdl"><option value="openrouter/auto">auto (best available)</option><option value="google/gemini-2.5-flash">google/gemini-2.5-flash</option><option value="anthropic/claude-sonnet-4-6">anthropic/claude-sonnet</option><option value="meta-llama/llama-3.3-70b-instruct">llama-3.3-70b (free)</option></select>
        </div>
        <div id="pc-ollama" class="pc">
          <div class="info-box">Ollama must be running on this node or local network. No API key needed.</div>
          <label>Ollama URL</label><input type="url" id="pl-url" value="http://127.0.0.1:11434">
          <label>Model name *</label><input type="text" id="pl-mdl" placeholder="e.g. llama3.2, mistral, phi4">
        </div>
        <div class="divider"></div>
        <label>Agent autonomy</label>
        <div class="ao">
          <div class="ab" onclick="sAu('readonly',this)"><div class="ar"></div><div><div class="an">👁 Read-Only</div><div class="ad">Observe, read files, answer questions. Cannot execute commands.</div></div></div>
          <div class="ab" onclick="sAu('supervised',this)"><div class="ar"></div><div><div class="an">✋ Supervised <span style="font-size:11px;color:#6366f1;margin-left:6px">Recommended</span></div><div class="ad">Plans actions and waits for your approval before executing.</div></div></div>
          <div class="ab" onclick="sAu('full',this)"><div class="ar"></div><div><div class="an">⚡ Full Autonomy</div><div class="ad">Acts immediately, notifies you after. Best for background tasks.</div></div></div>
        </div>
        <div class="fw" id="fw">
          <strong>⚠ Full Autonomy — read before enabling</strong><br>
          Agent acts without asking. It can run Podman/systemctl commands and manage node services.
          <label><input type="checkbox" id="fc" onchange="chkS3()"> I understand and want the agent to act without approval</label>
        </div>
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
      <div class="stit">Review & initialize</div>
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
        <tr><td>Container Runtime</td><td>Podman + crun</td></tr>
      </table>
      <div class="info-box" style="margin-top:16px">After you click Initialize:<br>
      1. SSH access is configured for the <code>holo</code> user<br>
      2. Podman Quadlet services are registered with systemd<br>
      3. If the AI agent is enabled, ZeroClaw connects within ~60 seconds<br>
      4. This setup page redirects to the management panel</div>
      <div class="brow">
        <button class="btn btn-secondary" onclick="gTo(3)">← Back</button>
        <button class="btn btn-primary" id="bsub" onclick="doSubmit()">
          <span id="slbl">Initialize Node</span>
          <div class="spin" id="spin"></div>
        </button>
      </div>
    </div>

    <!-- SUCCESS -->
    <div class="step" id="suc">
      <div class="suc">
        <div style="font-size:48px;margin-bottom:16px">🜲</div>
        <h2>Node Initialized!</h2>
        <p>Redirecting to the management panel…</p>
      </div>
    </div>
  </div>
</div>
<script>
const S={{ch:null,pv:'ollama',au:null,agent:false}};
const CHN={{telegram:'Telegram',discord:'Discord',slack:'Slack',signal:'Signal',matrix:'Matrix',whatsapp:'WhatsApp'}};
const PVN={{holo:'Holo Intelligence Plus',google:'Google Gemini',anthropic:'Anthropic Claude',openai:'OpenAI',openrouter:'OpenRouter',ollama:'Ollama (Local)'}};

function gTo(n){{
  document.querySelectorAll('.step').forEach(s=>s.classList.remove('active'));
  document.getElementById(n===5?'suc':'s'+n).classList.add('active');
  document.getElementById('prog').style.width=(n/4*100)+'%';
  if(n===4)bRev();
  window.scrollTo(0,0);
}}

function chkS1(){{
  const ok=document.getElementById('nodeName').value.trim().length>0;
  document.getElementById('b1').disabled=!ok;
}}

function onAgentToggle(){{
  S.agent=document.getElementById('agentToggle').checked;
  document.getElementById('agentConfig').classList.toggle('vis',S.agent);
  document.getElementById('providerSection').style.display=S.agent?'block':'none';
  chkS3();
}}

function sCh(ch,el){{
  S.ch=ch;
  document.querySelectorAll('.cb').forEach(b=>b.classList.remove('sel'));
  el.classList.add('sel');
  document.querySelectorAll('.ch-cr').forEach(c=>c.style.display='none');
  document.getElementById('cr-'+ch).style.display='block';
}}

function sPv(pv,el){{
  S.pv=pv;
  document.querySelectorAll('.pb').forEach(b=>b.classList.remove('sel'));
  el.classList.add('sel');
  document.querySelectorAll('.pc').forEach(c=>c.classList.remove('vis'));
  document.getElementById('pc-'+pv).classList.add('vis');
  chkS3();
}}

function sAu(lvl,el){{
  S.au=lvl;
  document.querySelectorAll('.ab').forEach(b=>b.classList.remove('sel'));
  el.classList.add('sel');
  document.getElementById('fw').classList.toggle('vis',lvl==='full');
  if(lvl!=='full')document.getElementById('fc').checked=false;
  chkS3();
}}

function chkS3(){{
  let ok=true;
  if(S.agent){{
    if(!S.pv)ok=false;
    if(!S.au)ok=false;
    if(S.au==='full'&&!document.getElementById('fc').checked)ok=false;
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
  const set=(id,t)=>document.getElementById(id).textContent=t;
  set('rv-nn',v('nodeName')||'—');
  set('rv-sk',sk?sk.split(' ')[0]+' ••••':  '(not provided)');
  set('rv-ag',S.agent?'Enabled':'Disabled (SSH only)');
  set('rv-ch',S.agent?(CHN[S.ch]||'—'):'—');
  set('rv-pv',S.agent?(PVN[S.pv]||'—'):'—');
  set('rv-md',S.agent?(mdl||'(default)'):'—');
  set('rv-au',S.agent?({{readonly:'Read-Only',supervised:'Supervised',full:'Full Autonomy'}}[S.au]||'—'):'—');
  set('rv-hw',v('hw')==='WIND_TUNNEL'?'Wind Tunnel':'Standard EdgeNode');
}}

// Disable b3 initially; it will be re-checked when agent is toggled
document.getElementById('b3').disabled=false;

async function doSubmit(){{
  const nodeName=v('nodeName');
  if(!nodeName)return alert('Node name is required.');
  if(!/^[a-z0-9-]+$/.test(nodeName))return alert('Node name must be lowercase letters, numbers and hyphens only.');
  if(S.agent){{
    if(!S.ch)return alert('Please choose a chat app.');
    if(S.ch==='telegram'&&(!v('tg-tok')||!/^-?\d+$/.test(v('tg-uid'))))return alert('Fill in Telegram credentials.');
    if(S.ch==='discord'&&(!v('dc-tok')||!v('dc-uid')))return alert('Fill in Discord credentials.');
    if(S.ch==='slack'&&(!v('sl-bot')||!v('sl-app')||!v('sl-uid')))return alert('Fill in all Slack fields.');
    if(S.ch==='signal'&&(!v('sg-url')||!v('sg-acct')))return alert('Fill in Signal credentials.');
    if(S.ch==='matrix'&&(!v('mx-hs')||!v('mx-tok')||!v('mx-room')||!v('mx-uid')))return alert('Fill in all Matrix fields.');
    if(S.ch==='whatsapp'&&(!v('wa-pid')||!v('wa-tok')))return alert('Fill in WhatsApp credentials.');
    const needKey=['google','anthropic','openai','openrouter'];
    const keyMap={{google:'pg-key',anthropic:'pa-key',openai:'po-key',openrouter:'pr-key'}};
    if(needKey.includes(S.pv)&&!v(keyMap[S.pv]))return alert('Enter your API key.');
  }}
  const btn=document.getElementById('bsub');
  btn.disabled=true;
  document.getElementById('slbl').style.display='none';
  document.getElementById('spin').style.display='block';
  const p={{
    nodeName,sshKey:v('sshKey'),agentEnabled:S.agent,
    channel:S.ch||'',provider:S.pv||'',autonomyLevel:S.au||'supervised',hwMode:v('hw'),
    wifiSsid:v('wifiSsid'),wifiPass:v('wifiPass'),
    tgToken:v('tg-tok'),tgUid:v('tg-uid'),
    dcToken:v('dc-tok'),dcUid:v('dc-uid'),
    slBot:v('sl-bot'),slApp:v('sl-app'),slUid:v('sl-uid'),
    sgUrl:v('sg-url'),sgAcct:v('sg-acct'),sgAllowed:v('sg-alw'),
    mxHs:v('mx-hs'),mxTok:v('mx-tok'),mxRoom:v('mx-room'),mxUid:v('mx-uid'),
    waPid:v('wa-pid'),waTok:v('wa-tok'),waAllowed:v('wa-alw'),
    apiKey:(()=>{{if(S.pv==='google')return v('pg-key');if(S.pv==='anthropic')return v('pa-key');if(S.pv==='openai')return v('po-key');if(S.pv==='openrouter')return v('pr-key');return '';}})(),
    model:(()=>{{if(S.pv==='google')return v('pg-mdl');if(S.pv==='anthropic')return v('pa-mdl');if(S.pv==='openai')return v('po-mdl');if(S.pv==='openrouter')return v('pr-mdl');if(S.pv==='ollama')return v('pl-mdl')||'llama3.2';return '';}})(),
    apiUrl:S.pv==='ollama'?v('pl-url'):'',
  }};
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
        css = COMMON_CSS,
        wifi_block = wifi_block)
}

fn build_manage_html(state: &AppState) -> String {
    let node_name  = state.node_name.lock().unwrap().clone();
    let hw_mode    = state.hw_mode.lock().unwrap().clone();
    let channel    = state.channel.lock().unwrap().clone();
    let provider   = state.provider.lock().unwrap().clone();
    let model      = state.model.lock().unwrap().clone();
    let agent_on   = state.agent_enabled.load(Ordering::Relaxed);
    let ssh_keys   = read_ssh_keys();
    let uptime_s   = state.start_time.elapsed().unwrap_or_default().as_secs();
    let ip         = get_local_ip();

    // SSH keys list
    let keys_html: String = if ssh_keys.is_empty() {
        r#"<div class="no-keys">No SSH keys configured. Add one below to enable SSH access.</div>"#.to_string()
    } else {
        ssh_keys.iter().enumerate().map(|(i, k)| {
            let short = if k.len() > 72 {
                format!("{}…", &k[..72])
            } else {
                k.clone()
            };
            format!(
                r#"<div class="key-row"><span class="key-type">{}</span><span class="key-val">{}</span><button class="btn btn-danger btn-sm" onclick="removeKey({})">Remove</button></div>"#,
                html_escape(k.split_whitespace().next().unwrap_or("key")),
                html_escape(&short),
                i
            )
        }).collect()
    };

    let hw_std_sel  = if hw_mode != "WIND_TUNNEL" { " selected" } else { "" };
    let hw_wt_sel   = if hw_mode == "WIND_TUNNEL" { " selected" } else { "" };
    let agent_chk   = if agent_on { " checked" } else { "" };
    let agent_vis   = if agent_on { "" } else { "display:none" };

    format!(r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holo Node — {node_name}</title>
<style>
{css}
body{{align-items:flex-start}}
.card{{max-width:680px}}
.hdr{{display:flex;justify-content:space-between;align-items:center}}
.hdr-info{{}}
.hdr-meta{{font-size:12px;color:#6366f1;margin-top:4px}}
.logout{{background:transparent;border:1px solid rgba(255,255,255,.15);color:#94a3b8;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:13px;font-family:inherit}}
.logout:hover{{border-color:#6366f1;color:#e2e8f0}}
.section{{margin-bottom:24px}}
.section-hdr{{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:14px 16px;background:#0f1117;border:1px solid #2d3148;border-radius:10px;user-select:none}}
.section-title{{font-size:14px;font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:10px}}
.section-badge{{font-size:11px;padding:2px 8px;border-radius:20px;font-weight:600}}
.badge-green{{background:#0d2618;color:#86efac;border:1px solid #166534}}
.badge-gray{{background:#1a1d27;color:#64748b;border:1px solid #2d3148}}
.section-arrow{{color:#475569;transition:transform .2s;font-size:12px}}
.section-body{{padding:16px;border:1px solid #2d3148;border-top:none;border-radius:0 0 10px 10px;background:#13161f}}
.key-row{{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #1e2130}}
.key-row:last-child{{border-bottom:none}}
.key-type{{font-size:11px;font-weight:700;color:#6366f1;background:#1e1d3f;padding:2px 6px;border-radius:4px;flex-shrink:0;font-family:monospace}}
.key-val{{font-size:12px;color:#94a3b8;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}}
.no-keys{{font-size:13px;color:#475569;padding:10px 0}}
.btn-sm{{padding:6px 12px;font-size:12px;flex-shrink:0}}
.form-row{{display:flex;gap:10px;align-items:flex-end;margin-top:12px}}
.form-row input,.form-row textarea{{flex:1;margin:0}}
.form-row .btn{{flex-shrink:0}}
.provider-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}}
.pcard{{padding:12px;background:#0f1117;border:2px solid #2d3148;border-radius:8px;cursor:pointer;transition:all .2s;color:#94a3b8}}
.pcard:hover,.pcard.sel{{border-color:#6366f1;color:#a5b4fc}}.pcard.sel{{background:#1e1d3f}}
.pcard-name{{font-size:13px;font-weight:600}}.pcard-desc{{font-size:11px;color:#475569;margin-top:2px}}
.provider-creds{{display:none;margin-top:12px}}.provider-creds.vis{{display:block}}
.toggle-row{{display:flex;align-items:center;justify-content:space-between;padding:12px 0}}
.toggle-label{{font-size:14px;font-weight:600;color:#e2e8f0}}
.toggle{{position:relative;width:48px;height:26px;flex-shrink:0}}
.toggle input{{opacity:0;width:0;height:0}}
.slider{{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#2d3148;border-radius:13px;transition:.3s}}
.slider:before{{position:absolute;content:'';height:18px;width:18px;left:4px;bottom:4px;background:#64748b;border-radius:50%;transition:.3s}}
input:checked+.slider{{background:#6366f1}}
input:checked+.slider:before{{transform:translateX(22px);background:#fff}}
.toast{{position:fixed;bottom:24px;right:24px;padding:12px 18px;border-radius:10px;font-size:13px;font-weight:600;z-index:1000;opacity:0;transform:translateY(8px);transition:all .25s;pointer-events:none}}
.toast.vis{{opacity:1;transform:translateY(0)}}
.toast.ok{{background:#0d2618;border:1px solid #166534;color:#86efac}}
.toast.err{{background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5}}
.info-row{{display:flex;gap:24px;padding:12px 0;border-bottom:1px solid #2d3148;margin-bottom:16px;flex-wrap:wrap}}
.info-item{{font-size:12px;color:#64748b}}.info-item span{{color:#e2e8f0;font-weight:600;margin-left:4px}}
.hw-opts{{display:flex;gap:10px;margin-top:10px}}
.hw-opt{{flex:1;padding:14px;background:#0f1117;border:2px solid #2d3148;border-radius:8px;cursor:pointer;text-align:center;transition:all .2s;color:#94a3b8}}
.hw-opt:hover,.hw-opt.sel{{border-color:#6366f1;color:#a5b4fc}}.hw-opt.sel{{background:#1e1d3f}}
.hw-opt-name{{font-size:13px;font-weight:600}}.hw-opt-desc{{font-size:11px;color:#475569;margin-top:4px}}
</style></head><body>
<div id="toast" class="toast"></div>
<div class="card">
  <div class="hdr">
    <div class="hdr-info">
      <h1>🜲 {node_name}</h1>
      <div class="hdr-meta">v{version} · {ip} · uptime {uptime}</div>
    </div>
    <form method="POST" action="/logout" style="margin:0"><button type="submit" class="logout">Log out</button></form>
  </div>
  <div class="body" style="padding-top:0">
    <div class="info-row">
      <div class="info-item">Agent<span id="info-agent">{agent_badge}</span></div>
      <div class="info-item">Hardware<span id="info-hw">{hw_mode_display}</span></div>
      <div class="info-item">Channel<span id="info-ch">{channel_display}</span></div>
      <div class="info-item">Provider<span id="info-pv">{provider_display}</span></div>
    </div>

    <!-- SSH KEYS -->
    <div class="section">
      <div class="section-hdr" onclick="toggleSection('ssh')">
        <div class="section-title"><span>🔑</span> SSH Keys <span class="section-badge badge-green">{ssh_count} key{ssh_plural}</span></div>
        <span class="section-arrow" id="arr-ssh">▼</span>
      </div>
      <div class="section-body" id="sec-ssh">
        <div id="key-list">{keys_html}</div>
        <div style="margin-top:12px">
          <label>Add SSH public key</label>
          <textarea id="newKey" placeholder="ssh-ed25519 AAAA... or ssh-rsa AAAA..."></textarea>
          <div style="margin-top:8px"><button class="btn btn-primary" onclick="addKey()">Add Key</button></div>
        </div>
      </div>
    </div>

    <!-- AI AGENT -->
    <div class="section">
      <div class="section-hdr" onclick="toggleSection('agent')">
        <div class="section-title"><span>🤖</span> AI Agent <span class="section-badge {agent_badge_class}">{agent_badge}</span></div>
        <span class="section-arrow" id="arr-agent">▼</span>
      </div>
      <div class="section-body" id="sec-agent">
        <div class="toggle-row">
          <div><div class="toggle-label">Enable ZeroClaw AI agent</div></div>
          <label class="toggle"><input type="checkbox" id="agentToggle"{agent_chk} onchange="toggleAgent(this.checked)"><span class="slider"></span></label>
        </div>
        <div id="agentDetails" style="{agent_vis}">
          <div class="divider" style="margin:8px 0 16px"></div>
          <label>AI Provider</label>
          <div class="provider-grid">
            <div class="pcard{sel_holo}" onclick="selPv('holo',this)"><div class="pcard-name">🜲 Holo Intelligence</div><div class="pcard-desc">Included</div></div>
            <div class="pcard{sel_google}" onclick="selPv('google',this)"><div class="pcard-name">✦ Google Gemini</div><div class="pcard-desc">Free tier available</div></div>
            <div class="pcard{sel_anthropic}" onclick="selPv('anthropic',this)"><div class="pcard-name">◆ Anthropic Claude</div><div class="pcard-desc">Best reasoning</div></div>
            <div class="pcard{sel_openai}" onclick="selPv('openai',this)"><div class="pcard-name">⬡ OpenAI</div><div class="pcard-desc">GPT-4o, o4-mini</div></div>
            <div class="pcard{sel_openrouter}" onclick="selPv('openrouter',this)"><div class="pcard-name">⇄ OpenRouter</div><div class="pcard-desc">300+ models</div></div>
            <div class="pcard{sel_ollama}" onclick="selPv('ollama',this)"><div class="pcard-name">🦙 Ollama</div><div class="pcard-desc">Local / private</div></div>
          </div>
          <div id="mp-holo" class="provider-creds{vis_holo}"><div class="ok-box" style="margin-top:12px">✓ No API key required.</div></div>
          <div id="mp-google" class="provider-creds{vis_google}">
            <label>Gemini API Key</label><input type="password" id="m-gkey" placeholder="AIzaSy...">
            <label>Model</label><select id="m-gmdl"><option>gemini-2.5-flash</option><option>gemini-2.5-pro</option><option>gemini-2.0-flash</option></select>
          </div>
          <div id="mp-anthropic" class="provider-creds{vis_anthropic}">
            <label>Claude API Key</label><input type="password" id="m-akey" placeholder="sk-ant-...">
            <label>Model</label><select id="m-amdl"><option value="claude-haiku-4-5-20251001">claude-haiku</option><option value="claude-sonnet-4-6">claude-sonnet</option></select>
          </div>
          <div id="mp-openai" class="provider-creds{vis_openai}">
            <label>OpenAI API Key</label><input type="password" id="m-okey" placeholder="sk-...">
            <label>Model</label><select id="m-omdl"><option>gpt-4o-mini</option><option>gpt-4o</option><option>o4-mini</option></select>
          </div>
          <div id="mp-openrouter" class="provider-creds{vis_openrouter}">
            <label>OpenRouter API Key</label><input type="password" id="m-rkey" placeholder="sk-or-...">
            <label>Model</label><select id="m-rmdl"><option value="openrouter/auto">auto</option><option value="google/gemini-2.5-flash">google/gemini-2.5-flash</option><option value="anthropic/claude-sonnet-4-6">anthropic/claude-sonnet</option></select>
          </div>
          <div id="mp-ollama" class="provider-creds{vis_ollama}">
            <label>Ollama URL</label><input type="url" id="m-lurl" value="http://127.0.0.1:11434">
            <label>Model name</label><input type="text" id="m-lmdl" placeholder="llama3.2">
          </div>
          <div style="margin-top:14px"><button class="btn btn-primary" onclick="saveProvider()">Save Provider</button></div>
        </div>
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
          <div class="hw-opt{sel_std}" id="hw-std" onclick="selHw('STANDARD',this)">
            <div class="hw-opt-name">🌐 Standard EdgeNode</div>
            <div class="hw-opt-desc">Always-on Holochain peer</div>
          </div>
          <div class="hw-opt{sel_wt}" id="hw-wt" onclick="selHw('WIND_TUNNEL',this)">
            <div class="hw-opt-name">🌀 Wind Tunnel</div>
            <div class="hw-opt-desc">Network stress-tester</div>
          </div>
        </div>
        <div style="margin-top:14px"><button class="btn btn-primary" onclick="saveHardware()">Apply Mode</button></div>
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
        <p style="font-size:13px;color:#64748b;margin-bottom:14px">The node checks for updates automatically every hour from GitHub Releases. You can also trigger an immediate check.</p>
        <button class="btn btn-primary" onclick="triggerUpdate()" id="upd-btn">Check for Updates</button>
        <div id="upd-msg" style="margin-top:10px;font-size:13px;color:#64748b;display:none"></div>
      </div>
    </div>
  </div>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────────
let curPv = '{provider_js}';
let curHw = '{hw_mode}';
let openSections = {{}};

// ── Section toggle ─────────────────────────────────────────────────────────────
function toggleSection(id){{
  const body = document.getElementById('sec-'+id);
  const arr  = document.getElementById('arr-'+id);
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  arr.textContent = open ? '▶' : '▼';
}}
// Collapse all sections on load except SSH
['agent','hw','pw','upd'].forEach(id=>toggleSection(id));

// ── Toast ──────────────────────────────────────────────────────────────────────
function toast(msg, ok){{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast '+(ok?'ok':'err')+' vis';
  clearTimeout(t._timer);
  t._timer = setTimeout(()=>t.classList.remove('vis'), 3000);
}}

// ── Generic POST ───────────────────────────────────────────────────────────────
async function api(path, payload){{
  const r = await fetch(path, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
  const text = await r.text();
  if(!r.ok) throw new Error(text || 'Server error '+r.status);
  return text;
}}

// ── SSH Keys ───────────────────────────────────────────────────────────────────
async function addKey(){{
  const key = document.getElementById('newKey').value.trim();
  if(!key) return toast('Paste a public key first', false);
  try{{
    await api('/manage/ssh/add', {{key}});
    document.getElementById('newKey').value='';
    toast('Key added — reloading…', true);
    setTimeout(()=>location.reload(), 800);
  }}catch(e){{toast('Error: '+e.message, false);}}
}}

async function removeKey(i){{
  if(!confirm('Remove this SSH key?')) return;
  try{{
    await api('/manage/ssh/remove', {{index:i}});
    toast('Key removed — reloading…', true);
    setTimeout(()=>location.reload(), 800);
  }}catch(e){{toast('Error: '+e.message, false);}}
}}

// ── Agent toggle ───────────────────────────────────────────────────────────────
function toggleAgent(on){{
  document.getElementById('agentDetails').style.display = on ? 'block' : 'none';
  api('/manage/agent', {{enabled:on}})
    .then(()=>toast(on?'Agent enabled':'Agent disabled', true))
    .catch(e=>toast('Error: '+e.message, false));
}}

// ── Provider ───────────────────────────────────────────────────────────────────
function selPv(pv, el){{
  curPv = pv;
  document.querySelectorAll('.pcard').forEach(c=>c.classList.remove('sel'));
  el.classList.add('sel');
  document.querySelectorAll('.provider-creds').forEach(c=>c.classList.remove('vis'));
  document.getElementById('mp-'+pv).classList.add('vis');
}}

function v(id){{ const e=document.getElementById(id); return e?e.value.trim():''; }}

async function saveProvider(){{
  let key='', model='', apiUrl='';
  if(curPv==='google')  {{key=v('m-gkey'); model=v('m-gmdl');}}
  else if(curPv==='anthropic') {{key=v('m-akey'); model=v('m-amdl');}}
  else if(curPv==='openai')   {{key=v('m-okey'); model=v('m-omdl');}}
  else if(curPv==='openrouter'){{key=v('m-rkey'); model=v('m-rmdl');}}
  else if(curPv==='ollama')   {{apiUrl=v('m-lurl'); model=v('m-lmdl');}}
  try{{
    await api('/manage/provider', {{provider:curPv, model, apiKey:key, apiUrl}});
    toast('Provider updated — agent restarting…', true);
    setTimeout(()=>location.reload(), 1500);
  }}catch(e){{toast('Error: '+e.message, false);}}
}}

// ── Hardware mode ──────────────────────────────────────────────────────────────
function selHw(mode, el){{
  curHw = mode;
  document.querySelectorAll('.hw-opt').forEach(o=>o.classList.remove('sel'));
  el.classList.add('sel');
}}

async function saveHardware(){{
  try{{
    await api('/manage/hardware', {{mode:curHw}});
    document.getElementById('hw-badge').textContent = curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    document.getElementById('info-hw').textContent  = curHw==='WIND_TUNNEL'?'Wind Tunnel':'EdgeNode';
    toast('Hardware mode switching…', true);
  }}catch(e){{toast('Error: '+e.message, false);}}
}}

// ── Password ───────────────────────────────────────────────────────────────────
async function changePassword(){{
  const cur = v('pw-cur'), nw = v('pw-new'), cfm = v('pw-cfm');
  if(!cur||!nw) return toast('Fill in all password fields', false);
  if(nw !== cfm) return toast('New passwords do not match', false);
  if(nw.length < 8) return toast('New password must be at least 8 characters', false);
  try{{
    await api('/manage/password', {{current:cur, newPassword:nw}});
    document.getElementById('pw-cur').value='';
    document.getElementById('pw-new').value='';
    document.getElementById('pw-cfm').value='';
    toast('Password updated', true);
  }}catch(e){{toast('Error: '+e.message, false);}}
}}

// ── Software update ────────────────────────────────────────────────────────────
async function triggerUpdate(){{
  const btn = document.getElementById('upd-btn');
  const msg = document.getElementById('upd-msg');
  btn.disabled = true;
  btn.textContent = 'Checking…';
  msg.style.display='block';
  msg.textContent='Querying GitHub Releases…';
  try{{
    await api('/manage/update', {{}});
    msg.textContent='Update check triggered. If a newer version was found, the node will restart automatically within 60 seconds.';
    toast('Update check started', true);
  }}catch(e){{
    msg.textContent='Error: '+e.message;
    toast('Update check failed', false);
  }}finally{{
    btn.disabled=false;
    btn.textContent='Check for Updates';
  }}
}}
</script>
</body></html>"##,
        css            = COMMON_CSS,
        node_name      = html_escape(&node_name),
        version        = VERSION,
        ip             = ip,
        uptime         = fmt_uptime(uptime_s),
        agent_badge    = if agent_on { "Enabled" } else { "Disabled" },
        agent_badge_class = if agent_on { "badge-green" } else { "badge-gray" },
        agent_chk      = agent_chk,
        agent_vis      = agent_vis,
        hw_mode_display = if hw_mode == "WIND_TUNNEL" { "Wind Tunnel" } else { "EdgeNode" },
        hw_mode        = hw_mode,
        channel_display = if channel.is_empty() { "—".to_string() } else { channel.clone() },
        provider_display = if provider.is_empty() { "—".to_string() } else { provider.clone() },
        provider_js    = html_escape(&provider),
        keys_html      = keys_html,
        ssh_count      = ssh_keys.len(),
        ssh_plural     = if ssh_keys.len() == 1 { "" } else { "s" },
        sel_std        = if hw_mode != "WIND_TUNNEL" { " sel" } else { "" },
        sel_wt         = if hw_mode == "WIND_TUNNEL" { " sel" } else { "" },
        sel_holo       = if provider == "holo"       { " sel" } else { "" },
        sel_google     = if provider == "google"     { " sel" } else { "" },
        sel_anthropic  = if provider == "anthropic"  { " sel" } else { "" },
        sel_openai     = if provider == "openai"     { " sel" } else { "" },
        sel_openrouter = if provider == "openrouter" { " sel" } else { "" },
        sel_ollama     = if provider == "ollama"     { " sel" } else { "" },
        vis_holo       = if provider == "holo"       { " vis" } else { "" },
        vis_google     = if provider == "google"     { " vis" } else { "" },
        vis_anthropic  = if provider == "anthropic"  { " vis" } else { "" },
        vis_openai     = if provider == "openai"     { " vis" } else { "" },
        vis_openrouter = if provider == "openrouter" { " vis" } else { "" },
        vis_ollama     = if provider == "ollama"     { " vis" } else { "" },
    )
}

fn fmt_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

// ── Request dispatcher ─────────────────────────────────────────────────────────

fn handle(stream: &mut TcpStream, state: Arc<AppState>, auth_hash: Arc<Mutex<String>>) {
    let req = match read_request(stream) {
        Some(r) => r,
        None => return,
    };

    let path = req.path.as_str();
    let method = req.method.as_str();

    // ── Public routes ────────────────────────────────────────────────────────
    match (method, path) {
        ("GET", "/login") => {
            send_html(stream, &build_login_html(false));
            return;
        }
        ("POST", "/login") => {
            let form = parse_form(&req.body);
            let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
            let hash = auth_hash.lock().unwrap().clone();
            if verify_password(password, &hash) {
                let token = create_session(&state);
                send_redirect_with_cookie(stream, "/manage", &session_cookie(&token));
            } else {
                send_html(stream, &build_login_html(true));
            }
            return;
        }
        ("POST", "/logout") => {
            if let Some(token) = get_cookie(&req.headers, "session") {
                state.sessions.lock().unwrap().remove(&token);
            }
            let hdr = format!(
                "HTTP/1.1 302 Found\r\nLocation: /login\r\nSet-Cookie: {}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n",
                clear_cookie()
            );
            let _ = stream.write_all(hdr.as_bytes());
            return;
        }
        ("GET", "/") => {
            if state.onboarded.load(Ordering::Relaxed) {
                send_redirect(stream, "/manage");
            } else {
                send_html(stream, &build_onboarding_html(state.ap_mode));
            }
            return;
        }
        ("POST", "/submit") => {
            handle_submit(stream, &req, &state, &auth_hash);
            return;
        }
        _ => {}
    }

    // ── Auth-gated routes ────────────────────────────────────────────────────
    if !is_authenticated(&req, &state) {
        send_redirect(stream, "/login");
        return;
    }

    match (method, path) {
        ("GET", "/manage") => {
            send_html(stream, &build_manage_html(&state));
        }
        ("GET", "/manage/status") => {
            handle_manage_status(stream, &state);
        }
        ("POST", "/manage/ssh/add") => {
            handle_ssh_add(stream, &req);
        }
        ("POST", "/manage/ssh/remove") => {
            handle_ssh_remove(stream, &req);
        }
        ("POST", "/manage/agent") => {
            handle_agent_toggle(stream, &req, &state);
        }
        ("POST", "/manage/provider") => {
            handle_provider_swap(stream, &req, &state);
        }
        ("POST", "/manage/hardware") => {
            handle_hardware_switch(stream, &req, &state);
        }
        ("POST", "/manage/password") => {
            handle_password_change(stream, &req, &auth_hash);
        }
        ("POST", "/manage/update") => {
            let repo = env::var(UPDATE_REPO_ENV)
                .unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
            thread::spawn(move || check_and_apply_update(&repo));
            send_json_ok(stream, r#"{"status":"update check triggered"}"#);
        }
        _ => {
            send_response(stream, 404, "Not Found", "text/plain", b"Not Found");
        }
    }
}

// ── Route handlers ─────────────────────────────────────────────────────────────

fn handle_submit(
    stream: &mut TcpStream,
    req: &Req,
    state: &AppState,
    auth_hash: &Arc<Mutex<String>>,
) {
    let body = &req.body;
    let node_name   = json_str(body, "nodeName");
    let ssh_key     = json_str(body, "sshKey");
    let agent_on    = json_bool(body, "agentEnabled");
    let channel     = json_str(body, "channel");
    let provider    = json_str(body, "provider");
    let api_key     = json_str(body, "apiKey");
    let model       = json_str(body, "model");
    let api_url     = json_str(body, "apiUrl");
    let hw_mode     = json_str(body, "hwMode");
    let level       = match json_str(body, "autonomyLevel") {
        "readonly" | "full" => json_str(body, "autonomyLevel"),
        _ => "supervised",
    };

    if node_name.is_empty() {
        send_json_err(stream, 400, "nodeName is required");
        return;
    }

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
    for dir in &[
        "/etc/node-onboarding",
        SKILLS_DIR,
        QUADLET_DIR,
        WORKSPACE_DIR,
        "/var/lib/edgenode",
        "/home/holo/.ssh",
    ] {
        let _ = fs::create_dir_all(dir);
    }

    // ── SSH keys ─────────────────────────────────────────────────────────────
    if !ssh_key.trim().is_empty() {
        if !is_valid_ssh_pubkey(ssh_key) {
            send_json_err(stream, 400, "Invalid SSH public key format");
            return;
        }
        if let Err(e) = write_ssh_keys(&[ssh_key.to_string()]) {
            let msg = format!("Failed to write SSH key: {}", e);
            send_json_err(stream, 500, &msg);
            return;
        }
        eprintln!("[onboard] SSH key written for holo user");
    }

    // ── Quadlets ─────────────────────────────────────────────────────────────
    let wt_hostname    = format!("nomad-client-{}", node_name);
    let edgenode_image = resolve_edgenode_image();
    let wt_image       = resolve_wind_tunnel_image();
    eprintln!("[onboard] edgenode image: {}", edgenode_image);
    eprintln!("[onboard] wind-tunnel image: {}", wt_image);

    let _ = fs::write(
        format!("{}/edgenode.container", QUADLET_DIR),
        build_edgenode_quadlet(&edgenode_image),
    );
    let _ = fs::write(
        format!("{}/wind-tunnel.container", QUADLET_DIR),
        build_wind_tunnel_quadlet(&wt_hostname, &wt_image),
    );
    eprintln!("[onboard] daemon-reload");
    let _ = Command::new("systemctl").args(["daemon-reload"]).output();

    // ── Mode file ────────────────────────────────────────────────────────────
    let _ = fs::write(
        format!("{}/mode_switch.txt", WORKSPACE_DIR),
        if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" },
    );

    // ── Start container ──────────────────────────────────────────────────────
    let initial_svc = if hw_mode == "WIND_TUNNEL" {
        "wind-tunnel.service"
    } else {
        "edgenode.service"
    };
    eprintln!("[onboard] Starting {}", initial_svc);
    let _ = Command::new("systemctl").args(["start", initial_svc]).output();

    // ── Agent (optional) ─────────────────────────────────────────────────────
    if agent_on {
        if channel.is_empty() || provider.is_empty() {
            send_json_err(stream, 400, "channel and provider required when agent is enabled");
            return;
        }
        let pv_cfg = match make_provider_config(provider, model, api_key, api_url) {
            Some(c) => c,
            None => {
                send_json_err(stream, 400, "unknown provider");
                return;
            }
        };

        eprintln!("[onboard] Running zeroclaw onboard");
        if let Err(e) = run_zeroclaw_onboard(&pv_cfg) {
            send_json_err(stream, 500, &e);
            return;
        }

        let config = match fs::read_to_string("/etc/zeroclaw/config.toml") {
            Ok(c) => c,
            Err(e) => {
                send_json_err(stream, 500, &format!("config not found: {}", e));
                return;
            }
        };

        let mut final_config = patch_config(&config, level);
        final_config.push('\n');
        final_config.push_str(&build_channel_toml(body, channel));

        if let Err(e) = fs::write("/etc/zeroclaw/config.toml", &final_config) {
            send_json_err(stream, 500, &format!("failed to write config: {}", e));
            return;
        }
        let _ = Command::new("chmod").args(["600", "/etc/zeroclaw/config.toml"]).output();

        // Persist provider credentials for hot-swap / re-enable
        let _ = fs::write(
            PROVIDER_FILE,
            format!(
                "provider={}\nmodel={}\napi_key={}\napi_url={}\n",
                toml_escape(provider), toml_escape(&pv_cfg.model),
                toml_escape(api_key), toml_escape(api_url)
            ),
        );
        let _ = Command::new("chmod").args(["600", PROVIDER_FILE]).output();

        let _ = fs::write(format!("{}/wind-tunnel.env", "/etc/zeroclaw"),
            format!("WIND_TUNNEL_HOSTNAME={}\n", wt_hostname));
        let _ = fs::write(format!("{}/holo-node.md", SKILLS_DIR), HOLO_NODE_SKILL);

        eprintln!("[onboard] Starting zeroclaw-daemon");
        let _ = Command::new("systemctl").args(["start", "zeroclaw-daemon.service"]).output();

        // Welcome message after brief startup pause
        let body_clone = body.to_string();
        let channel_str = channel.to_string();
        let hw_str = hw_mode.to_string();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(8));
            send_welcome_message(&channel_str, &body_clone, &hw_str);
        });
    }

    // ── Persist state ────────────────────────────────────────────────────────
    let mut kv = HashMap::new();
    kv.insert("onboarded".to_string(), "true".to_string());
    kv.insert("node_name".to_string(), node_name.to_string());
    kv.insert("hw_mode".to_string(), if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string());
    kv.insert("agent_enabled".to_string(), agent_on.to_string());
    kv.insert("channel".to_string(), channel.to_string());
    kv.insert("provider".to_string(), provider.to_string());
    kv.insert("model".to_string(), model.to_string());
    write_state_file(&kv);

    // ── Update in-memory state ───────────────────────────────────────────────
    *state.node_name.lock().unwrap() = node_name.to_string();
    *state.hw_mode.lock().unwrap() = if hw_mode == "WIND_TUNNEL" { "WIND_TUNNEL" } else { "STANDARD" }.to_string();
    *state.channel.lock().unwrap() = channel.to_string();
    *state.provider.lock().unwrap() = provider.to_string();
    *state.model.lock().unwrap() = model.to_string();
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
        .collect::<Vec<_>>()
        .join(",");

    let json = format!(
        r#"{{"version":"{}","node_name":"{}","hw_mode":"{}","agent_enabled":{},"channel":"{}","provider":"{}","model":"{}","ssh_key_count":{},"ssh_keys":[{}],"uptime_secs":{}}}"#,
        VERSION, node_name, hw_mode, agent, channel, provider, model,
        keys.len(), keys_json, uptime
    );
    send_json_ok(stream, &json);
}

fn handle_ssh_add(stream: &mut TcpStream, req: &Req) {
    let key = json_str(&req.body, "key");
    if key.is_empty() {
        send_json_err(stream, 400, "key is required");
        return;
    }
    if !is_valid_ssh_pubkey(key) {
        send_json_err(stream, 400, "Invalid SSH public key format");
        return;
    }
    let mut keys = read_ssh_keys();
    // Deduplicate
    if keys.iter().any(|k| k == key) {
        send_json_err(stream, 409, "Key already present");
        return;
    }
    keys.push(key.to_string());
    match write_ssh_keys(&keys) {
        Ok(()) => send_json_ok(stream, r#"{"status":"added"}"#),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_ssh_remove(stream: &mut TcpStream, req: &Req) {
    // Parse index from JSON: {"index": 2}
    let idx_str = {
        let needle = "\"index\":";
        match req.body.find(needle) {
            None => {
                send_json_err(stream, 400, "index is required");
                return;
            }
            Some(p) => req.body[p + needle.len()..].trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("")
                .to_string(),
        }
    };
    let idx: usize = match idx_str.parse() {
        Ok(i) => i,
        Err(_) => {
            send_json_err(stream, 400, "invalid index");
            return;
        }
    };
    let mut keys = read_ssh_keys();
    if idx >= keys.len() {
        send_json_err(stream, 404, "index out of range");
        return;
    }
    keys.remove(idx);
    match write_ssh_keys(&keys) {
        Ok(()) => send_json_ok(stream, r#"{"status":"removed"}"#),
        Err(e) => send_json_err(stream, 500, &e),
    }
}

fn handle_agent_toggle(stream: &mut TcpStream, req: &Req, state: &AppState) {
    let enable = json_bool(&req.body, "enabled");

    if enable && !state.agent_enabled.load(Ordering::Relaxed) {
        // Re-enable: need stored provider config
        let pf = fs::read_to_string(PROVIDER_FILE).unwrap_or_default();
        let pf_kv: HashMap<String, String> = pf.lines()
            .filter_map(|l| l.find('=').map(|e| (l[..e].to_string(), l[e+1..].to_string())))
            .collect();
        let provider = pf_kv.get("provider").map(|s| s.as_str()).unwrap_or("holo");
        let model    = pf_kv.get("model").map(|s| s.as_str()).unwrap_or("");
        let api_key  = pf_kv.get("api_key").map(|s| s.as_str()).unwrap_or("");
        let api_url  = pf_kv.get("api_url").map(|s| s.as_str()).unwrap_or("");

        let pv_cfg = match make_provider_config(provider, model, api_key, api_url) {
            Some(c) => c,
            None => {
                send_json_err(stream, 400, "invalid stored provider config");
                return;
            }
        };
        if let Err(e) = run_zeroclaw_onboard(&pv_cfg) {
            send_json_err(stream, 500, &e);
            return;
        }
        // Restore patched config
        if let Ok(config) = fs::read_to_string("/etc/zeroclaw/config.toml") {
            let autonomy = read_state_file().get("autonomy").cloned().unwrap_or_else(|| "supervised".into());
            let channel_cfg = extract_channel_config(&config);
            let mut final_config = patch_config(&config, &autonomy);
            final_config.push('\n');
            final_config.push_str(&channel_cfg);
            let _ = fs::write("/etc/zeroclaw/config.toml", &final_config);
            let _ = Command::new("chmod").args(["600", "/etc/zeroclaw/config.toml"]).output();
        }
        let _ = Command::new("systemctl").args(["start", "zeroclaw-daemon.service"]).output();
        eprintln!("[manage] Agent re-enabled");
    } else if !enable && state.agent_enabled.load(Ordering::Relaxed) {
        let _ = Command::new("systemctl").args(["stop", "zeroclaw-daemon.service"]).output();
        eprintln!("[manage] Agent disabled");
    }

    state.agent_enabled.store(enable, Ordering::Relaxed);
    update_state_key("agent_enabled", if enable { "true" } else { "false" });
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_provider_swap(stream: &mut TcpStream, req: &Req, state: &AppState) {
    let provider = json_str(&req.body, "provider");
    let model    = json_str(&req.body, "model");
    let api_key  = json_str(&req.body, "apiKey");
    let api_url  = json_str(&req.body, "apiUrl");

    if provider.is_empty() {
        send_json_err(stream, 400, "provider is required");
        return;
    }
    let pv_cfg = match make_provider_config(provider, model, api_key, api_url) {
        Some(c) => c,
        None => {
            send_json_err(stream, 400, "unknown provider");
            return;
        }
    };

    eprintln!("[manage] Provider swap → {}", provider);
    if let Err(e) = run_zeroclaw_onboard(&pv_cfg) {
        send_json_err(stream, 500, &e);
        return;
    }

    // Re-apply patches, preserving existing channel config
    let config = match fs::read_to_string("/etc/zeroclaw/config.toml") {
        Ok(c) => c,
        Err(e) => {
            send_json_err(stream, 500, &format!("config not found: {}", e));
            return;
        }
    };
    let autonomy = read_state_file().get("autonomy").cloned().unwrap_or_else(|| "supervised".into());
    let channel_cfg = extract_channel_config(&config);
    let mut final_config = patch_config(&config, &autonomy);
    final_config.push('\n');
    final_config.push_str(&channel_cfg);
    let _ = fs::write("/etc/zeroclaw/config.toml", &final_config);
    let _ = Command::new("chmod").args(["600", "/etc/zeroclaw/config.toml"]).output();

    // Update stored provider file
    let _ = fs::write(
        PROVIDER_FILE,
        format!(
            "provider={}\nmodel={}\napi_key={}\napi_url={}\n",
            toml_escape(provider), toml_escape(&pv_cfg.model),
            toml_escape(api_key), toml_escape(api_url)
        ),
    );
    let _ = Command::new("chmod").args(["600", PROVIDER_FILE]).output();

    // Restart daemon
    let _ = Command::new("systemctl").args(["restart", "zeroclaw-daemon.service"]).output();

    *state.provider.lock().unwrap() = provider.to_string();
    *state.model.lock().unwrap() = pv_cfg.model.clone();
    update_state_key("provider", provider);
    update_state_key("model", &pv_cfg.model);

    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_hardware_switch(stream: &mut TcpStream, req: &Req, state: &AppState) {
    let mode = json_str(&req.body, "mode");
    let mode = match mode {
        "WIND_TUNNEL" => "WIND_TUNNEL",
        _ => "STANDARD",
    };
    apply_hardware_mode(mode, state);
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

fn handle_password_change(
    stream: &mut TcpStream,
    req: &Req,
    auth_hash: &Arc<Mutex<String>>,
) {
    let current  = json_str(&req.body, "current");
    let new_pass = json_str(&req.body, "newPassword");

    if current.is_empty() || new_pass.is_empty() {
        send_json_err(stream, 400, "current and newPassword are required");
        return;
    }
    if new_pass.len() < 8 {
        send_json_err(stream, 400, "new password must be at least 8 characters");
        return;
    }

    let stored = auth_hash.lock().unwrap().clone();
    if !verify_password(current, &stored) {
        send_json_err(stream, 403, "current password is incorrect");
        return;
    }

    let new_hash = hash_password(new_pass);
    let _ = fs::write(AUTH_FILE, &new_hash);
    let _ = Command::new("chmod").args(["600", AUTH_FILE]).output();
    *auth_hash.lock().unwrap() = new_hash;

    eprintln!("[manage] Password changed");
    send_json_ok(stream, r#"{"status":"ok"}"#);
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let ap_mode = env::var("AP_MODE").unwrap_or_default() == "true";
    let state   = Arc::new(AppState::new(ap_mode));

    // Generate or load auth credential; display on HDMI if this is first run.
    let auth_hash = Arc::new(Mutex::new(load_or_create_auth()));

    // Spawn background self-update checker.
    let repo = env::var(UPDATE_REPO_ENV).unwrap_or_else(|_| UPDATE_REPO_DEFAULT.to_string());
    spawn_update_checker(repo);

    let listener = TcpListener::bind("0.0.0.0:8080").expect("failed to bind :8080");
    eprintln!("Holo node-onboarding v{} on :8080", VERSION);
    eprintln!(
        "State: onboarded={} agent={} hw={}",
        state.onboarded.load(Ordering::Relaxed),
        state.agent_enabled.load(Ordering::Relaxed),
        state.hw_mode.lock().unwrap()
    );

    for stream in listener.incoming() {
        let mut s = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let st = Arc::clone(&state);
        let ah = Arc::clone(&auth_hash);
        thread::spawn(move || handle(&mut s, st, ah));
    }
}
