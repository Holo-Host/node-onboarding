# node-manager

The onboarding and management server that ships inside every Holo Node.

It is a single Rust binary with zero external dependencies — no Tokio, no Axum, no serde. It serves a browser UI over plain TCP on port 8080 and handles the full lifecycle of a node: first-time setup, SSH key management, AI agent configuration, hardware mode switching, and binary self-updates pulled from this repository's GitHub Releases.

---

## Table of contents

1. [How it fits into the system](#how-it-fits-into-the-system)
2. [What it does](#what-it-does)
3. [Building locally](#building-locally)
4. [Repository structure](#repository-structure)
5. [Shipping a release](#shipping-a-release)
6. [Self-update mechanism](#self-update-mechanism)
7. [Switching OpenClaw forks](#switching-openclaw-forks)
8. [Routes reference](#routes-reference)
9. [File paths on the node](#file-paths-on-the-node)
10. [Security model](#security-model)
11. [Adding a new chat channel](#adding-a-new-chat-channel)
12. [Contributing](#contributing)

---

## How it fits into the system

```
holo-host/holo-node-iso          holo-host/node-manager
        │                                  │
        │  Butane YAML + build scripts     │  source + release pipeline
        │                                  │
        │  ISO contains node-setup.sh,     │  GitHub Actions builds two
        │  a first-boot shell script       │  musl-static binaries on
        │                                  │  every version tag
        ▼                                  │
┌─────────────────────┐                    ▼
│   Holo Node ISO     │       node-manager-x86_64
│                     │       node-manager-aarch64
│  node-setup.sh ─────┼──────────────────────────────►  downloaded at first boot
│  (inlined script)   │
│                     │
│  node-manager       │   After first boot, the binary
│  .service (systemd) │   checks GitHub Releases hourly
│                     │   and replaces itself in-place
└─────────────────────┘   without needing a new ISO.
```

The binary is **not baked into the ISO**. Instead, the ISO contains `node-setup.sh` — a small bash script that runs once on first boot, downloads the appropriate binary from the latest GitHub Release here, and exits. From that point on, the binary self-updates hourly. No new ISO is required to deliver updates to running nodes.

---

## What it does

### First boot

On first boot `node-setup.sh` (part of the ISO) downloads this binary from the latest GitHub Release and installs it to `/usr/local/bin/node-manager`. Once installed, `node-manager.service` starts.

On startup the binary generates a random 12-character password, writes its SHA-256 hash to `/etc/node-manager/auth`, and displays the password and the node's local IP address on the HDMI-connected screen (`/dev/tty1`) in large coloured text. The node operator uses that information to open the setup UI in a browser.

### Onboarding wizard

A four-step browser UI walks the operator through:

1. **Node identity & SSH** — node name (used as hostname slug) and optional SSH public key for the `holo` user
2. **AI agent** — opt-in toggle (default off); if enabled, choose a chat platform and credentials
3. **AI engine & hardware mode** — provider/model selection (if agent enabled), autonomy level, and initial container mode (EdgeNode or Wind Tunnel)
4. **Review & initialize** — summary before committing

After the operator submits, the server configures everything, starts the appropriate container service, sends a welcome message through the chosen chat platform (if agent enabled), and redirects the browser to the management panel. The server **does not shut down** — it stays running permanently.

### Management panel (`/manage`)

After onboarding, `GET /` redirects to `/manage`. The panel (password-protected) lets the operator:

- Add and remove SSH public keys for the `holo` user without physical access
- Enable or disable the OpenClaw AI agent at any time
- Hot-swap the AI provider, model, and API key without re-onboarding
- Switch hardware mode between Standard EdgeNode and Wind Tunnel
- Change the node password
- Trigger an immediate software update check
- View and switch the AI agent autonomy level (Read-Only, Supervised, Full Autonomy)

### Self-update

A background thread wakes every hour, queries the GitHub Releases API for this repository, and compares the latest tag against the compiled-in `VERSION` constant. If a newer version exists it downloads the architecture-matched binary, atomically replaces the running binary on disk, and calls `systemctl restart node-manager.service`. The update check can also be triggered manually from the `/manage` panel.

On every startup, `node-manager` also rewrites the fork config block in `/usr/local/bin/openclaw-update.sh` from its compiled-in constants (see [Switching OpenClaw forks](#switching-openclaw-forks) below). This ensures the hourly OpenClaw update timer is always pointed at the correct fork repo, even after a node-manager update changes the active fork.

---

## Building locally

### Prerequisites

- Rust stable (1.75 or newer)
- For the static musl builds that ship in releases: `musl-tools` (`apt install musl-tools`) and the musl targets added to your toolchain

```bash
# Add musl targets (first time only)
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

### Development build (dynamic, your host OS)

```bash
cargo build
./target/debug/node-manager
# Open http://localhost:8080
```

### Production build (static musl — what goes into GitHub Releases)

```bash
# x86_64
cargo build --release --target x86_64-unknown-linux-musl

# aarch64 (requires aarch64-linux-gnu-gcc cross-compiler)
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl
```

The resulting binaries are fully static — no glibc, no external libraries. They run on any FCOS image regardless of what userland packages are present.

### Testing the UI locally

```bash
cargo run
# Visit http://localhost:8080
# On first run it will print the generated password to stderr since /dev/tty1
# won't exist on a dev machine.
```

To simulate an already-onboarded node (skip to /manage):

```bash
mkdir -p /etc/node-manager
echo "onboarded=true\nnode_name=test\nhw_mode=STANDARD\nagent_enabled=false" \
  > /etc/node-manager/state
cargo run
# GET / will redirect to /manage
```

---

## Repository structure

```
node-manager/
├── src/
│   └── main.rs              ← entire server (single file, std-only)
├── holo-node.md             ← OpenClaw skill file, embedded via include_str!
├── Cargo.toml
├── Cargo.lock
├── .github/
│   └── workflows/
│       └── release.yml      ← builds + publishes binaries on version tag
└── README.md
```

The server is intentionally a single file with no dependencies so it can be audited easily and compiled without a network connection.

---

## Shipping a release

Every release publishes two binary assets:

| Asset name                | Architecture           |
|---------------------------|------------------------|
| `node-manager-x86_64`     | x86-64 (most hardware) |
| `node-manager-aarch64`    | ARM64 (Raspberry Pi, Apple Silicon VMs) |

**These asset names are load-bearing.** Both the self-update code in `find_asset_download_url()` and the first-boot `node-setup.sh` in `holo-node-iso` search for them by exact name. Do not rename them.

### Step-by-step release process

1. Make your changes to `src/main.rs` (and/or `holo-node.md`).

2. Update the version in **two places** — they must match exactly:
   - `const VERSION: &str = "5.1.0";` in `src/main.rs`
   - `version = "5.1.0"` in `Cargo.toml`

3. Commit:
   ```bash
   git add src/main.rs Cargo.toml
   git commit -m "release: v5.1.0 — <one line summary of changes>"
   ```

4. Tag and push:
   ```bash
   git tag v5.1.0
   git push origin main
   git push origin v5.1.0
   ```

5. GitHub Actions (`.github/workflows/release.yml`) picks up the tag, builds both binaries using musl static linking, creates a GitHub Release, and attaches both binary assets automatically. No manual upload needed.

6. Running nodes pick up the update within 60 minutes. Operators can trigger it immediately from the `/manage` panel's "Software Update" section.

### Delivery to nodes

Once a release is published, updates reach nodes in two ways:

- **Running nodes** — the hourly self-update check downloads the new binary and restarts the service automatically, within 60 minutes of the release being published.
- **Freshly provisioned nodes** — `node-setup.sh` always downloads the latest release at first boot, so new nodes get the current version immediately with no ISO rebuild required.

---

## Self-update mechanism

The update logic lives in `check_and_apply_update()` and `spawn_update_checker()`.

**Flow:**

1. Thread sleeps 90 seconds after startup (lets the server stabilise)
2. Queries `https://api.github.com/repos/{UPDATE_REPO}/releases/latest`
3. Parses `tag_name`, strips the leading `v`, compares to `VERSION`
4. If newer: finds the asset named `node-manager-{uname -m}` in the release JSON
5. Downloads to `/usr/local/bin/node-manager-update`
6. `chmod +x`, then `fs::rename` (atomic on Linux)
7. `systemctl restart node-manager.service`
8. Sleeps 1 hour, repeats

The `UPDATE_REPO` environment variable overrides the default (`holo-host/node-manager`). This is used in staging environments.

---

## Switching OpenClaw forks

`node-manager` ships with an abstraction layer for the OpenClaw AI agent binary. The active fork is controlled by two constants in `src/main.rs`:

```rust
const OPENCLAW_FORKS: &[OpenClawFork] = &[
    OpenClawFork {
        id:           "zeroclaw",
        display_name: "ZeroClaw",
        repo:         "zeroclaw-labs/zeroclaw",
        asset_prefix: "zeroclaw",
        binary_name:  "zeroclaw",
    },
    // add future forks here
];

const ACTIVE_OPENCLAW_FORK: &str = "zeroclaw";
```

On every startup, `patch_openclaw_update_script()` rewrites the fork config block at the top of `/usr/local/bin/openclaw-update.sh` from these constants. The hourly `openclaw-update.timer` then pulls from whichever repo is compiled in.

**To switch the entire fleet to a different fork:**

1. Add the new fork entry to `OPENCLAW_FORKS` (if not already present).
2. Change `ACTIVE_OPENCLAW_FORK` to the new fork's `id`.
3. Bump `VERSION` in `src/main.rs` and `Cargo.toml`.
4. Tag and push a release.

All nodes update within 60 minutes. On startup after the update, `patch_openclaw_update_script()` rewrites the update script, and the next `openclaw-update.timer` tick installs the new fork binary to `/usr/local/bin/openclaw`. No ISO rebuild or SSH access to nodes is required.

---

## Routes reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | — | Onboarding wizard (pre-onboard) or redirect to `/manage` |
| `POST` | `/submit` | — | Run onboarding; returns JSON |
| `GET` | `/login` | — | Login page |
| `POST` | `/login` | — | Authenticate; sets session cookie |
| `POST` | `/logout` | session | Clear session cookie |
| `GET` | `/manage` | session | Management panel HTML |
| `GET` | `/manage/status` | session | JSON node state snapshot |
| `POST` | `/manage/ssh/add` | session | Add SSH public key |
| `POST` | `/manage/ssh/remove` | session | Remove SSH key by index |
| `POST` | `/manage/agent` | session | Enable/disable OpenClaw agent |
| `POST` | `/manage/provider` | session | Hot-swap AI provider/model/key |
| `POST` | `/manage/hardware` | session | Switch STANDARD ↔ WIND_TUNNEL |
| `POST` | `/manage/password` | session | Change node password |
| `POST` | `/manage/update` | session | Trigger immediate update check |
| `POST` | `/manage/autonomy` | session | Change agent autonomy level |

Session tokens are stored in-memory and cleared on restart — operators will need to log in again after an update.

---

## File paths on the node

| Path | Contents | Permissions |
|------|----------|-------------|
| `/etc/node-manager/state` | Key-value store of node state (node_name, hw_mode, agent_enabled, channel, provider, model) | 600 |
| `/etc/node-manager/auth` | Password hash: `sha256:<salt>:<hash>` | 600 |
| `/etc/node-manager/provider` | Provider credentials for agent re-enable | 600 |
| `/etc/openclaw/config.toml` | OpenClaw agent configuration (if agent enabled) | 600 |
| `/etc/openclaw/skills/holo-node.md` | Embedded OpenClaw skill | 644 |
| `/usr/local/bin/openclaw` | Active OpenClaw fork binary (fork-agnostic path) | 755 |
| `/usr/local/bin/openclaw-update.sh` | Hourly update script (fork config block managed by node-manager) | 755 |
| `/etc/containers/systemd/edgenode.container` | Podman Quadlet for the EdgeNode container | 644 |
| `/etc/containers/systemd/wind-tunnel.container` | Podman Quadlet for Wind Tunnel | 644 |
| `/home/holo/.ssh/authorized_keys` | SSH public keys for the holo user | 600 |
| `/var/lib/openclaw/workspace/mode_switch.txt` | Current hardware mode (STANDARD or WIND_TUNNEL) | 644 |
| `/var/lib/edgenode/` | EdgeNode persistent data volume | — |

---

## Security model

### Authentication

The server is protected by a single password (the "node password"). On first run a random 12-character password is generated (charset excludes ambiguous characters: `0`, `O`, `1`, `l`, `I`), hashed as `sha256:<8-hex-salt>:<sha256(salt:password)>`, and the hash is stored at `/etc/node-manager/auth` (chmod 600). The cleartext password is never stored — it is only displayed once on the HDMI screen and logged to the systemd journal.

Sessions are 24-hour cookie-based tokens stored in-memory. They are cleared on server restart. All `/manage/*` routes require an active session; unauthenticated requests are redirected to `/login`.

### SSH access

SSH access is provided only for the `holo` system user. Root login is disabled via `/etc/ssh/sshd_config.d/90-holo.conf`. Password authentication is disabled — SSH keys only. SSH is intended as a "break glass" access path, not the primary management interface. The `/manage` panel is the primary interface.

### AI agent command allowlist

The OpenClaw AI agent operates against a strict allowlist. `curl` and `wget` are intentionally excluded to prevent the agent from making arbitrary outbound HTTP requests. The full list:

```
ls, cat, grep, find, head, tail, wc, echo, pwd, date, git,
podman, docker, systemctl, journalctl,
chmod, chown, mkdir, rm, cp, mv, touch,
df, du, ps, free, uname, env, which
```

The agent also cannot write outside `/var/lib/openclaw/workspace` (enforced by `allowed_roots` in the OpenClaw config) and cannot modify system files (enforced by `forbidden_paths`).

### Network exposure

The server binds to `0.0.0.0:8080`. It is intended to be reachable only on the local network — the FCOS firewall configuration in `holo-node-iso` should not expose port 8080 to the internet. The UI has no HTTPS; TLS termination (if desired) should be handled at the network edge.

---

## Adding a new chat channel

1. Add a credentials block to the HTML in `build_onboarding_html()` (copy the pattern from the `cr-telegram` div).
2. Add a case to `build_channel_toml()` that serialises the credentials to TOML.
3. Add a case to `send_welcome_message()` that posts the welcome message via the channel's API.
4. Add the channel to the `extract_channel_config()` parser if the section header differs from the `[channels_config.<n>]` pattern.
5. Test locally; submit a PR.

---

## Contributing

This repository is intentionally kept simple. Before contributing, please read the design constraints:

- **No async runtime.** The server uses `std::thread` for concurrency. Each connection spawns a thread. This is appropriate for a UI that handles at most a handful of simultaneous requests.
- **No third-party crates.** `std` only. This keeps the binary small, the build reproducible, and the audit surface minimal.
- **Single file.** `src/main.rs` contains the entire server. This is a deliberate choice for auditability — an operator should be able to read the entire source in one sitting.

Pull requests that introduce dependencies or split the code across multiple files will not be accepted unless there is a very strong reason.

For bug reports or feature requests, open an issue. For security issues, contact security@holo.host directly.