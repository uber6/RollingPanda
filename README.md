# RollingPanda

A lightweight **SSH-2 server** in Rust, inspired by [DropBear](https://matt.ucc.asn.au/dropbear/dropbear.html). RollingPanda does **not** use system accounts (`/etc/passwd`, PAM, or Windows users). It authenticates only against a **username and password compiled into the binary**.

Typical uses: embedded devices, appliances, lab jump boxes, or any host where you want a fixed SSH login without provisioning OS users.

## Features

| Capability | Details |
|------------|---------|
| Authentication | Password only (baked in at compile time) |
| Host identity | Ephemeral Ed25519 host key in memory (optional `--host-key` file) |
| Sessions | Interactive shell and remote commands (`ssh host`, `ssh host cmd`) |
| Platforms | Linux, macOS, Windows (PTY via [portable-pty](https://docs.rs/portable-pty)) |
| Default listen | `0.0.0.0` on port **2222** (baked-in; customizable at build time) |

Public-key authentication is **not** supported.

## Requirements

- [Rust](https://rustup.rs/) 1.85+ (edition 2024)
- An SSH client (e.g. OpenSSH) for testing

## Quick start

```bash
git clone <your-repo-url> RollingPanda
cd RollingPanda
cargo build --release
```

Start the server:

```bash
# Linux / macOS
./target/release/rollingpanda

# Windows
.\target\release\rollingpanda.exe
```

Connect from another terminal:

```bash
ssh -p 2222 panda@127.0.0.1
```

Default credentials (change before any real deployment):

| Field    | Default   |
|----------|-----------|
| Username | `panda`   |
| Password | `rolling` |

## Build-time configuration

Username, password, and default listen port are embedded at **build time**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ROLLINGPANDA_USER` | `panda` | SSH username |
| `ROLLINGPANDA_PASSWORD` | `rolling` | SSH password |
| `ROLLINGPANDA_PORT` | `2222` | Default TCP port (1–65535) |

```bash
# Bash / Linux / macOS
export ROLLINGPANDA_USER=admin
export ROLLINGPANDA_PASSWORD='your-secret-here'
export ROLLINGPANDA_PORT=8022
cargo build --release
```

```powershell
# Windows PowerShell
$env:ROLLINGPANDA_USER = "admin"
$env:ROLLINGPANDA_PASSWORD = "your-secret-here"
$env:ROLLINGPANDA_PORT = "8022"
cargo build --release
```

After building with `ROLLINGPANDA_PORT=8022`, running `./target/release/rollingpanda` listens on **8022** unless you pass `-p` to override for that run.

**Security note:** strings can often be recovered from the binary (`strings`, reverse engineering). Treat baked-in passwords like firmware secrets, not as a substitute for vaults, rotation, or network isolation in hostile environments.

## Command-line options

```text
rollingpanda --help

  --bind <ADDR>       Address to bind (default: 0.0.0.0)
  -p, --port <PORT>   TCP port (default: compile-time `ROLLINGPANDA_PORT`, else 2222)
  --host-key <PATH>   Load host key from file (default: generate in memory each start)
```

By default the server generates a **new Ed25519 host key in RAM** on every start. Clients will warn about a changed host key after each restart unless you use `--host-key` with a stable file:

```bash
# one-time: create a key to reuse
ssh-keygen -t ed25519 -f rollingpanda_host_key -N ""
./target/release/rollingpanda --host-key rollingpanda_host_key
```

## Cryptography

With a typical OpenSSH client, RollingPanda negotiates **modern classical** algorithms (not post-quantum hybrid KEX):

| Layer | Algorithm |
|-------|-----------|
| Key exchange | `curve25519-sha256` |
| Host key | `ssh-ed25519` |
| Encryption | `chacha20-poly1305@openssh.com` |
| Compression | `none` |

RollingPanda intentionally **does not offer** `mlkem768x25519-sha256` or zlib compression by default. Some OpenSSH + [russh](https://github.com/Eugeny/russh) combinations failed handshakes or interactive sessions when those were enabled.

### OpenSSH post-quantum warning

You may see:

```text
WARNING: connection is not using a post-quantum key exchange algorithm.
```

That means the session is **encrypted**, but not using OpenSSH’s hybrid PQ KEX. It warns about hypothetical “store now, decrypt later” attacks against recorded traffic. It does **not** mean the connection is plaintext. See [OpenSSH PQ documentation](https://openssh.com/pq.html).

To force classic algorithms from the client (if needed on an old build):

```bash
ssh -p 2222 -o KexAlgorithms=curve25519-sha256 -o Compression=no panda@HOST
```

## Logging

```bash
RUST_LOG=rollingpanda=info ./target/release/rollingpanda
```

Debug server and protocol issues:

```bash
RUST_LOG=russh=debug,rollingpanda=debug ./target/release/rollingpanda
```

## Project layout

```text
RollingPanda/
  src/main.rs       CLI, server startup
  src/creds.rs      Compile-time username, password, and default port
  src/hostkey.rs    In-memory or file-backed Ed25519 host key
  src/handler.rs    SSH auth, channels, algorithm preferences
  src/shell.rs      PTY bridge (shell and exec)
```

## Troubleshooting

### Handshake fails: `SshEncoding: length invalid`

Rebuild the latest code. The server disables ML-KEM KEX and zlib server-side. If problems persist:

```bash
ssh -p 2222 -o KexAlgorithms=curve25519-sha256 -o Compression=no panda@HOST
```

### Session drops on first keystroke

Use a build that bridges the PTY with `channel.wait()` and `data_bytes()` (current `src/shell.rs`). Rebuild and redeploy:

```bash
cargo build --release
```

### Port already in use

Only one process can bind to a port.

```powershell
# Windows
Get-Process rollingpanda -ErrorAction SilentlyContinue | Stop-Process -Force
```

```bash
# Linux
pkill rollingpanda
# or: fuser -k 2222/tcp
```

### Broken keystrokes or garbage on the client after disconnect (Windows server)

**ConPTY** (used for every Windows PTY) emits CSI “private mode” sequences such as `\e[?31;115h` and `\e[?28;13h`. Linux SSH clients do not expect these; they can corrupt your local TTY and leave fragments like `;28;13;1;32;1_` on your shell after `exit`.

RollingPanda **strips CSI sequences that use private intermediates** (`ESC [ ? …`) before sending PTY output to the client, uses **`cmd.exe`**, forwards window resize, and stops relaying PTY data when the client disconnects.

Rebuild and redeploy on the Windows host. If your local terminal still looks wrong after a bad session, run `reset`. If you use SSH multiplexing (`ControlPath`, e.g. `/tmp/panda.ssh`), test once without it in case a background master is sharing a polluted TTY.

### Need to press Enter twice after `exit` (Windows server)

Older builds only checked whether the remote shell had exited **after** handling the next SSH packet, so the session stayed open until you pressed Enter again. Current builds `select!` on process exit and close the channel immediately. Rebuild and redeploy if you still see this.

### Host key changed

Remove the old entry from `~/.ssh/known_hosts`, or for local testing only:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ...
```

## RollingPanda vs DropBear

| | DropBear | RollingPanda |
|---|----------|--------------|
| Implementation | C, very small | Rust + async runtime |
| System users | Yes | No (baked-in creds only) |
| Public-key auth | Yes | No |
| Default port | Often 22 | 2222 |

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). See [LICENSE](LICENSE) and [NOTICE](NOTICE).

You may use, modify, and distribute RollingPanda (including commercially). Keep the copyright and license notices in copies and derivative works—do not remove [NOTICE](NOTICE) or [LICENSE](LICENSE).
