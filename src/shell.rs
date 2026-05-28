use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use anyhow::Context;
use bytes::Bytes;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use russh::server::Msg;
use russh::{Channel, ChannelMsg};
use tokio::sync::mpsc as async_mpsc;

/// Interactive login shell over a PTY (what `ssh host` expects).
pub async fn run_interactive_shell(
    channel: Channel<Msg>,
    cols: u16,
    rows: u16,
    resize_rx: async_mpsc::UnboundedReceiver<PtySize>,
) -> anyhow::Result<()> {
    bridge_pty(channel, cols, rows, None, resize_rx).await
}

/// Run a single remote command (what `ssh host command` expects).
pub async fn run_exec(
    channel: Channel<Msg>,
    cols: u16,
    rows: u16,
    command: &str,
) -> anyhow::Result<()> {
    let (_resize_tx, resize_rx) = async_mpsc::unbounded_channel();
    bridge_pty(channel, cols, rows, Some(command), resize_rx).await
}

async fn bridge_pty(
    mut channel: Channel<Msg>,
    cols: u16,
    rows: u16,
    command: Option<&str>,
    mut resize_rx: async_mpsc::UnboundedReceiver<PtySize>,
) -> anyhow::Result<()> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("opening PTY")?;

    let cmd = build_command(command)?;
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .context("spawning shell in PTY")?;
    drop(pair.slave);

    let master = pair.master;
    let mut pty_reader = master.try_clone_reader().context("PTY reader")?;
    let pty_writer = master.take_writer().context("PTY writer")?;

    let client_open = Arc::new(AtomicBool::new(true));
    let (pty_tx, mut pty_rx) = async_mpsc::unbounded_channel::<Vec<u8>>();
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>();

    let pty_to_ssh = {
        let client_open = Arc::clone(&client_open);
        thread::spawn(move || {
            #[cfg(windows)]
            use crate::pty_filter::ConPtyOutboundFilter;

            let mut buf = [0u8; 8192];
            #[cfg(windows)]
            let mut filter = ConPtyOutboundFilter::new();
            loop {
                if !client_open.load(Ordering::Relaxed) {
                    break;
                }
                match pty_reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        #[cfg(windows)]
                        let chunk = filter.process(&buf[..n]);
                        #[cfg(not(windows))]
                        let chunk = buf[..n].to_vec();
                        if !chunk.is_empty() && pty_tx.send(chunk).is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };

    let ssh_to_pty = thread::spawn(move || {
        let mut writer = pty_writer;
        while let Ok(chunk) = stdin_rx.recv() {
            let chunk = normalize_client_input(&chunk);
            if writer.write_all(&chunk).is_err() || writer.flush().is_err() {
                break;
            }
        }
    });

    // Wait for the shell process in the async runtime so we can `select!` on it.
    // Without this, the loop blocks in `channel.wait()` until the client sends another
    // keystroke (the "second Enter" after `exit`) even though cmd has already exited.
    let mut child_handle = tokio::task::spawn_blocking(move || child.wait());

    let mut exit_code = 0u32;
    let mut child_exited = false;
    loop {
        tokio::select! {
            biased;
            child_result = &mut child_handle => {
                let status = child_result
                    .map_err(|_| anyhow::anyhow!("PTY child task join failed"))??;
                exit_code = status.exit_code();
                child_exited = true;
                break;
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if stdin_tx.send(data.to_vec()).is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            out = pty_rx.recv() => {
                match out {
                    Some(bytes) => {
                        if channel.data_bytes(Bytes::from(bytes)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            size = resize_rx.recv() => {
                if let Some(size) = size {
                    let _ = master.resize(size);
                }
            }
        }
    }

    if !child_exited {
        if child_handle.is_finished() {
            if let Ok(Ok(status)) = child_handle.await {
                exit_code = status.exit_code();
            }
        } else {
            child_handle.abort();
        }
    }

    client_open.store(false, Ordering::Relaxed);
    drop(stdin_tx);
    let _ = pty_to_ssh.join();
    let _ = ssh_to_pty.join();
    while pty_rx.try_recv().is_ok() {}

    let code = exit_code;
    let _ = channel.exit_status(code).await;
    let _ = channel.eof().await;
    let _ = channel.close().await;
    Ok(())
}

/// Windows ConPTY + OpenSSH: cmd expects CRLF; Linux SSH often sends bare `\r` on Enter.
fn normalize_client_input(chunk: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        let mut out = Vec::with_capacity(chunk.len().saturating_mul(2));
        for (i, &b) in chunk.iter().enumerate() {
            match b {
                b'\n' => {
                    if i == 0 || chunk[i - 1] != b'\r' {
                        out.push(b'\r');
                    }
                    out.push(b'\n');
                }
                b'\r' => {
                    out.push(b'\r');
                    if chunk.get(i + 1) != Some(&b'\n') {
                        out.push(b'\n');
                    }
                }
                _ => out.push(b),
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        chunk.to_vec()
    }
}

fn build_command(command: Option<&str>) -> anyhow::Result<CommandBuilder> {
    match command {
        None => Ok(login_shell()),
        Some(cmd) => Ok(exec_shell(cmd)),
    }
}

fn login_shell() -> CommandBuilder {
    #[cfg(windows)]
    {
        // cmd.exe plays nicer with Linux SSH clients than PowerShell/PSReadLine,
        // which emits ConPTY DEC mode sequences that can corrupt the client TTY.
        let mut builder = CommandBuilder::new("cmd.exe");
        builder.env("TERM", "xterm-256color");
        builder
    }
    #[cfg(not(windows))]
    {
        CommandBuilder::new_default_prog()
    }
}

fn exec_shell(command: &str) -> CommandBuilder {
    #[cfg(windows)]
    {
        let mut builder = CommandBuilder::new("cmd.exe");
        builder.args(["/C", command]);
        builder.env("TERM", "xterm-256color");
        builder
    }
    #[cfg(not(windows))]
    {
        let mut builder = CommandBuilder::new("sh");
        builder.args(["-c", command]);
        builder
    }
}
