use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use russh::keys::ssh_key::Algorithm;
use russh::server::{Auth, Msg, Session};
use portable_pty::PtySize;
use russh::{compression, kex, server, Channel, ChannelId, Preferred};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use crate::creds;
use crate::shell;

/// KEX algorithms offered to clients. ML-KEM is omitted because some OpenSSH
/// + russh combinations fail with `SshEncoding: length invalid` when it is
/// negotiated.
const COMPATIBLE_KEX: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

const COMPATIBLE_HOST_KEYS: &[Algorithm] = &[Algorithm::Ed25519];

const COMPATIBLE_COMPRESSION: &[compression::Name] = &[compression::NONE];

#[derive(Clone)]
pub struct RollingPandaServer;

impl server::Server for RollingPandaServer {
    type Handler = SessionHandler;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Self::Handler {
        info!(?peer, "new SSH client connection");
        SessionHandler::new(peer)
    }

    fn handle_session_error(
        &mut self,
        error: <Self::Handler as server::Handler>::Error,
    ) {
        let hint = session_error_hint(&error);
        error!(
            ?error,
            hint,
            "SSH session failed (often during key exchange or message parsing)"
        );
    }
}

pub struct SessionHandler {
    peer: Option<SocketAddr>,
    state: Arc<Mutex<ChannelState>>,
}

struct ChannelState {
    channel: Option<Channel<Msg>>,
    cols: u16,
    rows: u16,
    term: String,
    resize_tx: Option<mpsc::UnboundedSender<PtySize>>,
}

impl SessionHandler {
    fn new(peer: Option<SocketAddr>) -> Self {
        Self {
            peer,
            state: Arc::new(Mutex::new(ChannelState {
                channel: None,
                cols: 80,
                rows: 24,
                term: "xterm-256color".into(),
                resize_tx: None,
            })),
        }
    }
}

fn pty_size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}

impl server::Handler for SessionHandler {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        if creds::verify(user, password) {
            info!(
                peer = ?self.peer,
                user,
                "password authentication accepted (baked-in creds)"
            );
            Ok(Auth::Accept)
        } else {
            warn!(peer = ?self.peer, user, "password authentication rejected");
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        warn!(
            peer = ?self.peer,
            user,
            "public-key authentication rejected (RollingPanda uses baked-in password only)"
        );
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut state = self.state.lock().await;
        state.channel = Some(channel);
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _terminal_modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut state = self.state.lock().await;
        state.term = term.to_string();
        state.cols = col_width.clamp(1, u16::MAX as u32) as u16;
        state.rows = row_height.clamp(1, u16::MAX as u32) as u16;
        session.channel_success(_channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut state = self.state.lock().await;
        state.cols = col_width.clamp(1, u16::MAX as u32) as u16;
        state.rows = row_height.clamp(1, u16::MAX as u32) as u16;
        if let Some(tx) = &state.resize_tx {
            let _ = tx.send(pty_size(state.cols, state.rows));
        }
        session.channel_success(_channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (channel, cols, rows, resize_rx) = {
            let mut state = self.state.lock().await;
            let channel = state
                .channel
                .take()
                .context("shell requested before session channel was opened")?;
            let (resize_tx, resize_rx) = mpsc::unbounded_channel();
            state.resize_tx = Some(resize_tx);
            (channel, state.cols, state.rows, resize_rx)
        };

        session.channel_success(channel_id)?;
        let peer = self.peer;
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let result = shell::run_interactive_shell(channel, cols, rows, resize_rx).await;
            state.lock().await.resize_tx = None;
            if let Err(error) = result {
                tracing::error!(?peer, ?error, "interactive shell ended with error");
            }
        });
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8(command.to_vec()).context("exec command must be UTF-8")?;
        let (channel, cols, rows) = {
            let mut state = self.state.lock().await;
            let channel = state
                .channel
                .take()
                .context("exec requested before session channel was opened")?;
            (channel, state.cols, state.rows)
        };

        session.channel_success(channel_id)?;
        let peer = self.peer;
        tokio::spawn(async move {
            if let Err(error) = shell::run_exec(channel, cols, rows, &command).await {
                tracing::error!(?peer, ?command, ?error, "exec ended with error");
            }
        });
        Ok(())
    }
}

pub fn server_config(host_keys: Vec<russh::keys::PrivateKey>) -> server::Config {
    let preferred = Preferred {
        kex: Cow::Borrowed(COMPATIBLE_KEX),
        key: Cow::Borrowed(COMPATIBLE_HOST_KEYS),
        compression: Cow::Borrowed(COMPATIBLE_COMPRESSION),
        ..Preferred::DEFAULT
    };

    server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: host_keys,
        preferred,
        ..Default::default()
    }
}

fn session_error_hint(error: &anyhow::Error) -> &'static str {
    let message = format!("{error:#}");
    if message.contains("SshEncoding") && message.contains("length invalid") {
        "protocol decode failed — often caused by mlkem768 KEX or zlib compression mismatch; RollingPanda now disables both server-side"
    } else if message.contains("Kex") || message.contains("kex") {
        "key exchange failed — try: ssh -o KexAlgorithms=curve25519-sha256"
    } else if message.contains("compression") || message.contains("zlib") {
        "compression negotiation failed — try: ssh -o Compression=no"
    } else {
        "see RUST_LOG=russh=debug,rollingpanda=debug for details"
    }
}
