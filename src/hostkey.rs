use std::path::Path;

use anyhow::Context;
use russh::keys::{Algorithm, PrivateKey};

/// Generate a fresh Ed25519 host key in memory (new fingerprint every process start).
pub fn generate_in_memory() -> anyhow::Result<Vec<PrivateKey>> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generating Ed25519 host key")?;
    tracing::info!(
        fingerprint = %key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256),
        "using ephemeral in-memory SSH host key"
    );
    Ok(vec![key])
}

/// Load a host key from disk (stable fingerprint across restarts).
pub fn load_from_file(path: &Path) -> anyhow::Result<Vec<PrivateKey>> {
    let key = PrivateKey::read_openssh_file(path)
        .with_context(|| format!("reading host key {}", path.display()))?;
    tracing::info!(path = %path.display(), "loaded SSH host key from file");
    Ok(vec![key])
}
