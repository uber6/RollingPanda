//! Credentials and listen port compiled into the binary (not read from the OS).
//!
//! Override at build time:
//!   ROLLINGPANDA_USER=admin ROLLINGPANDA_PASSWORD='s3cret' ROLLINGPANDA_PORT=8022 cargo build --release

use subtle::ConstantTimeEq;

/// Baked-in SSH username.
pub const USERNAME: &str = match option_env!("ROLLINGPANDA_USER") {
    Some(user) => user,
    None => "panda",
};

/// Baked-in SSH password.
pub const PASSWORD: &str = match option_env!("ROLLINGPANDA_PASSWORD") {
    Some(pass) => pass,
    None => "rolling",
};

/// Baked-in TCP listen port (`-p` / `--port` still overrides at runtime).
pub const PORT: u16 = parse_port(match option_env!("ROLLINGPANDA_PORT") {
    Some(port) => port,
    None => "2222",
});

const fn parse_port(s: &str) -> u16 {
    let bytes = s.as_bytes();
    let mut n: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            panic!("ROLLINGPANDA_PORT must contain only digits");
        }
        n = n * 10 + (b - b'0') as u32;
        if n > u16::MAX as u32 {
            panic!("ROLLINGPANDA_PORT must be 1..=65535");
        }
        i += 1;
    }
    if i == 0 || n == 0 {
        panic!("ROLLINGPANDA_PORT must be 1..=65535");
    }
    n as u16
}

/// Returns true when `user` / `password` match the baked-in credentials.
pub fn verify(user: &str, password: &str) -> bool {
    ct_eq_str(user, USERNAME) && ct_eq_str(password, PASSWORD)
}

fn ct_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
