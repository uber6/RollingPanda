//! Filters ConPTY output on Windows before it is sent to the SSH client.
//!
//! ConPTY synchronizes Win32 console modes using CSI sequences such as
//! `ESC [ ? 31 ; 115 h`. Linux terminals and OpenSSH do not expect these on
//! the wire and may print them literally or leave the client TTY corrupt.

#[derive(Debug, Default)]
pub struct ConPtyOutboundFilter {
    state: State,
    csi_buf: Vec<u8>,
    /// Drop the current CSI (ConPTY private / device-control sequences).
    csi_private: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    #[default]
    Ground,
    Escape,
    Csi,
}

impl ConPtyOutboundFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &byte in input {
            self.process_byte(byte, &mut out);
        }
        out
    }

    fn process_byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        match self.state {
            State::Ground => {
                if byte == 0x1b {
                    self.csi_buf.clear();
                    self.csi_buf.push(byte);
                    self.csi_private = false;
                    self.state = State::Escape;
                } else {
                    out.push(byte);
                }
            }
            State::Escape => {
                if byte == b'[' {
                    self.csi_buf.push(byte);
                    self.state = State::Csi;
                } else {
                    out.extend_from_slice(&self.csi_buf);
                    out.push(byte);
                    self.csi_buf.clear();
                    self.state = State::Ground;
                }
            }
            State::Csi => {
                self.csi_buf.push(byte);

                if is_private_csi_intro(byte) || (0x20..=0x2f).contains(&byte) {
                    self.csi_private = true;
                }

                if (0x40..=0x7e).contains(&byte) {
                    if !self.csi_private {
                        out.extend_from_slice(&self.csi_buf);
                    }
                    self.csi_buf.clear();
                    self.csi_private = false;
                    self.state = State::Ground;
                }
            }
        }
    }
}

/// First parameter byte marking a private/device CSI (e.g. `ESC [ ? … h`).
fn is_private_csi_intro(byte: u8) -> bool {
    matches!(byte, b'?' | b'>' | b'!' | b'=' | b'<')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_plain_text() {
        let mut f = ConPtyOutboundFilter::new();
        assert_eq!(f.process(b"hello"), b"hello");
    }

    #[test]
    fn drops_private_mode_csi() {
        let mut f = ConPtyOutboundFilter::new();
        assert_eq!(f.process(b"\x1b[?31;115h"), b"");
        assert_eq!(f.process(b"\x1b[?28;13h"), b"");
        assert_eq!(f.process(b"\x1b[?25h"), b"");
    }

    #[test]
    fn keeps_sgr_and_cursor() {
        let mut f = ConPtyOutboundFilter::new();
        assert_eq!(f.process(b"\x1b[31m"), b"\x1b[31m");
        assert_eq!(f.process(b"\x1b[2J"), b"\x1b[2J");
    }

    #[test]
    fn splits_across_reads() {
        let mut f = ConPtyOutboundFilter::new();
        assert_eq!(f.process(b"\x1b[?31"), b"");
        assert_eq!(f.process(b";115h"), b"");
        assert_eq!(f.process(b"ok"), b"ok");
    }
}
