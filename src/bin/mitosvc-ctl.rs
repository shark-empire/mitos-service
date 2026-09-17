//! `mitosvc-ctl` - the command-line client for mitos-service's control
//! socket. Connects, sends one line, prints the response, exits.
//! `mitosvc-ctl check <sha256> <capability>`, `mitosvc-ctl grant
//! <sha256> <capability> <allow|deny> <once|session|always>`,
//! `mitosvc-ctl revoke <sha256> <capability>`, `mitosvc-ctl list`,
//! `mitosvc-ctl ping` (default: list).
//!
//! Only the command word itself is case-insensitive (`grant` and
//! `GRANT` both work) - everything after it is forwarded exactly as
//! typed, since a hash or capability name is case-sensitive.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const SOCKET_PATH: &str = "/run/mitos-service/control.sock";

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "list".to_string());
    let rest: Vec<String> = args.collect();
    let line = if rest.is_empty() {
        command.to_uppercase()
    } else {
        format!("{} {}", command.to_uppercase(), rest.join(" "))
    };

    let mut stream = match UnixStream::connect(SOCKET_PATH) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mitosvc-ctl: couldn't connect to {SOCKET_PATH}: {e}");
            eprintln!("(is mitos-service running?)");
            std::process::exit(1);
        }
    };

    if stream.write_all(format!("{line}\n").as_bytes()).is_err() {
        eprintln!("mitosvc-ctl: couldn't send command");
        std::process::exit(1);
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        eprintln!("mitosvc-ctl: couldn't read response");
        std::process::exit(1);
    }
    print!("{response}");
}
