pub(crate) mod queue;

use core::ffi::{CStr, c_char, c_int};
use std::io::Write;

use log::debug;

/// Log an argument vector.
pub(crate) fn log_argv<'a>(args: impl Iterator<Item = &'a String>, prefix: &str) {
    for (i, arg) in args.enumerate() {
        debug!("{prefix}: argv[{i}]={arg}");
    }
}

/// Pack an argument vector up into a buffer.
pub(crate) fn pack_argv(args: &[String], mut buf: &mut [u8]) -> Option<()> {
    if args.is_empty() {
        return Some(());
    }
    log_argv(args.iter(), "tmux_rs::cmd::pack_argv");

    buf[0] = b'\0';
    for arg in args {
        buf.write_all(arg.as_bytes()).ok()?;
        buf.write_all(b"\0").ok()?;
    }

    Some(())
}

/// Unpack an argument vector from a packed buffer.
pub(crate) fn unpack_argv(mut buf: &[c_char], argc: c_int) -> Option<Vec<String>> {
    if argc == 0 {
        return Some(Vec::new());
    }

    let mut args = Vec::with_capacity(argc.try_into().unwrap());
    for _ in 0..argc {
        if buf.is_empty() {
            return None;
        }

        let arg = unsafe { CStr::from_ptr(buf.as_ptr()) };
        args.push(arg.to_str().unwrap().to_owned());
        buf = &buf[arg.to_bytes_with_nul().len()..];
    }
    log_argv(args.iter(), "tmux_rs::cmd::unpack_argv");

    Some(args)
}
