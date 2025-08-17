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
