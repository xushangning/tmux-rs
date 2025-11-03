#![feature(layout_for_ptr)]

pub(crate) mod args;
pub mod client;
pub(crate) mod cmd;
pub mod compat;
pub(crate) mod file;
mod libevent;
pub mod log;
pub mod osdep;
mod proc;
mod protocol;
mod server;
pub mod tmux;
pub mod tmux_sys;
pub(crate) mod util;

pub use compat::{getptmfd, pledge};
pub use tmux::get_shell;

use core::ffi::{CStr, c_char};

use bitflags::bitflags;
use bytemuck::{AnyBitPattern, NoUninit};

pub const TMUX_CONF: &str =
    "/etc/tmux.conf:~/.tmux.conf:$XDG_CONFIG_HOME/tmux/tmux.conf:~/.config/tmux/tmux.conf";
pub const TMUX_SOCK_PERM: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum ModeKey {
    Emacs,
    Vi,
}

bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, AnyBitPattern, NoUninit)]
    pub struct ClientFlag: u64 {
        const LOGIN = 1 << 1;
        const NO_START_SERVER = 1 << 12;
        const CONTROL = 1 << 13;
        const CONTROL_CONTROL = 1 << 14;
        const UTF8 = 1 << 16;
        const DEFAULT_SOCKET = 1 << 27;
        const START_SERVER = 1 << 28;
        const NO_FORK = 1 << 30;
        const CONTROL_WAIT_EXIT = 1 << 33;
    }
}

/// Skip until end.
pub fn format_skip_rust(bs: &[u8], end: &[u8]) -> Option<usize> {
    let mut brackets = 0;
    let mut prev_is_hash = false;
    for (i, b) in bs.iter().enumerate() {
        if prev_is_hash {
            prev_is_hash = false;
            if b",#{}:".contains(b) {
                if *b == b'{' {
                    brackets += 1;
                }
                continue;
            }
        }

        if *b == b'}' {
            brackets -= 1;
        }
        prev_is_hash = *b == b'#';

        if end.contains(b) && brackets == 0 {
            return Some(i);
        }
    }

    None
}

#[unsafe(no_mangle)]
pub extern "C" fn format_skip(s: *const c_char, end: *const c_char) -> *const c_char {
    match format_skip_rust(
        unsafe { CStr::from_ptr(s) }.to_bytes(),
        unsafe { CStr::from_ptr(end) }.to_bytes(),
    ) {
        Some(i) => unsafe { s.add(i) },
        None => std::ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn skip_hash_escape() {
        // Make sure a hash only escape its next character so in this case the
        // second hash does not escape the third character.
        assert_eq!(crate::format_skip_rust(b"##,", b","), Some(2));
    }
}
