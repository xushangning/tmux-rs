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
pub(crate) mod window;

pub use compat::{getptmfd, pledge};
pub use tmux::get_shell;

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};

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
    pub struct ClientFlags: u64 {
        const TERMINAL = 1;
        const LOGIN = 1 << 1;
        const EXIT = 1 << 2;
        const REPEAT = 1 << 5;
        const SUSPENDED = 1 << 6;
        const ATTACHED = 1 << 7;
        const DEAD = 1 << 9;
        const READ_ONLY = 1 << 11;
        const NO_START_SERVER = 1 << 12;
        const CONTROL = 1 << 13;
        const CONTROL_CONTROL = 1 << 14;
        const FOCUSED = 1 << 15;
        const UTF8 = 1 << 16;
        const IDENTIFIED = 1 << 18;
        const DOUBLE_CLICK = 1 << 20;
        const TRIPLE_CLICK = 1 << 21;
        const DEFAULT_SOCKET = 1 << 27;
        const START_SERVER = 1 << 28;
        const NO_FORK = 1 << 30;
        const CONTROL_WAIT_EXIT = 1 << 33;

        const _ = !0;
    }
}

#[allow(dead_code)]
#[repr(C)]
enum ClientExitType {
    Return,
    Shutdown,
    Detach,
}

#[repr(C)]
pub struct Client {
    name: *const c_char,
    peer: *mut crate::proc::Peer,
    queue: *mut crate::tmux_sys::cmdq_list,
    windows: crate::tmux_sys::client_windows,
    control_state: *mut crate::tmux_sys::control_state,
    pause_age: c_uint,
    pid: libc::pid_t,
    fd: c_int,
    out_fd: c_int,
    event: crate::tmux_sys::event,
    retval: c_int,
    creation_time: libc::timeval,
    activity_time: libc::timeval,
    last_activity_time: libc::timeval,
    environ: *mut crate::tmux_sys::environ,
    jobs: *mut crate::tmux_sys::format_job_tree,
    title: *mut c_char,
    path: *mut c_char,
    cwd: *const c_char,
    term_name: *mut c_char,
    term_features: c_int,
    term_type: *mut c_char,
    term_caps: *mut *mut c_char,
    term_ncaps: c_uint,
    ttyname: *mut c_char,
    tty: crate::tmux_sys::tty,
    written: usize,
    discarded: usize,
    redraw: usize,
    repeat_timer: crate::tmux_sys::event,
    click_timer: crate::tmux_sys::event,
    click_button: c_uint,
    click_event: crate::tmux_sys::mouse_event,
    status: crate::tmux_sys::status_line,
    theme: crate::tmux_sys::client_theme,
    flags: ClientFlags,
    exit_type: ClientExitType,
    exit_msgtype: crate::protocol::Msg,
    exit_session: *mut c_char,
    exit_message: *mut c_char,
    keytable: *mut crate::tmux_sys::key_table,
    last_key: crate::tmux_sys::key_code,
    redraw_panes: u64,
    redraw_scrollbars: u64,
    message_ignore_keys: c_int,
    message_ignore_styles: c_int,
    message_string: *mut c_char,
    message_timer: crate::tmux_sys::event,
    prompt_string: *mut c_char,
    prompt_formats: *mut crate::tmux_sys::format_tree,
    prompt_buffer: *mut crate::tmux_sys::utf8_data,
    prompt_last: *mut c_char,
    prompt_index: usize,
    prompt_inputcb: crate::tmux_sys::prompt_input_cb,
    prompt_freecb: crate::tmux_sys::prompt_free_cb,
    prompt_data: *mut c_void,
    prompt_hindex: [c_uint; 4],
    prompt_mode: c_uint,
    prompt_saved: *mut crate::tmux_sys::utf8_data,
    prompt_flags: c_int,
    prompt_type: crate::tmux_sys::prompt_type,
    prompt_cursor: c_int,
    session: *mut crate::tmux_sys::session,
    last_session: *mut crate::tmux_sys::session,
    references: c_int,
    pan_window: *mut c_void,
    pan_ox: c_uint,
    pan_oy: c_uint,
    overlay_check: crate::tmux_sys::overlay_check_cb,
    overlay_mode: crate::tmux_sys::overlay_mode_cb,
    overlay_draw: crate::tmux_sys::overlay_draw_cb,
    overlay_key: crate::tmux_sys::overlay_key_cb,
    overlay_free: crate::tmux_sys::overlay_free_cb,
    overlay_resize: crate::tmux_sys::overlay_resize_cb,
    overlay_data: *mut c_void,
    overlay_timer: crate::tmux_sys::event,
    files: crate::tmux_sys::client_files,
    source_file_depth: c_uint,
    clipboard_panes: *mut c_uint,
    clipboard_npanes: c_uint,
    entry: crate::compat::queue::tailq::Entry<Self>,
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
