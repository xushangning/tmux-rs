use core::ffi::{c_char, c_int};

use libevent_sys::event_base;

use crate::proc::Proc;

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn server_start(
        client: *mut Proc,
        flags: u64,
        base: *mut event_base,
        lockfd: c_int,
        lockfile: *mut c_char,
    ) -> c_int;
}
