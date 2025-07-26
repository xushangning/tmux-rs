use core::ffi::{c_char, c_int};

use crate::{libevent::EventBase, proc::Proc};

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn server_start(
        client: *mut Proc,
        flags: u64,
        base: *mut EventBase,
        lockfd: c_int,
        lockfile: *mut c_char,
    ) -> c_int;
}
