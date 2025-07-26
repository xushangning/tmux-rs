use core::ffi::{c_char, c_int, c_uint};

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn tty_term_read_list(
        name: *const c_char,
        fd: c_int,
        caps: *mut *mut *mut c_char,
        ncaps: *mut c_uint,
        cause: *mut *mut c_char,
    ) -> c_int;
    pub(crate) fn tty_term_free_list(caps: *mut *mut c_char, ncaps: c_uint);
}
