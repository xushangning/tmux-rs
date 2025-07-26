use std::env;

use libevent_sys::event_base;

// TODO: support other OSes
#[cfg(target_os = "macos")]
pub fn event_init() -> *mut event_base {
    unsafe {
        // On OS X, kqueue and poll are both completely broken and don't
        // work on anything except socket file descriptors (yes, really).
        env::set_var("EVENT_NOKQUEUE", "1");
        env::set_var("EVENT_NOPOLL", "1");

        let base = libevent_sys::event_init();
        env::remove_var("EVENT_NOKQUEUE");
        env::remove_var("EVENT_NOPOLL");
        base
    }
}
