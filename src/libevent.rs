use core::ffi::{c_int, c_short, c_void};

use libc::timeval;

use crate::tmux_sys::{event, event_add, event_set};

pub(crate) unsafe fn evtimer_set(
    arg1: *mut event,
    arg2: Option<unsafe extern "C" fn(arg1: c_int, arg2: c_short, arg3: *mut c_void)>,
    arg3: *mut c_void,
) {
    unsafe {
        event_set(arg1, -1, 0, arg2, arg3);
    }
}

pub(crate) unsafe fn evtimer_add(ev: *mut event, timeout: *mut timeval) {
    unsafe {
        event_add(ev, timeout);
    }
}

pub(crate) unsafe fn signal_set(
    ev: *mut event,
    x: c_int,
    cb: Option<unsafe extern "C" fn(c_int, c_short, *mut c_void)>,
    arg: *mut c_void,
) {
    use crate::tmux_sys::{EV_PERSIST, EV_SIGNAL};

    unsafe {
        event_set(ev, x, (EV_SIGNAL | EV_PERSIST).try_into().unwrap(), cb, arg);
    }
}
