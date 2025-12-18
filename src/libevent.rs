use core::ffi::{c_int, c_short, c_void};

use bitflags::{Flags, bitflags};
use libc::timeval;

use crate::tmux_sys::{event, event_add, event_set};

bitflags! {
    pub struct EventFlags: c_short {
        const TIMEOUT = crate::tmux_sys::EV_TIMEOUT as <Self as Flags>::Bits;
        const READ = crate::tmux_sys::EV_READ as <Self as Flags>::Bits;
        const WRITE = crate::tmux_sys::EV_WRITE as <Self as Flags>::Bits;
        const SIGNAL = crate::tmux_sys::EV_SIGNAL as <Self as Flags>::Bits;
        const PERSIST = crate::tmux_sys::EV_PERSIST as <Self as Flags>::Bits;
    }
}

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
    unsafe {
        event_set(
            ev,
            x,
            (EventFlags::SIGNAL | EventFlags::PERSIST).bits(),
            cb,
            arg,
        );
    }
}
