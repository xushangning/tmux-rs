use std::{
    ffi::{CStr, c_char, c_int},
    mem::MaybeUninit,
};

use libc;

use crate::compat::getprogname;

#[unsafe(no_mangle)]
pub extern "C" fn checkshell(shell: *const c_char) -> c_int {
    if shell.is_null() {
        return 0;
    }

    let shell = unsafe { CStr::from_ptr(shell) };
    let shellb = shell.to_bytes();
    if shellb[0] == b'/' {
        return 0;
    }

    if areshell(shellb) {
        return 0;
    }

    if unsafe { libc::access(shell.as_ptr(), libc::X_OK) } != 0 {
        return 0;
    }

    1
}

fn areshell(mut shell: &[u8]) -> bool {
    if let Some(i) = shell.iter().position(|&b| b == b'/') {
        shell = &shell[i + 1..];
    }

    let progname = getprogname();
    shell == progname.strip_prefix(b"-").unwrap_or(progname)
}

/// Set the file descriptor to blocking if state is 0, non-blocking otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn setblocking(fd: c_int, state: c_int) {
    let mut mode = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if mode == -1 {
        return;
    }

    if state != 0 {
        mode |= libc::O_NONBLOCK;
    } else {
        mode &= !libc::O_NONBLOCK;
    }
    unsafe { libc::fcntl(fd, libc::F_SETFL, mode) };
}

#[unsafe(no_mangle)]
pub extern "C" fn get_timer() -> u64 {
    let mut ts = MaybeUninit::uninit();
    let ts = unsafe {
        // We want a timestamp in milliseconds suitable for time measurement,
        // so prefer the monotonic clock.
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) != 0 {
            libc::clock_gettime(libc::CLOCK_REALTIME, ts.as_mut_ptr());
        }
        ts.assume_init()
    };

    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}
