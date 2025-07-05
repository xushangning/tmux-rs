use std::ffi::{CStr, c_char, c_int};

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
