use core::ffi::{CStr, c_char, c_int};
use std::{
    env,
    ffi::CString,
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use libc;

use crate::compat::getprogname;

pub fn get_shell() -> Option<PathBuf> {
    let shell = PathBuf::from(env::var("SHELL").ok()?);
    if check_shell_rust(&shell) {
        return Some(shell);
    }

    let pw = unsafe { libc::getpwuid(libc::getuid()).as_ref() }?;
    let shell = Path::new(unsafe { CStr::from_ptr(pw.pw_shell) }.to_str().unwrap());
    if check_shell_rust(&shell) {
        Some(shell.to_path_buf())
    } else {
        // The default value of the default-shell option has been set to
        // _PATH_BSHELL, so no need to return that again.
        None
    }
}

pub fn check_shell_rust(shell: impl AsRef<Path>) -> bool {
    let shell = shell.as_ref();
    if !shell.starts_with("/") {
        return false;
    }

    if are_shell(shell) {
        return false;
    }

    if unsafe {
        libc::access(
            CString::new(shell.as_os_str().as_bytes()).unwrap().as_ptr(),
            libc::X_OK,
        )
    } != 0
    {
        return false;
    }

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn checkshell(shell: *const c_char) -> c_int {
    let shell = unsafe { CStr::from_ptr(shell) }.to_str().unwrap();
    if check_shell_rust(shell) { 1 } else { 0 }
}

fn are_shell(shell: &Path) -> bool {
    let ptr = shell.file_name().unwrap_or_default();
    let progname = getprogname();
    ptr.to_str().unwrap() == progname.strip_prefix('-').unwrap_or(progname)
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
