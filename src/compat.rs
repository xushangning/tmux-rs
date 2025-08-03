pub mod queue;
pub mod tree;

use core::ffi::CStr;

#[cfg(not(target_os = "openbsd"))]
pub fn pledge(_promises: Option<&str>, _execpromises: Option<&str>) -> std::io::Result<()> {
    Ok(())
}

// TODO: figure out an easier way to do polyfill on other platforms.
pub fn getprogname() -> &'static str {
    unsafe { CStr::from_ptr(libc::getprogname()) }
        .to_str()
        .unwrap()
}

pub fn getptmfd() -> i32 {
    i32::MAX
}
