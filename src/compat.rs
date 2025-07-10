use std::ffi::CStr;

// TODO: figure out an easier way to do polyfill on other platforms.
pub fn getprogname() -> &'static str {
    unsafe { CStr::from_ptr(libc::getprogname()) }
        .to_str()
        .unwrap()
}

pub fn getptmfd() -> i32 {
    i32::MAX
}
