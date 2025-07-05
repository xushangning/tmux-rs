use std::ffi::CStr;

// TODO: figure out an easier way to do polyfill on other platforms.
pub fn getprogname() -> &'static [u8] {
    unsafe { CStr::from_ptr(libc::getprogname()) }.to_bytes()
}
