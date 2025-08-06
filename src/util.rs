use core::ffi::{CStr, c_char};
use std::{
    ffi::{CString, NulError, OsStr},
    os::unix::ffi::OsStrExt,
    path::Path,
};

pub(crate) unsafe fn c_str_to_path<'a>(p: *const c_char) -> &'a Path {
    Path::new(OsStr::from_bytes(unsafe { CStr::from_ptr(p).to_bytes() }))
}

pub(crate) unsafe fn path_to_c_str(p: &Path) -> Result<CString, NulError> {
    CString::new(p.as_os_str().as_bytes())
}
