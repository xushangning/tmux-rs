use std::ptr;

#[repr(C)]
pub(crate) struct RbHead<T> {
    rbh_root: *mut T,
}

impl<T> RbHead<T> {
    pub(crate) const fn new() -> Self {
        Self {
            rbh_root: ptr::null_mut(),
        }
    }
}
