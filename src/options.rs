use core::{
    ffi::{c_char, c_int, c_longlong},
    marker::{PhantomData, PhantomPinned},
};

use crate::OptionsTableEntry;

#[repr(C)]
pub struct OptionsEntry {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
pub struct Options {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    /// server options
    pub static mut global_options: *mut Options;
    /// session options
    pub static mut global_s_options: *mut Options;
    /// window options
    pub static mut global_w_options: *mut Options;
    pub fn options_create(parent: *mut Options) -> *mut Options;
    pub fn options_free(oo: *mut Options);
    pub fn options_default(oo: *mut Options, oe: *const OptionsTableEntry) -> *mut OptionsEntry;
    pub fn options_set_string(
        oo: *mut Options,
        name: *const c_char,
        append: c_int,
        fmt: *const c_char,
        ...
    ) -> *mut OptionsEntry;
    pub fn options_set_number(
        oo: *mut Options,
        name: *const c_char,
        value: c_longlong,
    ) -> *mut OptionsEntry;
}
