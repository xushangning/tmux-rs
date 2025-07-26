use core::{
    ffi::{c_char, c_int},
    marker::{PhantomData, PhantomPinned},
};

#[repr(C)]
pub struct Environ {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
pub struct EnvironEntry {
    name: *const c_char,
    pub value: *const c_char,
}

#[link(name = "tmux")]
unsafe extern "C" {
    pub static mut global_environ: *mut Environ;
    pub fn environ_create() -> *mut Environ;
    pub fn environ_free(env: *mut Environ);
    pub fn environ_put(env: *mut Environ, var: *const c_char, flags: c_int);
    pub fn environ_set(
        env: *mut Environ,
        name: *const c_char,
        flags: c_int,
        fmt: *const c_char,
        ...
    );
    pub fn environ_find(env: *mut Environ, name: *const c_char) -> *const EnvironEntry;
}
