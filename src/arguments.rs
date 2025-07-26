use core::{
    ffi::{c_char, c_int, c_uint},
    marker::{PhantomData, PhantomPinned},
};

#[repr(C)]
pub(crate) struct Value {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn args_free_values(values: *mut Value, count: c_uint);
    pub(crate) fn args_from_vector(argc: c_int, argv: *mut *mut c_char) -> *mut Value;
}
