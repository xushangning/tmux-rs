use core::marker::{PhantomData, PhantomPinned};

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
