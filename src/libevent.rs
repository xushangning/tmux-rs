use core::marker::{PhantomData, PhantomPinned};

#[repr(C)]
pub struct EventBase {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
pub(crate) struct EvBuffer {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}
