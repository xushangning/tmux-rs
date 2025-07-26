use core::{
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
};

#[repr(C)]
pub(crate) struct IBuf {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
pub(crate) struct IMsgHdr {
    pub(crate) type_: u32,
    pub(crate) len: u32,
    pub(crate) peer_id: u32,
    pid: u32,
}

#[repr(C)]
pub(crate) struct IMsg {
    pub(crate) hdr: IMsgHdr,
    pub(crate) data: *mut c_void,
    pub(crate) buf: *mut IBuf,
}

pub(crate) const IMSG_HEADER_SIZE: usize = core::mem::size_of::<IMsgHdr>();
pub(crate) const MAX_IMSG_SIZE: usize = 16384;
