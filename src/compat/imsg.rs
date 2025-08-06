use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::MaybeUninit,
};

use crate::compat::queue::tailq;

pub const HEADER_SIZE: usize = core::mem::size_of::<Hdr>();

#[repr(C)]
struct IBuf {
    entry: MaybeUninit<tailq::Entry<IBuf>>,
    buf: *mut c_uchar,
    size: usize,
    max: usize,
    wpos: usize,
    rpos: usize,
    fd: c_int,
}

#[repr(C)]
pub struct Hdr {
    pub type_: u32,
    pub len: u32,
    pub peerid: u32,
    pid: u32,
}

#[repr(C)]
pub struct IMsg {
    pub hdr: Hdr,
    pub data: *mut c_void,
    buf: *mut IBuf,
}
