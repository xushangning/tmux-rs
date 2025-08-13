use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::MaybeUninit,
    ptr,
};
use std::os::fd::{IntoRawFd, OwnedFd};

use nix::unistd::Pid;

use crate::{
    compat::queue::tailq,
    tmux_sys::{ibuf_add, ibuf_fd_set, ibuf_free, imsg_close, imsg_create, imsgbuf},
};

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

pub(crate) fn compose(
    imsg_buf: &mut imsgbuf,
    type_: u32,
    id: u32,
    pid: Option<Pid>,
    fd: Option<OwnedFd>,
    data: &[u8],
) -> Option<()> {
    let wbuf = unsafe {
        imsg_create(
            imsg_buf,
            type_,
            id,
            pid.map(|pid| pid.as_raw()).unwrap_or(-1),
            data.len(),
        )
        .as_mut()
    }?;

    unsafe {
        if ibuf_add(
            wbuf,
            if data.is_empty() {
                ptr::null_mut()
            } else {
                data.as_ptr().cast()
            },
            data.len(),
        ) == -1
        {
            ibuf_free(wbuf);
            return None;
        }

        ibuf_fd_set(wbuf, fd.map(|fd| fd.into_raw_fd()).unwrap_or(-1));
        imsg_close(imsg_buf, wbuf);
    }

    Some(())
}
