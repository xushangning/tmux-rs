use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::{self, MaybeUninit},
    ptr::{self, NonNull},
};
use std::os::fd::{IntoRawFd, OwnedFd};

use nix::unistd::Pid;

use crate::{
    compat::queue::tailq,
    tmux_sys::{ibuf_add, ibuf_dynamic, ibuf_fd_set, ibuf_free, imsg_close, imsgbuf},
};

pub const HEADER_SIZE: usize = core::mem::size_of::<Hdr>();

#[repr(C)]
pub struct IBuf {
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
) -> nix::Result<()> {
    let wbuf = create(imsg_buf, type_, id, pid, data.len())?;

    unsafe {
        if ibuf_add(
            wbuf.as_ptr(),
            if data.is_empty() {
                ptr::null_mut()
            } else {
                data.as_ptr().cast()
            },
            data.len(),
        ) == -1
        {
            ibuf_free(wbuf.as_ptr());
            return Err(nix::Error::last());
        }

        ibuf_fd_set(wbuf.as_ptr(), fd.map(|fd| fd.into_raw_fd()).unwrap_or(-1));
        imsg_close(imsg_buf, wbuf.as_ptr());
    }

    Ok(())
}

pub(crate) fn create(
    imsg_buf: &mut imsgbuf,
    type_: u32,
    id: u32,
    pid: Option<Pid>,
    mut data_len: usize,
) -> nix::Result<NonNull<IBuf>> {
    data_len += HEADER_SIZE;
    if data_len > imsg_buf.maxsize as usize {
        return Err(nix::Error::ERANGE);
    }

    let hdr = Hdr {
        type_,
        len: 0,
        peerid: id,
        pid: pid
            .map(|pid| match pid.as_raw() {
                0 => imsg_buf.pid,
                pid => pid,
            })
            .unwrap_or(-1) as u32,
    };
    let Some(wbuf) = NonNull::new(unsafe { ibuf_dynamic(data_len, imsg_buf.maxsize as usize) })
    else {
        return Err(nix::Error::last());
    };
    unsafe {
        if ibuf_add(
            wbuf.as_ptr(),
            (&raw const hdr).cast(),
            mem::size_of_val_raw(&raw const hdr),
        ) == -1
        {
            ibuf_free(wbuf.as_ptr());
            return Err(nix::Error::last());
        }
    }

    Ok(wbuf)
}
