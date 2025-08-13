use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::MaybeUninit,
    ptr::NonNull,
};
use std::os::fd::{IntoRawFd, OwnedFd};

use bytemuck::NoUninit;
use nix::unistd::Pid;

use crate::{
    compat::queue::tailq,
    tmux_sys::{ibuf_dynamic, ibuf_fd_set, ibuf_free, ibuf_reserve, imsg_close, imsgbuf},
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

impl IBuf {
    pub fn add(&mut self, data: &[u8]) -> nix::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let Some(b) = NonNull::new(unsafe { ibuf_reserve(self, data.len()) }) else {
            return Err(nix::Error::last());
        };

        unsafe {
            data.as_ptr()
                .copy_to_nonoverlapping(b.as_ptr().cast(), data.len());
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, NoUninit)]
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
    let mut wbuf = create(imsg_buf, type_, id, pid, data.len())?;

    unsafe {
        wbuf.as_mut()
            .add(data)
            .inspect_err(|_| ibuf_free(wbuf.as_ptr()))?;

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
    let Some(mut wbuf) = NonNull::new(unsafe { ibuf_dynamic(data_len, imsg_buf.maxsize as usize) })
    else {
        return Err(nix::Error::last());
    };
    unsafe {
        match wbuf.as_mut().add(bytemuck::bytes_of(&hdr)) {
            Ok(_) => Ok(wbuf),
            Err(err) => {
                ibuf_free(wbuf.as_ptr());
                Err(err)
            }
        }
    }
}
