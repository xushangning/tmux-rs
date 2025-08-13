use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::{self, MaybeUninit},
    ptr::NonNull,
};
use std::os::fd::{IntoRawFd, OwnedFd};

use bytemuck::NoUninit;
use nix::unistd::Pid;

use crate::{
    compat::queue::tailq,
    tmux_sys::{ibuf_fd_set, ibuf_free, imsg_close, imsgbuf},
};

pub const HEADER_SIZE: usize = core::mem::size_of::<Hdr>();

#[repr(C)]
pub struct IBuf {
    entry: MaybeUninit<tailq::Entry<IBuf>>,
    buf: NonNull<c_uchar>,
    size: usize,
    max: usize,
    wpos: usize,
    rpos: usize,
    fd: c_int,
}

impl IBuf {
    const FD_MARK_ON_STACK: c_int = -2;

    pub fn dynamic(len: usize, max: usize) -> nix::Result<NonNull<Self>> {
        if max == 0 || max < len {
            return Err(nix::Error::EINVAL);
        }

        let Some(mut buf) =
            NonNull::new(unsafe { libc::calloc(1, mem::size_of::<Self>()) } as *mut Self)
        else {
            return Err(nix::Error::last());
        };
        let buf_ref = unsafe { buf.as_mut() };
        if len > 0 {
            buf_ref.buf = unsafe {
                NonNull::new(libc::calloc(len, 1) as *mut u8).ok_or_else(|| {
                    libc::free(buf.as_ptr().cast());
                    nix::Error::last()
                })
            }?;
        }
        buf_ref.size = len;
        buf_ref.max = max;
        buf_ref.fd = -1;

        Ok(buf)
    }

    pub fn reserve(&mut self, len: usize) -> nix::Result<NonNull<u8>> {
        if len > usize::MAX - self.wpos {
            return Err(nix::Error::ERANGE);
        }
        if self.fd == Self::FD_MARK_ON_STACK {
            // can not grow stack buffers
            return Err(nix::Error::EINVAL);
        }

        let new_size = self.wpos + len;
        if new_size > self.size {
            // check if buffer is allowed to grow
            if new_size > self.max {
                return Err(nix::Error::ERANGE);
            }
            let Some(nb) = NonNull::new(
                unsafe { libc::realloc(self.buf.as_ptr().cast(), new_size) } as *mut u8,
            ) else {
                return Err(nix::Error::last());
            };
            unsafe {
                // Set newly allocated memory to zero.
                nb.add(self.size).write_bytes(0, new_size - self.size);
            }
            self.buf = nb;
            self.size = new_size;
        }

        let b = unsafe { self.buf.add(self.wpos) };
        self.wpos += len;
        Ok(b)
    }

    pub fn add(&mut self, data: &[u8]) -> nix::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let b = self.reserve(data.len())?;

        unsafe {
            b.as_ptr()
                .copy_from_nonoverlapping(data.as_ptr(), data.len());
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
    let mut wbuf = IBuf::dynamic(data_len, imsg_buf.maxsize as usize)?;
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
