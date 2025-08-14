use core::{
    ffi::{c_int, c_uchar, c_void},
    mem::{self, ManuallyDrop, MaybeUninit, offset_of},
    ptr::NonNull,
};
use std::{
    ops::{Deref, DerefMut},
    os::fd::{IntoRawFd, OwnedFd},
};

use bytemuck::NoUninit;
use nix::unistd::Pid;

use crate::{compat::queue::tailq, tmux_sys::imsgbuf};

pub const HEADER_SIZE: usize = core::mem::size_of::<Hdr>();

const FD_MARK: usize = 0x80000000;

#[repr(transparent)]
pub struct OwnedIBuf(NonNull<IBuf>);

impl Drop for OwnedIBuf {
    fn drop(&mut self) {
        unsafe {
            self.0.drop_in_place();
            libc::free(self.0.as_ptr().cast());
        }
    }
}

impl Deref for OwnedIBuf {
    type Target = IBuf;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.as_ref() }
    }
}

impl DerefMut for OwnedIBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.as_mut() }
    }
}

impl OwnedIBuf {
    pub fn into_raw(p: Self) -> NonNull<IBuf> {
        let p = ManuallyDrop::new(p);
        p.0
    }
}

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

    pub fn dynamic(len: usize, max: usize) -> nix::Result<OwnedIBuf> {
        if max == 0 || max < len {
            return Err(nix::Error::EINVAL);
        }

        let Some(buf) =
            NonNull::new(unsafe { libc::calloc(1, mem::size_of::<Self>()) } as *mut Self)
        else {
            return Err(nix::Error::last());
        };
        let mut buf = OwnedIBuf(buf);
        if len > 0 {
            buf.buf = NonNull::new(unsafe { libc::calloc(len, 1) } as *mut u8)
                .ok_or_else(|| nix::Error::last())?;
        }
        buf.size = len;
        buf.max = max;
        buf.fd = -1;

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

    pub fn fd_avail(&self) -> bool {
        self.fd >= 0
    }

    pub fn fd_set(&mut self, fd: Option<OwnedFd>) {
        // if buf lives on the stack abort before causing more harm
        if self.fd == Self::FD_MARK_ON_STACK {
            panic!();
        }
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
        self.fd = match fd {
            Some(fd) => fd.into_raw_fd(),
            None => -1,
        };
    }
}

impl Drop for IBuf {
    fn drop(&mut self) {
        // We don't save and then restore errno because drop() is only called
        // in Rust code, and all errno values have been saved in Result before
        // calling drop() in Rust code.

        // if buf lives on the stack abort before causing more harm
        if self.fd == Self::FD_MARK_ON_STACK {
            panic!();
        }
        unsafe {
            crate::tmux_sys::freezero(self.buf.as_ptr().cast(), self.size);
            if self.fd >= 0 {
                libc::close(self.fd);
            }
        }
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

    wbuf.add(data)?;

    wbuf.fd_set(fd);
    close(imsg_buf, wbuf);

    Ok(())
}

pub(crate) fn create(
    imsg_buf: &mut imsgbuf,
    type_: u32,
    id: u32,
    pid: Option<Pid>,
    mut data_len: usize,
) -> nix::Result<OwnedIBuf> {
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
    wbuf.add(bytemuck::bytes_of(&hdr)).map(|_| wbuf)
}

pub(crate) fn close(imsg_buf: &mut imsgbuf, msg: OwnedIBuf) {
    let mut len = unsafe { crate::tmux_sys::ibuf_size(msg.0.as_ptr()) };
    if msg.fd_avail() {
        len |= FD_MARK;
    }
    unsafe {
        crate::tmux_sys::ibuf_set_h32(
            msg.0.as_ptr(),
            offset_of!(Hdr, len),
            len.try_into().unwrap(),
        );
        crate::tmux_sys::ibuf_close(imsg_buf.w, OwnedIBuf::into_raw(msg).as_ptr());
    }
}
