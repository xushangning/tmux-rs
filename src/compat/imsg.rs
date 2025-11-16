use core::{
    ffi::{c_int, c_uchar, c_void},
    marker::PhantomPinned,
    mem::{self, MaybeUninit, offset_of},
    ptr::{self, NonNull},
};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};

use bytemuck::NoUninit;
use mbox::MBox;
use nix::unistd::Pid;

use crate::compat::queue::tailq;

pub const HEADER_SIZE: usize = core::mem::size_of::<Hdr>();
pub const MAX_IMSG_SIZE: u32 = 16384;

const FD_MARK: u32 = 0x80000000;

#[repr(C)]
pub struct Buf {
    w: NonNull<crate::tmux_sys::msgbuf>,
    pid: libc::pid_t,
    maxsize: u32,
    pub fd: OwnedFd,
    flags: c_int,
    _pin: PhantomPinned,
}

impl Buf {
    pub fn init(out: NonNull<Self>, fd: OwnedFd) -> nix::Result<()> {
        let w = NonNull::new(unsafe {
            crate::tmux_sys::msgbuf_new_reader(HEADER_SIZE, Some(parse_hdr), out.as_ptr().cast())
        })
        .ok_or_else(|| nix::Error::last())?;
        unsafe {
            out.write(Self {
                w,
                pid: libc::getpid(),
                maxsize: MAX_IMSG_SIZE,
                fd,
                flags: 0,
                _pin: PhantomPinned,
            });
        }
        Ok(())
    }
}

#[repr(C)]
pub struct IBuf {
    entry: MaybeUninit<tailq::Entry<Self>>,
    buf: NonNull<c_uchar>,
    size: usize,
    max: usize,
    wpos: usize,
    rpos: usize,
    fd: c_int,
}

impl IBuf {
    const FD_MARK_ON_STACK: c_int = -2;

    pub fn new(size: usize, max: usize) -> nix::Result<Self> {
        let buf = NonNull::new(unsafe { libc::calloc(size, 1) }.cast::<u8>())
            .ok_or_else(|| nix::Error::last())?;

        Ok(Self {
            entry: MaybeUninit::uninit(),
            buf,
            size,
            max,
            wpos: 0,
            rpos: 0,
            fd: -1,
        })
    }

    pub fn dynamic(len: usize, max: usize) -> nix::Result<MBox<Self>> {
        if max == 0 || max < len {
            return Err(nix::Error::EINVAL);
        }

        unsafe {
            let mut buf = MBox::from_non_null_raw(
                NonNull::new(libc::calloc(1, mem::size_of::<Self>()).cast::<MaybeUninit<Self>>())
                    .ok_or_else(|| nix::Error::last())?,
            );
            buf.as_mut_ptr().write(Self::new(len, max)?);

            Ok(buf.assume_init())
        }
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

    pub fn seek(&self, pos: usize, len: usize) -> nix::Result<NonNull<u8>> {
        // only allow seeking between rpos and wpos
        if self.size < pos || usize::MAX - pos < len || self.size < pos + len {
            Err(nix::Error::ERANGE)
        } else {
            Ok(unsafe { self.buf.add(self.rpos + pos) })
        }
    }

    pub fn set(&mut self, pos: usize, data: &[u8]) -> nix::Result<()> {
        let b = self.seek(pos, data.len())?;

        if !data.is_empty() {
            unsafe {
                b.as_ptr()
                    .copy_from_nonoverlapping(data.as_ptr(), data.len());
            }
        }
        Ok(())
    }

    pub fn set_h32(&mut self, pos: usize, value: u64) -> nix::Result<()> {
        let v: u32 = value.try_into().map_err(|_| nix::Error::EINVAL)?;

        self.set(pos, bytemuck::bytes_of(&v))
    }

    pub fn size(&self) -> usize {
        self.wpos - self.rpos
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

impl Drop for IMsg {
    fn drop(&mut self) {
        if !self.buf.is_null() {
            unsafe {
                self.buf.drop_in_place();
            }
        }
    }
}

pub(crate) fn compose(
    imsg_buf: &mut Buf,
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
    imsg_buf: &mut Buf,
    type_: u32,
    id: u32,
    pid: Option<Pid>,
    mut data_len: usize,
) -> nix::Result<MBox<IBuf>> {
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

pub(crate) fn close(imsg_buf: &mut Buf, mut msg: MBox<IBuf>) {
    let mut len = msg.size();
    if msg.fd_avail() {
        len |= FD_MARK as usize;
    }
    msg.set_h32(offset_of!(Hdr, len), len.try_into().unwrap())
        .unwrap();
    unsafe {
        crate::tmux_sys::ibuf_close(imsg_buf.w.as_ptr(), MBox::into_raw(msg));
    }
}

extern "C" fn parse_hdr(buf: *mut IBuf, arg: *mut c_void, fd: *mut RawFd) -> *mut IBuf {
    let mut hdr = MaybeUninit::<Hdr>::uninit();
    if unsafe { crate::tmux_sys::ibuf_get(buf, hdr.as_mut_ptr().cast(), size_of_val(&hdr)) } == -1 {
        return ptr::null_mut();
    }

    let hdr = unsafe { hdr.assume_init_ref() };
    let len = hdr.len & !FD_MARK;

    let imsgbuf = unsafe { arg.cast::<Buf>().as_mut().unwrap() };
    if (len as usize) < HEADER_SIZE || len > imsgbuf.maxsize {
        nix::Error::ERANGE.set();
        return ptr::null_mut();
    }
    let Some(mut b) = NonNull::new(unsafe { crate::tmux_sys::ibuf_open(len as usize) }) else {
        return ptr::null_mut();
    };
    if hdr.len & FD_MARK != 0 {
        unsafe {
            b.as_mut().fd_set(Some(OwnedFd::from_raw_fd(*fd)));
            fd.write(-1);
        }
    }

    b.as_ptr()
}
