use core::{
    ffi::{CStr, c_char, c_int, c_void},
    mem::MaybeUninit,
    ptr::NonNull,
};
use std::{
    ffi::{CString, OsStr},
    mem,
    os::unix::ffi::OsStrExt,
    path::Path,
    process,
};

use bitflags::bitflags;
use libc::uid_t;
use log::debug;

use crate::{
    compat::queue::tailq,
    tmux_sys::{event_get_method, event_get_version, imsg, imsgbuf, tmuxproc, xcalloc, xstrdup},
};

#[repr(C)]
pub struct Proc {
    name: *const c_char,
    exit: c_int,

    signal_cb: Option<unsafe extern "C" fn(c_int)>,

    ev_sigint: crate::tmux_sys::event,
    ev_sighup: crate::tmux_sys::event,
    ev_sigchld: crate::tmux_sys::event,
    ev_sigcont: crate::tmux_sys::event,
    ev_sigterm: crate::tmux_sys::event,
    ev_sigusr1: crate::tmux_sys::event,
    ev_sigusr2: crate::tmux_sys::event,
    ev_sigwinch: crate::tmux_sys::event,

    peers: MaybeUninit<tailq::Head<Peer, { mem::offset_of!(Peer, entry) }>>,
}

bitflags! {
    #[repr(C)]
    pub struct PeerFlag: c_int {
        const BAD = 1;
    }
}

#[repr(C)]
pub struct Peer {
    parent: *mut Proc,

    ibuf: imsgbuf,
    event: crate::tmux_sys::event,
    uid: uid_t,

    flags: PeerFlag,
    dispatchcb: Option<unsafe extern "C" fn(*mut imsg, *mut c_void)>,
    arg: *mut c_void,

    entry: tailq::Entry<Peer>,
}

pub(crate) fn start(name: &str) -> NonNull<Proc> {
    crate::log::open(name);
    let socket_path = Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(crate::tmux_sys::socket_path) }.to_bytes(),
    ));
    crate::compat::setproctitle(format!("{name} ({})", socket_path.display()).as_ref());

    debug!(
        "{name} started ({}): version {}, socket {}, protocol {}",
        process::id(),
        env!("CARGO_PKG_VERSION"),
        socket_path.display(),
        crate::protocol::VERSION
    );
    let u = nix::sys::utsname::uname().unwrap();
    debug!(
        "on {} {} {}",
        u.sysname().display(),
        u.release().display(),
        u.version().display(),
    );
    unsafe {
        debug!(
            "using libevent {} {}",
            CStr::from_ptr(event_get_version()).to_str().unwrap(),
            CStr::from_ptr(event_get_method()).to_str().unwrap(),
        );
    }
    // TODO:
    // #ifdef HAVE_UTF8PROC
    // log_debug("using utf8proc %s", utf8proc_version());
    // #endif
    // #ifdef NCURSES_VERSION
    // log_debug("using ncurses %s %06u", NCURSES_VERSION, NCURSES_VERSION_PATCH);
    // #endif

    unsafe {
        let mut tp: NonNull<tmuxproc> =
            NonNull::new_unchecked(xcalloc(1, mem::size_of::<tmuxproc>()).cast());
        tp.as_mut().name = xstrdup(CString::new(name).unwrap().as_ptr());
        tailq::Head::new(&mut tp.as_mut().peers);
        tp
    }
}
