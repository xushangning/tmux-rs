use core::{
    ffi::{CStr, c_char, c_int, c_short, c_void},
    mem::{self, MaybeUninit},
    pin::Pin,
    ptr::{self, NonNull},
};
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    process,
};

use bitflags::bitflags;
use libc::uid_t;
use log::debug;
use nix::{errno::Errno, unistd::ForkResult};

use crate::{
    compat::{imsg::IMsg, queue::tailq},
    protocol::Msg,
    tmux_sys::{
        EV_READ, EV_WRITE, PROTOCOL_VERSION, event_add, event_del, event_get_method,
        event_get_version, event_set, imsg, imsg_free, imsg_get, imsgbuf, imsgbuf_queuelen,
        imsgbuf_read, imsgbuf_write, tmuxproc, xcalloc, xstrdup,
    },
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

extern "C" fn event_cb(_fd: c_int, events: c_short, arg: *mut c_void) {
    let peer = unsafe { &mut *(arg as *mut Peer) };

    unsafe {
        if !peer.flags.intersects(PeerFlag::BAD) && (events & EV_READ as i16) != 0 {
            if imsgbuf_read(&mut peer.ibuf) != 1 {
                peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
                return;
            }

            loop {
                let mut imsg = MaybeUninit::<IMsg>::uninit();
                let n = imsg_get(&mut peer.ibuf, imsg.as_mut_ptr());
                if n == -1 {
                    peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
                    return;
                }
                if n == 0 {
                    break;
                }

                let imsg = imsg.assume_init_mut();
                debug!("peer {peer:p} message {}", imsg.hdr.type_);

                if !peer_check_version(peer, imsg) {
                    imsg_free(imsg);
                    break;
                }

                peer.dispatchcb.unwrap()(imsg, peer.arg);
                imsg_free(imsg);
            }
        }

        if events & EV_WRITE as i16 != 0 {
            if imsgbuf_write(&mut peer.ibuf) == -1 {
                peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
                return;
            }
        }

        if peer.flags.intersects(PeerFlag::BAD) && imsgbuf_queuelen(&mut peer.ibuf) == 0 {
            peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
            return;
        }
    }

    update_event(peer);
}

fn peer_check_version(peer: &mut Peer, imsg: &imsg) -> bool {
    let version = imsg.hdr.peerid & 0xff;
    if imsg.hdr.type_ != unsafe { mem::transmute(Msg::Version) } && version != PROTOCOL_VERSION {
        debug!("peer {:p} bad version {}", peer, version);

        send(peer, Msg::Version, None, &[]);
        peer.flags |= PeerFlag::BAD;

        return false;
    }
    true
}

fn update_event(peer: &mut Peer) {
    unsafe {
        event_del(&mut peer.event);

        let mut events = EV_READ as c_short;
        if imsgbuf_queuelen(&mut peer.ibuf) > 0 {
            events |= EV_WRITE as c_short;
        }
        event_set(
            &mut peer.event,
            peer.ibuf.fd,
            events,
            Some(event_cb),
            peer as *mut _ as *mut c_void,
        );

        event_add(&mut peer.event, ptr::null_mut());
    }
}

pub(crate) fn send(peer: &mut Peer, msg_type: Msg, fd: Option<OwnedFd>, buf: &[u8]) -> Option<()> {
    if peer.flags.intersects(PeerFlag::BAD) {
        return None;
    }
    debug!(
        "sending message {msg_type:?} to peer {peer:p} ({} bytes)",
        buf.len()
    );

    crate::compat::imsg::compose(
        &mut peer.ibuf,
        unsafe { mem::transmute(msg_type) },
        crate::protocol::VERSION.try_into().unwrap(),
        None,
        fd,
        buf,
    )
    .ok()?;
    update_event(peer);
    Some(())
}

pub(crate) fn start(name: &str) -> NonNull<Proc> {
    crate::log::open(name);
    let socket_path = Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(crate::tmux_sys::socket_path) }.to_bytes(),
    ));
    crate::compat::setproctitle(&format!("{name} ({})", socket_path.display()));

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
        tailq::Head::new(Pin::new_unchecked(&mut tp.as_mut().peers));
        tp
    }
}

pub(crate) fn fork_and_daemon() -> (ForkResult, UnixStream) {
    let (parent_sock, child_sock) = UnixStream::pair().expect("socketpair failed");
    match unsafe { nix::unistd::fork() }.expect("fork failed") {
        ForkResult::Child => {
            // nix doesn't define daemon for macOS, so we call it ourselves here.
            #[allow(deprecated)]
            Errno::result(unsafe { libc::daemon(1, 0) }).expect("daemon failed");
            (ForkResult::Child, child_sock)
        }
        ForkResult::Parent { child } => (ForkResult::Parent { child }, parent_sock),
    }
}
