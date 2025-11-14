use core::{
    ffi::{CStr, c_char, c_int, c_short, c_void},
    mem::{self, MaybeUninit},
    pin::Pin,
    ptr::{self, NonNull},
};
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{OwnedFd, RawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    process, u32,
};

use bitflags::bitflags;
use libc::uid_t;
use log::debug;
use mbox::MBox;
use nix::{errno::Errno, unistd::ForkResult};
use pin_project::pin_project;

use crate::{
    compat::{
        imsg::{Buf as IMsgBuf, IMsg},
        queue::tailq,
    },
    protocol::Msg,
    tmux_sys::{
        EV_READ, EV_WRITE, PROTOCOL_VERSION, event_add, event_del, event_get_method,
        event_get_version, event_set, imsg, imsg_free, imsg_get, imsgbuf_queuelen, imsgbuf_read,
        imsgbuf_write, xstrdup,
    },
};

#[repr(C)]
#[pin_project]
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

    #[pin]
    peers: tailq::Head<Peer, { mem::offset_of!(Peer, entry) }>,
}

impl Proc {
    fn init(out: NonNull<Self>, name: &str) {
        let out = out.as_ptr();
        unsafe {
            (&raw mut (*out).name).write(xstrdup(CString::new(name).unwrap().as_ptr()));
            tailq::Head::init(NonNull::from_mut(&mut (*out).peers));
        }
    }
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

    ibuf: IMsgBuf,
    event: crate::tmux_sys::event,
    uid: uid_t,

    flags: PeerFlag,
    dispatchcb: Option<unsafe extern "C" fn(*mut imsg, *mut c_void)>,
    arg: *mut c_void,

    entry: MaybeUninit<tailq::Entry<Self>>,
}

impl Peer {
    fn init(
        out: NonNull<Self>,
        parent: NonNull<Proc>,
        fd: RawFd,
        dispatchcb: Option<unsafe extern "C" fn(*mut imsg, *mut c_void)>,
        arg: *mut c_void,
    ) {
        let ptr = out.as_ptr();
        unsafe {
            (&raw mut (*ptr).flags).write(PeerFlag::empty());

            (&raw mut (*ptr).parent).write(parent.as_ptr());

            (&raw mut (*ptr).dispatchcb).write(dispatchcb);
            (&raw mut (*ptr).arg).write(arg);

            IMsgBuf::init(NonNull::from_mut(&mut (*ptr).ibuf), fd).expect("imsgbuf_init");
            crate::tmux_sys::imsgbuf_allow_fdpass(&mut (*ptr).ibuf);
            event_set(
                &mut (*ptr).event,
                fd,
                EV_READ.try_into().unwrap(),
                Some(event_cb),
                ptr.cast(),
            );

            let mut gid = MaybeUninit::uninit();
            if libc::getpeereid(fd, &mut (*ptr).uid, gid.as_mut_ptr()) != 0 {
                (&raw mut (*ptr).uid).write(u32::MAX);
            }
        }
    }
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

pub(crate) fn start(name: &str) -> Pin<MBox<Proc>> {
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
        let mut tp = MBox::from_raw(
            crate::tmux_sys::xcalloc(1, mem::size_of::<Proc>()).cast::<MaybeUninit<Proc>>(),
        );
        Proc::init(NonNull::new_unchecked(tp.as_mut_ptr()), name);
        MBox::into_pin(tp.assume_init())
    }
}

pub(crate) fn add_peer(
    mut tp: Pin<&mut Proc>,
    fd: RawFd,
    dispatchcb: Option<unsafe extern "C" fn(arg1: *mut IMsg, arg2: *mut c_void)>,
    arg: *mut c_void,
) -> NonNull<Peer> {
    let mut peer = unsafe {
        let mut peer = MBox::from_raw(
            crate::tmux_sys::xcalloc(1, mem::size_of::<Peer>()).cast::<MaybeUninit<Peer>>(),
        );
        Peer::init(
            NonNull::new_unchecked(peer.as_mut_ptr()),
            NonNull::from_mut(tp.as_mut().get_unchecked_mut()),
            fd,
            dispatchcb,
            arg,
        );
        MBox::into_pin(peer.assume_init())
    };

    let mut peer_nonnull = NonNull::from_mut(unsafe { peer.as_mut().get_unchecked_mut() });
    debug!("add peer {:?}: {fd} ({arg:?})", peer_nonnull.as_ptr());
    unsafe {
        tp.project()
            .peers
            .push_back(MBox::into_non_null_raw(Pin::into_inner_unchecked(peer)));
    }

    update_event(unsafe { peer_nonnull.as_mut() });
    peer_nonnull
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
