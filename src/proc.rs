use core::{
    ffi::{CStr, c_char, c_int, c_short, c_void},
    mem::{self, MaybeUninit},
    pin::Pin,
    ptr::{self, NonNull},
};
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    process,
};

use bitflags::bitflags;
use libc::uid_t;
use log::debug;
use mbox::MBox;
use nix::{
    sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
    {errno::Errno, unistd::ForkResult},
};
use pin_project::pin_project;

use crate::{
    compat::{
        imsg::{Buf as IMsgBuf, IMsg},
        queue::tailq,
    },
    libevent::EventFlags,
    protocol::Msg,
    tmux_sys::{
        event_add, event_del, event_get_method, event_get_version, event_set, imsg_get,
        imsgbuf_queuelen, imsgbuf_read, imsgbuf_write, xstrdup,
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

    pub(crate) fn set_signals(mut self: Pin<&mut Proc>, signalcb: unsafe extern "C" fn(c_int)) {
        use crate::libevent::signal_set;

        let self_ptr = unsafe { self.as_mut().get_unchecked_mut() as *mut Proc }.cast::<c_void>();
        let this = self.project();

        *this.signal_cb = Some(signalcb);

        let sa = SigAction::new(SigHandler::SigIgn, SaFlags::SA_RESTART, SigSet::empty());
        unsafe {
            _ = sigaction(Signal::SIGPIPE, &sa);
            _ = sigaction(Signal::SIGTSTP, &sa);
            _ = sigaction(Signal::SIGTTIN, &sa);
            _ = sigaction(Signal::SIGTTOU, &sa);
            _ = sigaction(Signal::SIGQUIT, &sa);

            signal_set(this.ev_sigint, libc::SIGINT, Some(signal_cb), self_ptr);
            event_add(this.ev_sigint, ptr::null_mut());
            signal_set(this.ev_sighup, libc::SIGHUP, Some(signal_cb), self_ptr);
            event_add(this.ev_sighup, ptr::null_mut());
            signal_set(this.ev_sigchld, libc::SIGCHLD, Some(signal_cb), self_ptr);
            event_add(this.ev_sigchld, ptr::null_mut());
            signal_set(this.ev_sigcont, libc::SIGCONT, Some(signal_cb), self_ptr);
            event_add(this.ev_sigcont, ptr::null_mut());
            signal_set(this.ev_sigterm, libc::SIGTERM, Some(signal_cb), self_ptr);
            event_add(this.ev_sigterm, ptr::null_mut());
            signal_set(this.ev_sigusr1, libc::SIGUSR1, Some(signal_cb), self_ptr);
            event_add(this.ev_sigusr1, ptr::null_mut());
            signal_set(this.ev_sigusr2, libc::SIGUSR2, Some(signal_cb), self_ptr);
            event_add(this.ev_sigusr2, ptr::null_mut());
            signal_set(this.ev_sigwinch, libc::SIGWINCH, Some(signal_cb), self_ptr);
            event_add(this.ev_sigwinch, ptr::null_mut());
        }
    }

    pub(crate) fn clear_signals(self: Pin<&mut Self>, defaults: bool) {
        let sa = SigAction::new(SigHandler::SigDfl, SaFlags::SA_RESTART, SigSet::empty());

        unsafe {
            _ = sigaction(Signal::SIGPIPE, &sa);
            _ = sigaction(Signal::SIGTSTP, &sa);

            let this = self.project();
            event_del(this.ev_sigint);
            event_del(this.ev_sighup);
            event_del(this.ev_sigchld);
            event_del(this.ev_sigcont);
            event_del(this.ev_sigterm);
            event_del(this.ev_sigusr1);
            event_del(this.ev_sigusr2);
            event_del(this.ev_sigwinch);

            if defaults {
                _ = sigaction(Signal::SIGINT, &sa);
                _ = sigaction(Signal::SIGQUIT, &sa);
                _ = sigaction(Signal::SIGHUP, &sa);
                _ = sigaction(Signal::SIGCHLD, &sa);
                _ = sigaction(Signal::SIGCONT, &sa);
                _ = sigaction(Signal::SIGTERM, &sa);
                _ = sigaction(Signal::SIGUSR1, &sa);
                _ = sigaction(Signal::SIGUSR2, &sa);
                _ = sigaction(Signal::SIGWINCH, &sa);
            }
        }
    }

    pub(crate) fn add_peer(
        mut self: Pin<&mut Proc>,
        fd: OwnedFd,
        dispatchcb: Option<unsafe extern "C" fn(*mut IMsg, *mut c_void)>,
        arg: *mut c_void,
    ) -> NonNull<Peer> {
        let mut peer = unsafe {
            let mut peer = MBox::from_raw(
                crate::tmux_sys::xcalloc(1, mem::size_of::<Peer>()).cast::<MaybeUninit<Peer>>(),
            );
            Peer::init(
                NonNull::new_unchecked(peer.as_mut_ptr()),
                NonNull::from_mut(self.as_mut().get_unchecked_mut()),
                fd,
                dispatchcb,
                arg,
            );
            MBox::into_pin(peer.assume_init())
        };

        let mut peer_nonnull = NonNull::from_mut(unsafe { peer.as_mut().get_unchecked_mut() });
        debug!(
            "add peer {:?}: {} ({arg:?})",
            peer_nonnull.as_ptr(),
            peer.ibuf.fd.as_raw_fd(),
        );
        unsafe {
            self.project()
                .peers
                .push_back(MBox::into_non_null_raw(Pin::into_inner_unchecked(peer)));
        }

        unsafe {
            peer_nonnull.as_mut().update_event();
        }
        peer_nonnull
    }

    pub(crate) fn toggle_log(&self) {
        unsafe {
            crate::tmux_sys::log_toggle(self.name);
        }
    }
}

bitflags! {
    #[repr(C)]
    pub struct PeerFlags: c_int {
        const BAD = 1;
    }
}

#[repr(C)]
pub struct Peer {
    parent: *mut Proc,

    ibuf: IMsgBuf,
    event: crate::tmux_sys::event,
    uid: uid_t,

    flags: PeerFlags,
    dispatchcb: Option<unsafe extern "C" fn(*mut IMsg, *mut c_void)>,
    arg: *mut c_void,

    entry: MaybeUninit<tailq::Entry<Self>>,
}

impl Peer {
    fn init(
        out: NonNull<Self>,
        parent: NonNull<Proc>,
        fd: OwnedFd,
        dispatchcb: Option<unsafe extern "C" fn(*mut IMsg, *mut c_void)>,
        arg: *mut c_void,
    ) {
        let ptr = out.as_ptr();
        unsafe {
            (&raw mut (*ptr).flags).write(PeerFlags::empty());

            (&raw mut (*ptr).parent).write(parent.as_ptr());

            (&raw mut (*ptr).dispatchcb).write(dispatchcb);
            (&raw mut (*ptr).arg).write(arg);

            let raw_fd = fd.as_raw_fd();
            IMsgBuf::init(NonNull::from_mut(&mut (*ptr).ibuf), fd).expect("imsgbuf_init");
            crate::tmux_sys::imsgbuf_allow_fdpass(&mut (*ptr).ibuf);
            event_set(
                &mut (*ptr).event,
                raw_fd,
                EventFlags::READ.bits(),
                Some(event_cb),
                ptr.cast(),
            );

            let mut gid = MaybeUninit::uninit();
            #[cfg(target_os = "linux")]
            let result = crate::tmux_sys::getpeereid(raw_fd, &mut (*ptr).uid, gid.as_mut_ptr());
            #[cfg(not(target_os = "linux"))]
            let result = libc::getpeereid(raw_fd, &mut (*ptr).uid, gid.as_mut_ptr());
            if result != 0 {
                (&raw mut (*ptr).uid).write(u32::MAX);
            }
        }
    }

    fn update_event(&mut self) {
        unsafe {
            event_del(&mut self.event);

            let mut events = EventFlags::READ;
            if imsgbuf_queuelen(&mut self.ibuf) > 0 {
                events |= EventFlags::WRITE;
            }
            event_set(
                &mut self.event,
                self.ibuf.fd.as_raw_fd(),
                events.bits(),
                Some(event_cb),
                self as *mut _ as *mut c_void,
            );

            event_add(&mut self.event, ptr::null_mut());
        }
    }

    pub(crate) fn send(&mut self, msg_type: Msg, fd: Option<OwnedFd>, buf: &[u8]) -> Option<()> {
        if self.flags.intersects(PeerFlags::BAD) {
            return None;
        }
        debug!(
            "sending message {msg_type:?} to peer {self:p} ({} bytes)",
            buf.len()
        );

        crate::compat::imsg::compose(
            &mut self.ibuf,
            unsafe { mem::transmute(msg_type) },
            crate::protocol::VERSION.try_into().unwrap(),
            None,
            fd,
            buf,
        )
        .ok()?;
        self.update_event();
        Some(())
    }

    pub(crate) fn flush(&mut self) {
        unsafe {
            crate::tmux_sys::imsgbuf_flush(&mut self.ibuf);
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        unsafe {
            event_del(&mut self.event);
            crate::tmux_sys::imsgbuf_clear(&mut self.ibuf);
        }
    }
}

extern "C" fn event_cb(_fd: c_int, events: c_short, arg: *mut c_void) {
    let peer = unsafe { arg.cast::<Peer>().as_mut().unwrap() };
    let events = EventFlags::from_bits_retain(events);

    unsafe {
        if !peer.flags.intersects(PeerFlags::BAD) && events.intersects(EventFlags::READ) {
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

                let mut imsg = imsg.assume_init();
                debug!("peer {peer:p} message {}", imsg.hdr.type_);

                if !peer_check_version(peer, &imsg) {
                    break;
                }

                peer.dispatchcb.unwrap()(&mut imsg, peer.arg);
            }
        }

        if events.intersects(EventFlags::WRITE) {
            if imsgbuf_write(&mut peer.ibuf) == -1 {
                peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
                return;
            }
        }

        if peer.flags.intersects(PeerFlags::BAD) && imsgbuf_queuelen(&mut peer.ibuf) == 0 {
            peer.dispatchcb.unwrap()(ptr::null_mut(), peer.arg);
            return;
        }
    }

    peer.update_event();
}

extern "C" fn signal_cb(signo: c_int, _events: c_short, arg: *mut c_void) {
    let tp = arg.cast::<Proc>();
    unsafe { (*tp).signal_cb.unwrap()(signo) };
}

fn peer_check_version(peer: &mut Peer, imsg: &IMsg) -> bool {
    let version = imsg.hdr.peerid & 0xff;
    if imsg.hdr.type_ != unsafe { mem::transmute(Msg::Version) }
        && version != crate::protocol::VERSION
    {
        debug!("peer {peer:p} bad version {version}");

        peer.send(Msg::Version, None, &[]);
        peer.flags |= PeerFlags::BAD;

        return false;
    }
    true
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

// tp here must not be an immutable reference, because otherwise the compiler would assume that
// there doesn't exist a mutable reference to the same Proc instance and that tp.exit's value
// will never change during the loop, so it may optimize the code by loading tp.exit into a register
// before entering the loop and checking it only once.
pub(crate) fn loop_(tp: *const Proc, loopcb: Option<unsafe extern "C" fn() -> c_int>) {
    use crate::tmux_sys::{EVLOOP_ONCE, event_loop};

    let name = unsafe { CStr::from_ptr((*tp).name).to_str().unwrap() };
    debug!("{name} loop enter");
    loop {
        unsafe {
            event_loop(EVLOOP_ONCE);
            if (*tp).exit != 0 {
                break;
            }
        }
        if let Some(loopcb) = loopcb
            && unsafe { loopcb() } != 0
        {
            break;
        }
    }
    debug!("{name} loop exit");
}

pub(crate) fn exit(tp: Pin<&mut Proc>) {
    for mut peer in &tp.peers {
        unsafe {
            crate::tmux_sys::imsgbuf_flush(&mut peer.as_mut().ibuf);
        }
    }
    *tp.project().exit = 1;
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

pub(crate) fn remove_peer(mut peer: NonNull<Peer>) {
    unsafe { Pin::new_unchecked(peer.as_mut().parent.as_mut().unwrap()) }
        .project()
        .peers
        .remove(peer);
    let peer = MBox::into_pin(unsafe { MBox::from_non_null_raw(peer) });
    debug!("remove peer {:p}", peer.as_ref());
}

pub(crate) fn kill_peer(peer: &mut Peer) {
    peer.flags |= PeerFlags::BAD;
}
