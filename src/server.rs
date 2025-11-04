//! Main server functions.

#![allow(static_mut_refs)]

pub(crate) mod client;

use core::{
    ffi::{CStr, c_int, c_short, c_void},
    mem::{self, MaybeUninit},
    pin::Pin,
    ptr,
};
use std::{
    ffi::{CString, OsStr},
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    process,
    time::Instant,
};

use anyhow::Context;
use libc::{
    S_IRGRP, S_IROTH, S_IRUSR, S_IRWXG, S_IRWXO, S_IRWXU, S_IXGRP, S_IXOTH, S_IXUSR, WNOHANG,
    WUNTRACED, timeval,
};
use log::debug;
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, SigmaskHow, Signal, sigprocmask},
        wait::WaitStatus,
    },
    unistd::{ForkResult, Pid},
};

use crate::{
    ClientExitType, ClientFlags,
    compat::queue::tailq,
    libevent::{evtimer_add, evtimer_set},
    pledge,
    tmux_sys::{
        EV_READ, RB_NEGINF, WAIT_ANY, cmd_wait_for_flush, cmdq_next, event_add, event_base,
        event_del, event_initialized, event_reinit, event_set, format_tidy_jobs, input_key_build,
        job_check_died, job_kill_all, job_still_running, key_bindings_init, log_get_level,
        options_get_number, options_set_number, proc_clear_signals, proc_loop, proc_set_signals,
        proc_toggle_log, server_acl_init, server_acl_join, server_client_create,
        server_client_loop, server_client_lost, server_destroy_pane, session_destroy,
        sessions_RB_MINMAX, sessions_RB_NEXT, status_prompt_save_history, tmuxproc, tty_create_log,
        utf8_update_width_cache, window_pane_destroy_ready, xstrdup,
    },
    window::PaneFlags,
};

static mut LISTENER: Option<UnixListener> = None;
static mut CLIENT_FLAGS: ClientFlags = ClientFlags::empty();
static mut EXIT: bool = false;
static mut EV_ACCEPT: MaybeUninit<crate::tmux_sys::event> = MaybeUninit::zeroed();
static mut EV_TIDY: MaybeUninit<crate::tmux_sys::event> = MaybeUninit::uninit();

/// Create server socket.
fn create_socket(flags: ClientFlags) -> anyhow::Result<UnixListener> {
    let socket_path = Path::new(OsStr::from_bytes(unsafe {
        CStr::from_ptr(crate::tmux_sys::socket_path).to_bytes()
    }));
    // Ignore the returned error because the path may not exist.
    std::fs::remove_file(socket_path).ok();

    let mask = unsafe {
        libc::umask(
            S_IXUSR
                | S_IRWXO
                | if flags.intersects(ClientFlags::DEFAULT_SOCKET) {
                    S_IXGRP
                } else {
                    S_IRWXG
                },
        )
    };
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("error creating {}", socket_path.display()))?;
    unsafe {
        libc::umask(mask);
    }

    listener.set_nonblocking(true).unwrap();

    Ok(listener)
}

/// Tidy up every hour.
extern "C" fn tidy_event(_fd: c_int, _events: c_short, _data: *mut c_void) {
    let t = Instant::now();

    unsafe {
        format_tidy_jobs();
    }

    // TODO:
    // #ifdef HAVE_MALLOC_TRIM
    //     malloc_trim(0);
    // #endif

    debug!(
        "tmux_rs::server::tidy_event: took {} milliseconds",
        t.elapsed().as_millis()
    );
    let mut tv = timeval {
        tv_sec: 3600,
        tv_usec: 0,
    };
    unsafe {
        evtimer_add(EV_TIDY.as_mut_ptr(), &raw mut tv);
    }
}

/// Fork new server.
pub(crate) fn start(
    client: *mut tmuxproc,
    flags: ClientFlags,
    base: *mut event_base,
    lock_file: Option<File>,
) -> UnixStream {
    let set = SigSet::all();
    let mut oldset = SigSet::empty();
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut oldset)).unwrap();

    let mut fd: Option<UnixStream> = None;
    if !flags.intersects(ClientFlags::NO_FORK) {
        let (fork_result, sock) = crate::proc::fork_and_daemon();
        if matches!(fork_result, ForkResult::Parent { child: _ }) {
            sigprocmask(SigmaskHow::SIG_SETMASK, Some(&oldset), None).unwrap();
            return sock;
        }
        fd = Some(sock);
    }
    unsafe {
        proc_clear_signals(client, 0);
        CLIENT_FLAGS = flags;
    }

    if unsafe { event_reinit(base) } != 0 {
        panic!("event_reinit failed");
    }
    unsafe {
        crate::tmux_sys::server_proc = crate::proc::start("server").as_ptr();
    }

    unsafe {
        proc_set_signals(crate::tmux_sys::server_proc, Some(signal));
    }
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&oldset), None).unwrap();

    unsafe {
        if log_get_level() > 0 {
            tty_create_log();
        }
    }
    pledge(
        Some("stdio rpath wpath cpath fattr unix getpw recvfd proc exec tty ps"),
        None,
    )
    .expect("pledge failed");

    unsafe {
        input_key_build();
        utf8_update_width_cache();
        crate::tmux_sys::windows = Default::default();
        crate::tmux_sys::all_window_panes = Default::default();
        tailq::Head::new(Pin::new_unchecked(&mut crate::tmux_sys::clients));
        crate::tmux_sys::sessions = Default::default();
        key_bindings_init();
        tailq::Head::new(Pin::new_unchecked(&mut crate::tmux_sys::message_log));
        libc::gettimeofday(&raw mut crate::tmux_sys::start_time, ptr::null_mut());
    }

    let mut cause: Option<anyhow::Error> = None;
    let mut c: *mut crate::tmux_sys::client = ptr::null_mut();
    // TODO:
    // #ifdef HAVE_SYSTEMD
    // server_fd = systemd_create_socket(flags, &cause);
    match create_socket(flags) {
        Ok(listener) => unsafe {
            LISTENER = Some(listener);
            update_socket();
        },
        Err(err) => {
            cause = Some(err);
        }
    }
    unsafe {
        if !flags.intersects(ClientFlags::NO_FORK) {
            c = crate::server::client::create(fd.unwrap()).as_ptr();
        } else {
            options_set_number(crate::tmux_sys::global_options, c"exit-empty".as_ptr(), 0);
        }
    }

    if let Some(lock_file) = lock_file {
        mem::drop(lock_file);
    }

    if let Some(err) = cause {
        let cause = format!("{err:#}");
        if let Some(c) = unsafe { c.as_mut() } {
            c.exit_message = unsafe { xstrdup(CString::new(cause).unwrap().as_ptr()) };
            c.flags |= ClientFlags::EXIT;
        } else {
            eprintln!("{cause}");
            process::exit(1);
        }
    }

    unsafe {
        evtimer_set(EV_TIDY.as_mut_ptr(), Some(tidy_event), ptr::null_mut());
        let mut tv = timeval {
            tv_sec: 3600,
            tv_usec: 0,
        };
        evtimer_add(EV_TIDY.as_mut_ptr(), &raw mut tv);

        server_acl_init();

        add_accept(0);
        proc_loop(crate::tmux_sys::server_proc, Some(loop_));

        job_kill_all();
        status_prompt_save_history();
    }

    process::exit(0);
}

/// Server loop callback.
extern "C" fn loop_() -> c_int {
    unsafe {
        crate::tmux_sys::current_time = libc::time(ptr::null_mut());
    }

    loop {
        let items = unsafe {
            let mut items = cmdq_next(ptr::null_mut());
            for mut c in crate::tmux_sys::clients.assume_init_ref() {
                if c.as_ref().flags.intersects(ClientFlags::IDENTIFIED) {
                    items += cmdq_next(c.as_mut());
                }
            }

            items
        };
        if items == 0 {
            break;
        }
    }

    unsafe {
        server_client_loop();

        if options_get_number(crate::tmux_sys::global_options, c"exit-empty".as_ptr()) == 0 && !EXIT
        {
            return 0;
        }

        if options_get_number(crate::tmux_sys::global_options, c"exit-unattached".as_ptr()) == 0
            && !crate::tmux_sys::sessions.is_empty()
        {
            return 0;
        }

        if crate::tmux_sys::clients
            .assume_init_ref()
            .iter()
            .any(|c| !c.as_ref().session.is_null())
        {
            return 0;
        }

        // No attached clients therefore want to exit - flush any waiting
        // clients but don't actually exit until they've gone.
        cmd_wait_for_flush();
        if !crate::tmux_sys::clients.assume_init_ref().is_empty() {
            return 0;
        }

        if job_still_running() != 0 {
            return 0;
        }
    }

    1
}

/// Exit the server by killing all clients and windows.
fn send_exit() {
    unsafe {
        cmd_wait_for_flush();
    }

    for mut c_ptr in unsafe { crate::tmux_sys::clients.assume_init_ref() } {
        let c = unsafe { c_ptr.as_mut() };
        if c.flags.intersects(ClientFlags::SUSPENDED) {
            unsafe {
                server_client_lost(c_ptr.as_mut());
            }
        } else {
            c.flags |= ClientFlags::EXIT;
            c.exit_type = ClientExitType::Shutdown;
        }
        c.session = ptr::null_mut();
    }

    unsafe {
        let mut s = sessions_RB_MINMAX(&raw mut crate::tmux_sys::sessions, RB_NEGINF);
        while !s.is_null() {
            let s1 = sessions_RB_NEXT(s);
            session_destroy(s, 1, c"tmux_rs::server::send_exit".as_ptr());
            s = s1;
        }
    }
}

/// Update socket execute permissions based on whether sessions are attached.
fn update_socket() {
    // tmux sets the execute bit when there is an attached session. See commit
    // d00914ff2b6e6ee6789e6343e74807632efc4018.
    static mut LAST: i32 = -1;

    let mut n = 0;
    for s in unsafe { &crate::tmux_sys::sessions } {
        if unsafe { s.as_ref().attached } != 0 {
            n += 1;
            break;
        }
    }

    if n != unsafe { LAST } {
        unsafe {
            LAST = n;
        }

        let socket_path = unsafe { crate::util::c_str_to_path(crate::tmux_sys::socket_path) };
        let mut perm = fs::metadata(socket_path).unwrap().permissions();
        let mut mode = perm.mode() & (S_IRWXU | S_IRWXG | S_IRWXO) as u32;
        if n != 0 {
            if mode & S_IRUSR as u32 != 0 {
                mode |= S_IXUSR as u32;
            }
            if mode & S_IRGRP as u32 != 0 {
                mode |= S_IXGRP as u32;
            }
            if mode & S_IROTH as u32 != 0 {
                mode |= S_IXOTH as u32;
            }
        } else {
            mode &= !((S_IXUSR | S_IXGRP | S_IXOTH) as u32);
        }
        perm.set_mode(mode);
        fs::set_permissions(socket_path, perm).unwrap();
    }
}

/// Callback for server socket.
extern "C" fn accept(fd: c_int, events: c_short, _data: *mut c_void) {
    use Errno::*;

    add_accept(0);
    if events & EV_READ as i16 == 0 {
        return;
    }

    let new_fd = match nix::sys::socket::accept(fd) {
        Ok(fd) => fd,
        Err(err) => match err {
            EAGAIN | EINTR | ECONNABORTED => return,
            ENFILE | EMFILE => {
                // Delete and don't try again for 1 second.
                add_accept(1);
                return;
            }
            _ => Err(err).expect("accept failed"),
        },
    };

    unsafe {
        if EXIT {
            libc::close(new_fd);
        }
        let c = server_client_create(new_fd);
        if server_acl_join(c) == 0 {
            (*c).exit_message = xstrdup(c"access not allowed".as_ptr());
            (*c).flags |= ClientFlags::EXIT;
        }
    }
}

/// Add accept event. If timeout is nonzero, add as a timeout instead of a read
/// event - used to backoff when running out of file descriptors.
fn add_accept(timeout: c_int) {
    let listener = match unsafe { LISTENER.as_ref() } {
        Some(listener) => listener,
        None => return,
    };

    unsafe {
        if event_initialized(EV_ACCEPT.as_mut_ptr()) != 0 {
            event_del(EV_ACCEPT.as_mut_ptr());
        }

        if timeout == 0 {
            event_set(
                EV_ACCEPT.as_mut_ptr(),
                listener.as_raw_fd(),
                EV_READ.try_into().unwrap(),
                Some(accept),
                ptr::null_mut(),
            );
            event_add(EV_ACCEPT.as_mut_ptr(), ptr::null_mut());
        } else {
            event_set(
                EV_ACCEPT.as_mut_ptr(),
                listener.as_raw_fd(),
                EV_READ.try_into().unwrap(),
                Some(accept),
                ptr::null_mut(),
            );
            event_add(
                EV_ACCEPT.as_mut_ptr(),
                &timeval {
                    tv_sec: timeout as i64,
                    tv_usec: 0,
                },
            );
        }
    }
}

/// Signal handler.
extern "C" fn signal(sig: c_int) {
    use Signal::*;

    let sig = Signal::try_from(sig).unwrap();
    debug!("tmux_rs::server::signal: {sig}");
    match sig {
        SIGINT | SIGTERM => {
            unsafe {
                EXIT = true;
            }
            send_exit();
        }
        SIGCHLD => child_signal(),
        SIGUSR1 => unsafe {
            event_del(EV_ACCEPT.as_mut_ptr());
            if let Ok(listener) = create_socket(CLIENT_FLAGS) {
                LISTENER = Some(listener);
                update_socket();
            }
            add_accept(0);
        },
        SIGUSR2 => unsafe {
            proc_toggle_log(crate::tmux_sys::server_proc);
        },
        _ => {}
    }
}

/// Handle SIGCHLD.
fn child_signal() {
    loop {
        let mut status: c_int = 0;
        let pid = unsafe { libc::waitpid(WAIT_ANY, &raw mut status, WNOHANG | WUNTRACED) };
        if pid == -1 {
            let err = Errno::last();
            match err {
                Errno::ECHILD => return,
                _ => Err(err).expect("waitpid failed"),
            }
        } else if pid == 0 {
            return;
        }
        match WaitStatus::from_raw(Pid::from_raw(pid), status).unwrap() {
            WaitStatus::Stopped(pid, sig) => child_stopped(pid, sig, status),
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                child_exited(pid, status)
            }
            _ => {}
        }
    }
}

/// Handle exited children.
fn child_exited(pid: Pid, status: c_int) {
    unsafe {
        for w in &crate::tmux_sys::windows {
            for mut wp_ptr in w.as_ref().panes.assume_init_ref() {
                let wp = wp_ptr.as_mut();
                if wp.pid == pid.as_raw() {
                    wp.status = status;
                    wp.flags |= PaneFlags::STATUS_READY;

                    debug!("%{} exited", wp.id);
                    wp.flags |= PaneFlags::EXITED;

                    if window_pane_destroy_ready(wp_ptr.as_ptr()) != 0 {
                        server_destroy_pane(wp_ptr.as_ptr(), 1);
                    }
                    break;
                }
            }
        }
        job_check_died(pid.as_raw(), status);
    }
}

/// Handle stopped children.
fn child_stopped(pid: Pid, sig: Signal, status: c_int) {
    if matches!(sig, Signal::SIGTTIN | Signal::SIGTTOU) {
        return;
    }

    unsafe {
        for w in &crate::tmux_sys::windows {
            for wp in w.as_ref().panes.assume_init_ref() {
                if wp.as_ref().pid == pid.as_raw() {
                    if nix::sys::signal::killpg(pid, Signal::SIGCONT).is_err() {
                        nix::sys::signal::killpg(pid, Signal::SIGCONT).unwrap();
                    }
                }
            }
        }
        job_check_died(pid.as_raw(), status);
    }
}
