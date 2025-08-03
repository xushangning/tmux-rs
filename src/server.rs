//! Main server functions.

#![allow(static_mut_refs)]

use core::{
    ffi::{CStr, c_char, c_int, c_short, c_void},
    mem::{self, MaybeUninit},
    ptr,
};
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process,
    time::Instant,
};

use libc::{WNOHANG, WUNTRACED, timeval};
use log::debug;
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, SigmaskHow, Signal, sigprocmask},
        wait::WaitStatus,
    },
    unistd::Pid,
};

use crate::{
    ClientFlag,
    compat::queue::tailq,
    libevent::{evtimer_add, evtimer_set},
    pledge,
    tmux_sys::{
        CLIENT_EXIT, CLIENT_IDENTIFIED, CLIENT_SUSPENDED, EV_READ, PANE_EXITED, PANE_STATUSREADY,
        RB_NEGINF, WAIT_ANY, client_CLIENT_EXIT_SHUTDOWN, cmd_wait_for_flush, cmdq_next, event_add,
        event_base, event_del, event_initialized, event_reinit, event_set, format_tidy_jobs,
        input_key_build, job_check_died, job_kill_all, job_still_running, key_bindings_init,
        log_get_level, options_get_number, options_set_number, proc_clear_signals,
        proc_fork_and_daemon, proc_loop, proc_set_signals, proc_toggle_log, server_acl_init,
        server_acl_join, server_client_create, server_client_loop, server_client_lost,
        server_create_socket, server_destroy_pane, server_update_socket, session_destroy,
        sessions_RB_MINMAX, sessions_RB_NEXT, status_prompt_save_history, tmuxproc, tty_create_log,
        utf8_update_width_cache, window_pane_destroy_ready, xstrdup,
    },
};

static mut FD: Option<OwnedFd> = None;
static mut CLIENT_FLAGS: ClientFlag = ClientFlag::empty();
static mut EXIT: bool = false;
static mut EV_ACCEPT: MaybeUninit<crate::tmux_sys::event> = MaybeUninit::zeroed();
static mut EV_TIDY: MaybeUninit<crate::tmux_sys::event> = MaybeUninit::uninit();

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
    flags: ClientFlag,
    base: *mut event_base,
    lock_file: Option<File>,
) -> OwnedFd {
    let set = SigSet::all();
    let mut oldset = SigSet::empty();
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut oldset)).unwrap();

    let mut fd = MaybeUninit::uninit();
    if !flags.intersects(ClientFlag::NO_FORK)
        && unsafe { proc_fork_and_daemon(fd.as_mut_ptr()) } != 0
    {
        sigprocmask(SigmaskHow::SIG_SETMASK, Some(&oldset), None).unwrap();
        return unsafe { OwnedFd::from_raw_fd(fd.assume_init()) };
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
        tailq::Head::new(&mut crate::tmux_sys::clients);
        crate::tmux_sys::sessions = Default::default();
        key_bindings_init();
        tailq::Head::new(&mut crate::tmux_sys::message_log);
        libc::gettimeofday(&raw mut crate::tmux_sys::start_time, ptr::null_mut());
    }

    let mut cause: *mut c_char = ptr::null_mut();
    let mut c: *mut crate::tmux_sys::client = ptr::null_mut();
    // TODO:
    // #ifdef HAVE_SYSTEMD
    // server_fd = systemd_create_socket(flags, &cause);
    unsafe {
        let server_fd = server_create_socket(flags.bits(), &mut cause);
        if server_fd != -1 {
            FD = Some(OwnedFd::from_raw_fd(server_fd));
            server_update_socket();
        }
        if !flags.intersects(ClientFlag::NO_FORK) {
            c = server_client_create(fd.assume_init());
        } else {
            options_set_number(crate::tmux_sys::global_options, c"exit-empty".as_ptr(), 0);
        }
    }

    if let Some(lock_file) = lock_file {
        mem::drop(lock_file);
    }

    if !cause.is_null() {
        if let Some(c) = unsafe { c.as_mut() } {
            c.exit_message = cause;
            c.flags |= CLIENT_EXIT as u64;
        } else {
            eprintln!("{}", unsafe { CStr::from_ptr(cause).to_str().unwrap() });
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
                if c.as_ref().flags & CLIENT_IDENTIFIED as u64 != 0 {
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

    let mut iter = unsafe { crate::tmux_sys::clients.assume_init_ref().iter() }.peekable();
    while let Some(mut c_ptr) = iter.next() {
        iter.peek();
        let c = unsafe { c_ptr.as_mut() };
        if c.flags & CLIENT_SUSPENDED as u64 != 0 {
            unsafe {
                server_client_lost(c_ptr.as_mut());
            }
        } else {
            c.flags |= CLIENT_EXIT as u64;
            c.exit_type = client_CLIENT_EXIT_SHUTDOWN;
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
            (*c).flags |= CLIENT_EXIT as u64;
        }
    }
}

/// Add accept event. If timeout is nonzero, add as a timeout instead of a read
/// event - used to backoff when running out of file descriptors.
fn add_accept(timeout: c_int) {
    let fd = match unsafe { FD.as_ref() } {
        Some(fd) => fd,
        None => return,
    };

    unsafe {
        if event_initialized(EV_ACCEPT.as_mut_ptr()) != 0 {
            event_del(EV_ACCEPT.as_mut_ptr());
        }

        if timeout == 0 {
            event_set(
                EV_ACCEPT.as_mut_ptr(),
                fd.as_raw_fd(),
                EV_READ.try_into().unwrap(),
                Some(accept),
                ptr::null_mut(),
            );
            event_add(EV_ACCEPT.as_mut_ptr(), ptr::null_mut());
        } else {
            event_set(
                EV_ACCEPT.as_mut_ptr(),
                fd.as_raw_fd(),
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
            let fd = server_create_socket(CLIENT_FLAGS.bits(), ptr::null_mut());
            if fd != -1 {
                FD = Some(OwnedFd::from_raw_fd(fd));
                server_update_socket();
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
        let mut iter = crate::tmux_sys::windows.iter().peekable();
        while let Some(w) = iter.next() {
            iter.peek();
            for mut wp_ptr in w.as_ref().panes.assume_init_ref() {
                let wp = wp_ptr.as_mut();
                if wp.pid == pid.as_raw() {
                    wp.status = status;
                    wp.flags |= PANE_STATUSREADY as i32;

                    debug!("%{} exited", wp.id);
                    wp.flags |= PANE_EXITED as i32;

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
