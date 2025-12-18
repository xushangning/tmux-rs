#![allow(static_mut_refs)]

use core::{
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    mem,
    pin::Pin,
};
use std::{
    env,
    ffi::{CString, OsStr, OsString},
    fs::{File, OpenOptions, TryLockError},
    io::{self, ErrorKind, IsTerminal, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::Command,
    ptr, slice,
    sync::Mutex,
};

use libc::{VMIN, VTIME};
use log::debug;
use mbox::MBox;
use nix::{
    errno::Errno,
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, kill, sigaction},
        termios::{
            self, ControlFlags, InputFlags, OutputFlags, SetArg, cfgetispeed, cfgetospeed,
            cfsetispeed, cfsetospeed, tcgetattr, tcsetattr,
        },
        wait::{WaitPidFlag, waitpid},
    },
    unistd::{Pid, dup, getppid},
};
use thiserror::Error;

use crate::{
    ClientFlags,
    compat::imsg::IMsg,
    pledge,
    proc::Proc,
    protocol::{Msg, MsgCommand},
    tmux::{setblocking, shell_argv0},
    tmux_sys::{
        CMD_STARTSERVER, MAX_IMSGSIZE, client_files, cmd_list_any_have, cmd_list_free,
        cmd_parse_from_arguments, cmd_parse_status_CMD_PARSE_SUCCESS, environ_free, evbuffer,
        event_base, file_read_cancel, file_read_open, file_write_close, file_write_left,
        file_write_open, global_environ, global_options, global_s_options, global_w_options,
        imsg_hdr, options_free, tmuxpeer, tty_term_free_list, tty_term_read_list,
    },
};

#[derive(Error, Debug)]
enum Exit {
    #[error("detached (from session {session})")]
    Detached { session: String },
    #[error("detached and SIGHUP (from session {session})")]
    DetachedHup { session: String },
    #[error("lost tty")]
    LostTty,
    #[error("terminated")]
    Terminated,
    #[error("server exited unexpectedly")]
    LostServer,
    #[error("exited")]
    Exited,
    #[error("server exited")]
    ServerExited,
    #[error("{0}")]
    MessageProvided(String),
}

static mut PROC: Option<Pin<MBox<Proc>>> = None;
static mut PEER: *mut tmuxpeer = ptr::null_mut();
static mut SUSPENDED: bool = false;
static EXIT_REASON: Mutex<Option<Exit>> = Mutex::new(None);
static mut EXIT_FLAG: bool = false;
static mut EXIT_VAL: i32 = 0;
static mut EXIT_TYPE: MaybeUninit<Msg> = MaybeUninit::zeroed();
static EXEC_SHELL: Mutex<Option<OsString>> = Mutex::new(None);
static EXEC_CMD: Mutex<Option<OsString>> = Mutex::new(None);
static mut ATTACHED: bool = false;
static mut FILES: client_files = client_files {
    rbh_root: ptr::null_mut(),
};

struct Context {
    flags: ClientFlags,
}

#[derive(Debug)]
enum GetLockError {
    Failed,
    TryAgain,
}

/// Get server create lock. If already held then server start is happening in
/// another client, so block until the lock is released and return -2 to
/// retry. Return -1 on failure to continue and start the server anyway.
fn get_lock(lockfile: &Path) -> Result<File, GetLockError> {
    debug!("lock file is {}", lockfile.display());

    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(lockfile)
        .map_err(|e| {
            debug!("open failed: {e}");
            GetLockError::Failed
        })?;

    match lock.try_lock() {
        Ok(_) => {
            debug!("flock succeeded");
            Ok(lock)
        }
        Err(err) => {
            debug!("flock failed: {err}");
            match err {
                TryLockError::Error(_) => Ok(lock),
                TryLockError::WouldBlock => {
                    while let Err(err) = lock.lock()
                        && err.kind() == ErrorKind::Interrupted
                    {
                        // nothing
                    }
                    Err(GetLockError::TryAgain)
                }
            }
        }
    }
}

/// Connect client to server.
fn connect(base: *mut event_base, path: &Path, flags: ClientFlags) -> io::Result<UnixStream> {
    debug!("socket is {}", path.display());

    let mut lock: Option<File> = None;
    let mut locked = false;
    let lockfile = path.with_added_extension("lock");
    loop {
        debug!("trying connect");
        match UnixStream::connect(path) {
            Ok(stream) => break Ok(stream),
            Err(err) => {
                debug!("connect failed: {err}");
                if err.kind() != ErrorKind::ConnectionRefused && err.kind() != ErrorKind::NotFound
                    || flags.intersects(ClientFlags::NO_START_SERVER)
                    || !flags.intersects(ClientFlags::START_SERVER)
                {
                    break Err(err);
                }
            }
        }

        if !locked {
            let result = get_lock(&lockfile);
            if let Err(err) = result.as_ref() {
                debug!("didn't get lock {err:?}");
                if matches!(err, GetLockError::TryAgain) {
                    continue;
                }
            }
            debug!("got lock {result:?}");
            lock = result.ok();

            // Always retry at least once, even if we got the lock,
            // because another client could have taken the lock,
            // started the server and released the lock between our
            // connect() and flock().
            locked = true;
            continue;
        }

        // Unlike the original tmux source code, we don't unlink the lockfile because unlinking
        // may cause race conditions (https://www.dingmos.com/index.php/archives/142/),
        // and even if the current tmux behavior is likely correct, I'm too lazy to call unlink.
        // TODO: find a better way to do cross process synchronization.
        // if (lockfd >= 0 && unlink(path) != 0 && errno != ENOENT) {
        // 	free(lockfile);
        // 	close(lockfd);
        // 	return (-1);
        // }
        let stream = crate::server::start(
            unsafe { PROC.as_mut().unwrap().as_mut() },
            flags,
            base,
            lock,
        );
        stream.set_nonblocking(true).unwrap();
        break Ok(stream);
    }
}

fn exit() {
    unsafe {
        if file_write_left(&raw mut FILES) == 0 {
            crate::proc::exit(PROC.as_mut().unwrap().as_mut());
        }
    }
}

pub fn main(base: *mut event_base, args: &Vec<String>, mut flags: ClientFlags, feat: c_int) -> i32 {
    // Set up the initial command.
    let msg: Msg;
    if unsafe { !crate::tmux_sys::shell_command.is_null() } {
        msg = Msg::Shell;
        flags |= ClientFlags::START_SERVER;
    } else if args.is_empty() {
        msg = Msg::Command;
        flags |= ClientFlags::START_SERVER;
    } else {
        msg = Msg::Command;

        // It's annoying parsing the command string twice (in client
        // and later in server) but it is necessary to get the start
        // server flag.
        let mut values = crate::args::from_vector(args.iter());
        unsafe {
            let pr = cmd_parse_from_arguments(
                values.as_mut_ptr(),
                args.len().try_into().unwrap(),
                ptr::null_mut(),
            )
            .as_ref()
            .unwrap();
            match pr.status {
                #[allow(non_upper_case_globals)]
                cmd_parse_status_CMD_PARSE_SUCCESS => {
                    if cmd_list_any_have(pr.cmdlist, CMD_STARTSERVER) != 0 {
                        flags |= ClientFlags::START_SERVER;
                    }
                    cmd_list_free(pr.cmdlist);
                }
                _ => libc::free(pr.error.cast()),
            };
        }
    }

    unsafe {
        // Create client process structure (starts logging).
        PROC = Some(crate::proc::start("client"));
        PROC.as_mut().unwrap().as_mut().set_signals(signal);
    }

    let ctx = Box::new(Context { flags });

    // Save the flags.
    debug!("flags are {:#x}", flags.bits());

    // Initialize the client socket and start the server.
    // TODO: #ifdef HAVE_SYSTEMD
    let socket_path =
        OsStr::from_bytes(unsafe { CStr::from_ptr(crate::tmux_sys::socket_path) }.to_bytes());
    let fd = match connect(base, socket_path.as_ref(), ctx.flags) {
        Ok(stream) => stream,
        Err(err) => {
            match err.kind() {
                ErrorKind::ConnectionRefused => {
                    eprintln!("no server running on {}", socket_path.display())
                }

                _ => eprintln!("error connecting to {} ({err})", socket_path.display()),
            };
            return 1;
        }
    };

    let ctx_ptr = Box::into_raw(ctx);
    let ctx = unsafe { ctx_ptr.as_mut().unwrap() };
    unsafe {
        PEER = PROC
            .as_mut()
            .unwrap()
            .as_mut()
            .add_peer(fd.into(), Some(dispatch), ctx_ptr.cast())
            .as_ptr()
    };

    // Save these before pledge().
    let cwd = env::current_dir()
        .ok()
        .or_else(env::home_dir)
        .unwrap_or_else(|| PathBuf::from("/"));
    let ttynam = nix::unistd::ttyname(io::stdin()).unwrap_or_default();
    let termnam = env::var_os("TERM").unwrap_or_default();

    // Drop privileges for client. "proc exec" is needed for -c and for
    // locking (which uses system(3)).
    //
    // "tty" is needed to restore termios(4) and also for some reason -CC
    // does not work properly without it (input is not recognised).
    //
    // "sendfd" is dropped later in client_dispatch_wait().
    pledge(
        Some("stdio rpath wpath cpath unix sendfd proc exec tty"),
        None,
    )
    .expect("pledge failed");

    // Load terminfo entry if any.
    let mut caps = ptr::null_mut();
    let mut ncaps: c_uint = 0;
    let mut cause = ptr::null_mut();
    if io::stdin().is_terminal()
        && !termnam.is_empty()
        && unsafe {
            tty_term_read_list(
                CString::new(termnam.as_bytes()).unwrap().as_ptr(),
                io::stdin().as_raw_fd(),
                &mut caps,
                &mut ncaps,
                &mut cause,
            )
        } != 0
    {
        eprintln!("{}", unsafe { CStr::from_ptr(cause) }.to_str().unwrap());
        unsafe {
            libc::free(cause.cast());
        }
        return 1;
    }

    // Free stuff that is not used in the client.
    unsafe {
        if crate::tmux_sys::ptm_fd != -1 {
            libc::close(crate::tmux_sys::ptm_fd);
        }
        options_free(global_options);
        options_free(global_s_options);
        options_free(global_w_options);
        environ_free(global_environ);
    }

    // Set up control mode.
    let mut saved_tio = None;
    if ctx.flags.intersects(ClientFlags::CONTROL_CONTROL) {
        saved_tio = match tcgetattr(io::stdin()) {
            Ok(tio) => Some(tio),
            Err(err) => {
                eprintln!("tcgetattr failed: {err}");
                return 1;
            }
        };
        let saved_tio = saved_tio.as_ref().unwrap();
        let mut tio = saved_tio.clone();
        termios::cfmakeraw(&mut tio);
        tio.input_flags = InputFlags::ICRNL | InputFlags::IXANY;
        tio.output_flags = OutputFlags::OPOST | OutputFlags::ONLCR;
        // TODO:
        // #ifdef NOKERNINFO
        // tio.c_lflag = NOKERNINFO;
        // #endif
        tio.control_flags = ControlFlags::CREAD | ControlFlags::CS8 | ControlFlags::HUPCL;
        tio.control_chars[VMIN] = 1;
        tio.control_chars[VTIME] = 0;
        cfsetispeed(&mut tio, cfgetispeed(saved_tio)).ok();
        cfsetospeed(&mut tio, cfgetospeed(saved_tio)).ok();
        tcsetattr(io::stdin(), SetArg::TCSANOW, &tio).ok();
    }

    // Send identify messages.
    send_identify(
        &ctx,
        ttynam.as_os_str().as_bytes(),
        termnam.as_bytes(),
        caps,
        ncaps,
        cwd.as_os_str().as_bytes(),
        feat,
    );
    unsafe {
        tty_term_free_list(caps, ncaps);
        PEER.as_mut().unwrap().flush();
    }

    // Send first command.
    match msg {
        Msg::Command => {
            let data: MsgCommand = MsgCommand {
                argc: args.len().try_into().unwrap(),
            };
            // How big is the command?
            let size: usize = args.iter().map(|arg| arg.len() + 1).sum();
            let total_size = size + mem::size_of_val(&data);
            if total_size > MAX_IMSGSIZE as usize {
                eprintln!("command too long");
                return 1;
            }

            let mut data_buffer = Vec::<u8>::with_capacity(total_size);
            data_buffer.extend_from_slice(bytemuck::bytes_of(&data));
            data_buffer.resize(total_size, 0);

            // Prepare command for server.
            if crate::cmd::pack_argv(args, &mut data_buffer[mem::size_of_val(&data)..]).is_none() {
                eprintln!("command too long");
                return 1;
            }

            // Send the command.
            if unsafe { &mut *PEER }
                .send(msg, None, &data_buffer)
                .is_none()
            {
                eprintln!("failed to send command");
                return 1;
            }
        }

        Msg::Shell => {
            unsafe { &mut *PEER }.send(msg, None, &[]);
        }

        _ => {}
    }

    // Start main loop.
    crate::proc::loop_(unsafe { PROC.as_ref().unwrap().as_ref().get_ref() }, None);

    // Run command if user requested exec, instead of exiting.
    if matches!(unsafe { EXIT_TYPE.assume_init_ref() }, Msg::Exec) {
        if ctx.flags.intersects(ClientFlags::CONTROL_CONTROL) {
            tcsetattr(io::stdout(), SetArg::TCSAFLUSH, saved_tio.as_ref().unwrap()).ok();
        }
        exec(
            ctx,
            EXEC_SHELL.lock().unwrap().as_ref().unwrap().as_ref(),
            &EXEC_CMD.lock().unwrap().as_ref().unwrap(),
        );
    }

    // Restore streams to blocking.
    setblocking(io::stdin().as_raw_fd(), 1);
    setblocking(io::stdout().as_raw_fd(), 1);
    setblocking(io::stderr().as_raw_fd(), 1);

    if unsafe { ATTACHED } {
        if let Some(reason) = EXIT_REASON.lock().unwrap().as_ref() {
            println!("[{}]", reason);
        }

        let ppid = getppid();
        if matches!(unsafe { EXIT_TYPE.assume_init_ref() }, Msg::DetachKill) && ppid.as_raw() > 1 {
            kill(ppid, Signal::SIGHUP).ok();
        }
    } else if ctx.flags.intersects(ClientFlags::CONTROL) {
        match EXIT_REASON.lock().unwrap().as_ref() {
            None => println!("%exit"),
            Some(reason) => println!("%exit {reason}"),
        }
        io::stdout().flush().ok();
        if ctx.flags.intersects(ClientFlags::CONTROL_WAIT_EXIT) {
            // TODO: i thought the stdin is already line buffered. why is setvbuf required?
            // setvbuf(stdin, NULL, _IOLBF, 0);
            io::stdin().lines().for_each(|_line| {});
        }
        if ctx.flags.intersects(ClientFlags::CONTROL_CONTROL) {
            print!("\x1b\\");
            io::stdout().flush().ok();
            tcsetattr(io::stdout(), SetArg::TCSAFLUSH, saved_tio.as_ref().unwrap()).ok();
        }
    } else if let Some(reason) = EXIT_REASON.lock().unwrap().as_ref() {
        eprintln!("{reason}");
    }

    unsafe { EXIT_VAL }
}

/// Send identify messages to server.
fn send_identify(
    ctx: &Context,
    ttynam: &[u8],
    termname: &[u8],
    mut caps: *mut *mut c_char,
    ncaps: c_uint,
    cwd: &[u8],
    feat: c_int,
) {
    unsafe {
        (*PEER).send(Msg::IdentifyLongFlags, None, bytemuck::bytes_of(&ctx.flags));
        // for compatibility, we send the flags again.
        (*PEER).send(Msg::IdentifyLongFlags, None, bytemuck::bytes_of(&ctx.flags));

        (*PEER).send(
            Msg::IdentifyTerm,
            None,
            CString::new(termname).unwrap().as_bytes_with_nul(),
        );
        (*PEER).send(Msg::IdentifyFeatures, None, bytemuck::bytes_of(&feat));

        (*PEER).send(
            Msg::IdentifyTtyName,
            None,
            CString::new(ttynam).unwrap().as_bytes_with_nul(),
        );
        (*PEER).send(
            Msg::IdentifyCwd,
            None,
            CString::new(cwd).unwrap().as_bytes_with_nul(),
        );

        for _ in 0..ncaps {
            let p = caps.as_ref().unwrap().cast_const();
            (*PEER).send(
                Msg::IdentifyTermInfo,
                None,
                CStr::from_ptr(p).to_bytes_with_nul(),
            );
            caps = caps.add(1);
        }

        (*PEER).send(
            Msg::IdentifyStdin,
            Some(dup(io::stdin()).expect("dup failed")),
            &[],
        );
        (*PEER).send(
            Msg::IdentifyStdout,
            Some(dup(io::stdout()).expect("dup failed")),
            &[],
        );

        let pid = Pid::this().as_raw();
        (*PEER).send(Msg::IdentifyClientPid, None, bytemuck::bytes_of(&pid));

        let mut ss = crate::tmux_sys::environ;
        loop {
            let s = *ss.as_ref().unwrap();
            if s.is_null() {
                break;
            }
            let s = CStr::from_ptr(s).to_bytes_with_nul();
            let sslen = s.len();
            if sslen > MAX_IMSGSIZE as usize - mem::size_of::<imsg_hdr>() {
                continue;
            }
            (*PEER).send(Msg::IdentifyEnviron, None, s);
            ss = ss.add(1);
        }

        (*PEER).send(Msg::IdentifyDone, None, &[]);
    }
}

/// Run command in shell; used for -c.
fn exec(ctx: &Context, shell: &Path, shell_cmd: &OsStr) -> ! {
    debug!("shell {}, command {}", shell.display(), shell_cmd.display());

    unsafe {
        PROC.as_mut().unwrap().as_mut().clear_signals(true);
    }

    setblocking(io::stdin().as_raw_fd(), 1);
    setblocking(io::stdout().as_raw_fd(), 1);
    setblocking(io::stderr().as_raw_fd(), 1);
    // after rewriting in rust, we expect all fd to be opened with O_CLOEXEC,
    // as stated in the documentation of CommandExt::exec, so this may not be necessary.
    // closefrom(STDERR_FILENO + 1);

    Err::<(), _>(
        Command::new(shell)
            .env("SHELL", shell)
            .arg0(shell_argv0(shell, ctx.flags.intersects(ClientFlags::LOGIN)))
            .arg("-c")
            .arg(shell_cmd)
            .exec(),
    )
    .expect("execl failed");
    unreachable!()
}

extern "C" fn signal(sig: c_int) {
    let sig = Signal::try_from(sig).unwrap();
    // As of today, getting the current function name is still not supported in Rust:
    // https://github.com/rust-lang/rfcs/issues/1743
    debug!("tmux_rs::client::signal: {sig}");
    if sig == Signal::SIGCHLD {
        while let Err(e) = waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            match e {
                Errno::ECHILD => break,
                _ => debug!("waitpid failed: {e}"),
            }
        }
    } else if unsafe { !ATTACHED } {
        if sig == Signal::SIGTERM || sig == Signal::SIGHUP {
            unsafe {
                crate::proc::exit(PROC.as_mut().unwrap().as_mut());
            }
        }
    } else {
        unsafe {
            match sig {
                Signal::SIGHUP => {
                    *EXIT_REASON.lock().unwrap() = Some(Exit::LostTty);
                    EXIT_VAL = 1;
                    (*PEER).send(Msg::Exiting, None, &[]);
                }
                Signal::SIGTERM => {
                    if !SUSPENDED {
                        *EXIT_REASON.lock().unwrap() = Some(Exit::Terminated);
                    }
                    EXIT_VAL = 1;
                    (*PEER).send(Msg::Exiting, None, &[]);
                }
                Signal::SIGWINCH => {
                    (*PEER).send(Msg::Resize, None, &[]);
                }
                Signal::SIGCONT => {
                    sigaction(
                        Signal::SIGTSTP,
                        &SigAction::new(SigHandler::SigIgn, SaFlags::SA_RESTART, SigSet::empty()),
                    )
                    .expect("sigaction failed");
                    (*PEER).send(Msg::WakeUp, None, &[]);
                    SUSPENDED = false;
                }
                _ => {}
            }
        }
    }
}

/// Callback for file write error or close.
extern "C" fn file_check_cb(
    _c: *mut crate::tmux_sys::client,
    _path: *const c_char,
    _error: c_int,
    _closed: c_int,
    _buffer: *mut evbuffer,
    _data: *mut c_void,
) {
    if unsafe { EXIT_FLAG } {
        exit();
    }
}

/// Callback for client read events.
extern "C" fn dispatch(imsg: *mut IMsg, arg: *mut c_void) {
    let ctx = unsafe { arg.cast::<Context>().as_mut().unwrap() };

    match unsafe { imsg.as_mut() } {
        None => unsafe {
            if !EXIT_FLAG {
                *EXIT_REASON.lock().unwrap() = Some(Exit::LostServer);
                EXIT_VAL = 1;
            }
            crate::proc::exit(PROC.as_mut().unwrap().as_mut());
        },
        Some(imsg) => {
            if unsafe { ATTACHED } {
                dispatch_attached(ctx, imsg);
            } else {
                dispatch_wait(ctx, imsg);
            }
        }
    }
}

fn dispatch_exit_message(data: *mut c_char, data_len: usize) {
    if data_len == 0 {
        return;
    }

    const RETVAL_SIZE: usize = unsafe { mem::size_of_val_raw(&raw const EXIT_VAL) };
    if data_len < RETVAL_SIZE {
        panic!("bad MSG_EXIT size");
    }

    let (retval_data, data) =
        unsafe { slice::from_raw_parts(data as *mut u8, data_len) }.split_at(RETVAL_SIZE);
    unsafe { EXIT_VAL = bytemuck::pod_read_unaligned(retval_data) };

    if data.len() > 0 {
        *EXIT_REASON.lock().unwrap() = Some(Exit::MessageProvided(
            str::from_utf8(data).unwrap().to_owned(),
        ));
    }
}

/// Dispatch imsgs when in wait state (before MSG_READY).
fn dispatch_wait(ctx: &mut Context, imsg: &mut IMsg) {
    static mut PLEDGE_APPLIED: bool = false;

    // "sendfd" is no longer required once all of the identify messages
    // have been sent. We know the server won't send us anything until that
    // point (because we don't ask it to), so we can drop "sendfd" once we
    // get the first message from the server.
    unsafe {
        if !PLEDGE_APPLIED {
            crate::compat::pledge(Some("stdio rpath wpath cpath unix proc exec tty"), None)
                .expect("pledge failed");
            PLEDGE_APPLIED = true;
        }
    }

    let data = imsg.data as *mut c_char;
    let data_len = imsg.hdr.len as usize - size_of::<imsg_hdr>();

    let msg_type: Msg = unsafe { mem::transmute(imsg.hdr.type_) };
    match msg_type {
        Msg::Exit | Msg::Shutdown => {
            dispatch_exit_message(data, data_len);
            unsafe {
                EXIT_FLAG = true;
            }
            exit();
        }

        Msg::Ready => {
            if data_len != 0 {
                panic!("bad MSG_READY size")
            }

            unsafe {
                ATTACHED = true;
                // I thought MSG_READY should be sent instead of MSG_RESIZE,
                // but after looking at commit 88b92df8492092fbbab37a3ddd2390e0eee2cb24,
                // I think RESIZE is the right choice.
                (*PEER).send(Msg::Resize, None, &[]);
            }
        }

        Msg::Version => {
            if data_len != 0 {
                panic!("bad MSG_VERSION size")
            }

            eprintln!(
                "protocol version mismatch (client {}, server {})",
                crate::protocol::VERSION,
                imsg.hdr.peerid & 0xff
            );
            unsafe {
                EXIT_VAL = 1;
                crate::proc::exit(PROC.as_mut().unwrap().as_mut());
            }
        }

        Msg::Flags => {
            ctx.flags = bytemuck::try_pod_read_unaligned(unsafe {
                slice::from_raw_parts(data as *const u8, data_len)
            })
            .expect("bad MSG_FLAGS string");
            debug!("new flags are {:x}", ctx.flags);
        }

        Msg::Shell => {
            let data = unsafe { CStr::from_ptr(data) }.to_bytes();
            if data_len == 0 || data.len() >= data_len {
                panic!("bad MSG_SHEL string")
            }

            exec(
                ctx,
                OsStr::from_bytes(data).as_ref(),
                OsStr::from_bytes(
                    unsafe { CStr::from_ptr(crate::tmux_sys::shell_command) }.to_bytes(),
                ),
            );
        }

        Msg::Detach | Msg::DetachKill => {
            unsafe { &mut *PEER }.send(Msg::Exiting, None, &[]);
        }

        Msg::Exited => unsafe {
            crate::proc::exit(PROC.as_mut().unwrap().as_mut());
        },

        Msg::ReadOpen => unsafe {
            file_read_open(
                &raw mut FILES,
                PEER,
                imsg,
                1,
                match !ctx.flags.intersects(ClientFlags::CONTROL) {
                    true => 1,
                    false => 0,
                },
                Some(file_check_cb),
                ptr::null_mut(),
            );
        },

        Msg::ReadCancel => unsafe {
            file_read_cancel(&raw mut FILES, imsg);
        },

        Msg::WriteOpen => unsafe {
            file_write_open(
                &raw mut FILES,
                PEER,
                imsg,
                1,
                match !ctx.flags.intersects(ClientFlags::CONTROL) {
                    true => 1,
                    false => 0,
                },
                Some(file_check_cb),
                ptr::null_mut(),
            );
        },

        Msg::Write => crate::file::write_data(unsafe { &mut FILES }, imsg),

        Msg::WriteClose => unsafe {
            file_write_close(&raw mut FILES, imsg);
        },

        Msg::OldStderr | Msg::OldStdin | Msg::OldStdout => {
            eprintln!("server version is too old for client");
            unsafe {
                crate::proc::exit(PROC.as_mut().unwrap().as_mut());
            }
        }

        _ => {}
    }
}

/// Dispatch imsgs in attached state (after MSG_READY).
fn dispatch_attached(ctx: &mut Context, imsg: &crate::tmux_sys::imsg) {
    let data = imsg.data as *mut c_char;
    let data_len = imsg.hdr.len as usize - size_of::<imsg_hdr>();

    let msg_type: Msg = unsafe { mem::transmute(imsg.hdr.type_) };
    match msg_type {
        Msg::Flags => {
            ctx.flags = bytemuck::try_pod_read_unaligned(unsafe {
                slice::from_raw_parts(data as *const u8, data_len)
            })
            .expect("bad MSG_FLAGS string");
            debug!("new flags are {:x}", ctx.flags);
        }

        Msg::Detach | Msg::DetachKill => {
            let data = unsafe { CStr::from_ptr(data) }.to_bytes();
            if data_len == 0 || data.len() >= data_len {
                panic!("bad MSG_DETACH string")
            }

            unsafe {
                let exit_session = str::from_utf8(data).unwrap().to_string();
                EXIT_TYPE.write(msg_type);
                *EXIT_REASON.lock().unwrap() = Some(if matches!(msg_type, Msg::DetachKill) {
                    Exit::DetachedHup {
                        session: exit_session,
                    }
                } else {
                    Exit::Detached {
                        session: exit_session,
                    }
                });
                (*PEER).send(Msg::Exiting, None, &[]);
            }
        }

        Msg::Exec => {
            let cmd = unsafe { CStr::from_ptr(data) }.to_bytes();
            if data_len == 0 || cmd.len() != data_len {
                panic!("bad MSG_EXEC string")
            }

            unsafe {
                *EXEC_CMD.lock().unwrap() = Some(OsStr::from_bytes(cmd).to_owned());
                let shell = CStr::from_ptr(data.add(cmd.len() + 1));
                *EXEC_SHELL.lock().unwrap() = Some(OsStr::from_bytes(shell.to_bytes()).to_owned());

                EXIT_TYPE.write(msg_type);
                (*PEER).send(Msg::Exiting, None, &[]);
            }
        }

        Msg::Exit => {
            dispatch_exit_message(data, data_len);
            unsafe {
                let mut exit_reason = EXIT_REASON.lock().unwrap();
                if exit_reason.is_none() {
                    *exit_reason = Some(Exit::Exited);
                }
                (*PEER).send(Msg::Exiting, None, &[]);
            }
        }

        Msg::Exited => {
            if data_len != 0 {
                panic!("bad MSG_EXITED size")
            }

            unsafe {
                crate::proc::exit(PROC.as_mut().unwrap().as_mut());
            }
        }

        Msg::Shutdown => {
            if data_len != 0 {
                panic!("bad MSG_SHUTDOWN size")
            }

            unsafe {
                (*PEER).send(Msg::Exiting, None, &[]);
                *EXIT_REASON.lock().unwrap() = Some(Exit::ServerExited);
                EXIT_VAL = 1;
            }
        }

        Msg::Suspend => {
            if data_len != 0 {
                panic!("bad MSG_SHUTDOWN size")
            }

            unsafe {
                sigaction(
                    Signal::SIGTSTP,
                    &SigAction::new(SigHandler::SigDfl, SaFlags::SA_RESTART, SigSet::empty()),
                )
                .expect("sigaction failed");
                SUSPENDED = true;
                kill(Pid::this(), Signal::SIGTSTP).unwrap();
            }
        }

        Msg::Lock => {
            if data_len == 0 || unsafe { data.add(data_len - 1).read() != 0 } {
                panic!("bad MSG_LOCK string")
            }

            unsafe {
                libc::system(data);
                (*PEER).send(Msg::Unlock, None, &[]);
            }
        }

        _ => {}
    }
}
