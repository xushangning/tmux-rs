use core::{
    ffi::{CStr, c_char, c_int, c_long, c_short, c_void},
    mem,
    ptr::{self, NonNull},
};
use std::os::{fd::IntoRawFd, unix::net::UnixStream};

use libc::pid_t;
use log::debug;
use nix::errno::Errno;
use scopeguard::defer;

use crate::{
    compat::{
        imsg::{HEADER_SIZE, IMsg},
        tree::rb,
    },
    libevent::evtimer_set,
    protocol::Msg,
    tmux_sys::{
        _PATH_BSHELL, CLIENT_CONTROL, CLIENT_DEAD, CLIENT_DOUBLECLICK, CLIENT_EXIT, CLIENT_FOCUSED,
        CLIENT_IDENTIFIED, CLIENT_READONLY, CLIENT_REPEAT, CLIENT_SUSPENDED, CLIENT_TERMINAL,
        CLIENT_TRIPLECLICK, CMD_READONLY, KEYC_DOUBLECLICK, WINDOW_SIZE_LATEST, args_free_values,
        args_from_vector, cfg_finished, checkshell, client_file, clients, cmd_free_argv,
        cmd_list_all_have, cmd_list_copy, cmd_list_free, cmd_parse_from_arguments,
        cmd_retval_CMD_RETURN_NORMAL, cmd_unpack_argv, cmdq_append, cmdq_get_callback1,
        cmdq_get_command, cmdq_get_error, control_ready, control_start, environ_put,
        file_read_data, file_read_done, file_write_ready, global_options, global_s_options,
        imsg_get_fd, key_bindings_get_table, key_event, msgtype_MSG_EXITED, notify_client,
        options_get_command, options_get_number, options_get_string, proc_add_peer, proc_kill_peer,
        proc_send, recalculate_size, recalculate_sizes, server_client_clear_overlay,
        server_client_handle_key, server_client_lost, server_client_set_key_table,
        server_client_set_session, server_redraw_client, server_status_client,
        session_update_activity, start_cfg, status_init, tty_close, tty_get_features, tty_init,
        tty_repeat_requests, tty_resize, tty_send_requests, tty_start_tty, xasprintf, xcalloc,
        xreallocarray, xstrdup,
    },
    util,
};

/// Create a new client.
pub(super) fn create(sock: UnixStream) -> NonNull<crate::tmux_sys::client> {
    sock.set_nonblocking(true).unwrap();

    let mut ret = unsafe {
        NonNull::<crate::tmux_sys::client>::new_unchecked(
            crate::tmux_sys::xcalloc(1, mem::size_of::<crate::tmux_sys::client>()).cast(),
        )
    };
    let c = unsafe { ret.as_mut() };
    c.references = 1;
    c.peer = unsafe {
        proc_add_peer(
            crate::tmux_sys::server_proc,
            sock.into_raw_fd(),
            Some(dispatch),
            ret.as_ptr().cast(),
        )
    };

    Errno::result(unsafe { libc::gettimeofday(&raw mut c.creation_time, ptr::null_mut()) })
        .expect("gettimeofday failed");
    c.activity_time = c.creation_time.clone();

    c.environ = unsafe { crate::tmux_sys::environ_create() };

    c.fd = -1;
    c.out_fd = -1;

    c.queue = unsafe { crate::tmux_sys::cmdq_new() };
    c.windows = rb::Head::new();
    c.files = unsafe {
        mem::transmute(rb::Head::<
            client_file,
            { mem::offset_of!(client_file, entry) },
        >::new())
    };

    c.tty.sx = 80;
    c.tty.sy = 24;
    c.theme = crate::tmux_sys::client_theme_THEME_UNKNOWN;

    unsafe {
        status_init(ret.as_ptr());
    }
    c.flags |= CLIENT_FOCUSED as u64;

    unsafe {
        c.keytable = key_bindings_get_table(c"root".as_ptr(), 1);
        (*c.keytable).references += 1;

        evtimer_set(
            &raw mut c.repeat_timer,
            Some(repeat_timer),
            ret.as_ptr().cast(),
        );
        evtimer_set(
            &raw mut c.click_timer,
            Some(click_timer),
            ret.as_ptr().cast(),
        );
    }

    unsafe {
        crate::tmux_sys::clients.assume_init_mut().push_back(ret);
    }
    debug!("new client {:?}", ret.as_ptr());
    ret
}

/// Has the latest client changed?
fn update_latest(c: &mut crate::tmux_sys::client) {
    let session = unsafe {
        match c.session.as_mut() {
            Some(session) => session,
            None => return,
        }
    };
    let w = unsafe { session.curw.as_mut().unwrap().window.as_mut().unwrap() };

    let c_ptr = c as *mut crate::tmux_sys::client as *mut c_void;
    if w.latest == c_ptr {
        return;
    }
    w.latest = c_ptr;

    unsafe {
        if options_get_number(w.options, c"window-size".as_ptr()) == WINDOW_SIZE_LATEST as i64 {
            recalculate_size(w, 0);
        }

        notify_client(c"client-active".as_ptr(), c);
    }
}

/// Repeat time callback.
extern "C" fn repeat_timer(_fd: c_int, _events: c_short, data: *mut c_void) {
    let c = unsafe { (data as *mut crate::tmux_sys::client).as_mut() }.unwrap();

    if c.flags & CLIENT_REPEAT as u64 != 0 {
        unsafe {
            server_client_set_key_table(c, ptr::null_mut());
        }
        c.flags &= !CLIENT_REPEAT as u64;
        unsafe {
            server_status_client(c);
        }
    }
}

/// Double-click callback.
extern "C" fn click_timer(_fd: c_int, _events: c_short, data: *mut c_void) {
    let c = unsafe { (data as *mut crate::tmux_sys::client).as_mut() }.unwrap();

    debug!("click timer expired");

    if c.flags & CLIENT_TRIPLECLICK as u64 != 0 {
        // Waiting for a third click that hasn't happened, so this must
        // have been a double click.
        let event = unsafe {
            (xcalloc(1, mem::size_of::<key_event>()) as *mut key_event)
                .as_mut()
                .unwrap()
        };
        event.key = KEYC_DOUBLECLICK as u64;
        event.m = c.click_event.clone();
        unsafe {
            if server_client_handle_key(c, event) == 0 {
                libc::free(event.buf.cast());
                libc::free((event as *mut key_event).cast());
            }
        }
    }
    c.flags &= !((CLIENT_DOUBLECLICK | CLIENT_TRIPLECLICK) as u64);
}

/// Dispatch message from client.
extern "C" fn dispatch(imsg: *mut crate::tmux_sys::imsg, arg: *mut c_void) {
    use crate::protocol::Msg::*;

    let c = unsafe { (arg as *mut crate::tmux_sys::client).as_mut() }.unwrap();

    if c.flags & CLIENT_DEAD as u64 != 0 {
        return;
    }

    let imsg = match unsafe { imsg.as_mut() } {
        Some(imsg) => imsg,
        None => {
            unsafe {
                server_client_lost(c);
            }
            return;
        }
    };

    let data_len = imsg.hdr.len as usize - HEADER_SIZE;

    match unsafe { mem::transmute::<_, Msg>(imsg.hdr.type_) } {
        IdentifyClientPid | IdentifyCwd | IdentifyEnviron | IdentifyFeatures | IdentifyFlags
        | IdentifyLongFlags | IdentifyStdin | IdentifyStdout | IdentifyTerm | IdentifyTermInfo
        | IdentifyTtyName | IdentifyDone => dispatch_identify(c, imsg),
        Command => dispatch_command(c, imsg),
        Resize => {
            if data_len != 0 {
                panic!("bad MSG_RESIZE size");
            }

            if c.flags & CLIENT_CONTROL as u64 == 0 {
                update_latest(c);
                unsafe {
                    tty_resize(&raw mut c.tty);
                    tty_repeat_requests(&raw mut c.tty);
                    recalculate_sizes();
                    match c.overlay_resize.as_ref() {
                        None => server_client_clear_overlay(c),
                        Some(overlay_resize) => overlay_resize(c, c.overlay_data),
                    }
                    server_redraw_client(c);
                    if !c.session.is_null() {
                        notify_client(c"client-resized".as_ptr(), c);
                    }
                }
            }
        }
        Exiting => {
            if data_len != 0 {
                panic!("bad MSG_EXITING size");
            }

            unsafe {
                server_client_set_session(c, ptr::null_mut());
                recalculate_sizes();
                tty_close(&raw mut c.tty);
                proc_send(c.peer, msgtype_MSG_EXITED, -1, ptr::null_mut(), 0);
            }
        }
        WakeUp | Unlock => {
            if data_len != 0 {
                panic!("bad MSG_WAKEUP size");
            }

            if c.flags & CLIENT_SUSPENDED as u64 == 0 {
                return;
            }
            c.flags &= !(CLIENT_SUSPENDED as u64);

            if c.fd == -1 || c.session.is_null() {
                // exited already
                return;
            }

            Errno::result(unsafe { libc::gettimeofday(&raw mut c.activity_time, ptr::null_mut()) })
                .expect("gettimeofday failed");

            unsafe {
                tty_start_tty(&raw mut c.tty);
                server_redraw_client(c);
                recalculate_sizes();

                session_update_activity(c.session, &raw mut c.activity_time);
            }
        }
        Shell => {
            if data_len != 0 {
                panic!("bad MSG_SHELL size");
            }

            dispatch_shell(c);
        }
        WriteReady => unsafe {
            file_write_ready(&raw mut c.files, imsg);
        },
        Read => unsafe {
            file_read_data(&raw mut c.files, imsg);
        },
        ReadDone => unsafe {
            file_read_done(&raw mut c.files, imsg);
        },
        _ => {}
    }
}

/// Callback when command is not allowed.
extern "C" fn read_only(
    item: *mut crate::tmux_sys::cmdq_item,
    _data: *mut c_void,
) -> crate::tmux_sys::cmd_retval {
    unsafe {
        crate::tmux_sys::cmdq_error(item, c"client is read-only".as_ptr());
    }
    crate::tmux_sys::cmd_retval_CMD_RETURN_ERROR
}

/// Callback when command is done.
extern "C" fn command_done(
    item: *mut crate::tmux_sys::cmdq_item,
    _data: *mut c_void,
) -> crate::tmux_sys::cmd_retval {
    let c = unsafe { crate::tmux_sys::cmdq_get_client(item).as_mut().unwrap() };

    if c.flags & crate::tmux_sys::CLIENT_ATTACHED as u64 == 0 {
        c.flags |= CLIENT_EXIT as u64;
    } else if c.flags & CLIENT_EXIT as u64 == 0 {
        if c.flags & CLIENT_CONTROL as u64 != 0 {
            unsafe {
                control_ready(c);
            }
        }
        unsafe {
            tty_send_requests(&raw mut c.tty);
        }
    }
    cmd_retval_CMD_RETURN_NORMAL
}

/// Handle command message.
fn dispatch_command(c: &mut crate::tmux_sys::client, imsg: &IMsg) {
    if c.flags & CLIENT_EXIT as u64 != 0 {
        return;
    }

    let data_len = imsg.hdr.len as usize - HEADER_SIZE;
    const MSG_COMMAND_LEN: usize = mem::size_of::<crate::tmux_sys::msg_command>();
    if data_len < MSG_COMMAND_LEN {
        panic!("bad MSG_COMMAND size");
    }
    let data = unsafe { ptr::read_unaligned(imsg.data as *const crate::tmux_sys::msg_command) };

    let buf = unsafe { imsg.data.byte_add(MSG_COMMAND_LEN) as *mut c_char };
    let len = data_len - MSG_COMMAND_LEN;

    if len > 0 && unsafe { *buf.add(len - 1) } != 0 {
        panic!("bad MSG_COMMAND string");
    }

    let argc = data.argc;
    let mut argv: *mut *mut i8 = ptr::null_mut();
    let error = |c: &mut crate::tmux_sys::client, cause: *mut c_char| {
        unsafe {
            cmdq_append(c, cmdq_get_error(cause));
            libc::free(cause.cast());
        }

        c.flags |= CLIENT_EXIT as u64;
    };
    if unsafe { cmd_unpack_argv(buf, len, argc, &raw mut argv) } != 0 {
        error(c, unsafe { xstrdup(c"command too long".as_ptr()) });
        return;
    }
    defer! {
        unsafe {
            cmd_free_argv(argc, argv);
        }
    }

    let cmdlist = if argc == 0 {
        unsafe {
            cmd_list_copy(
                options_get_command(global_options, c"default-client-command".as_ptr()),
                0,
                ptr::null_mut(),
            )
        }
    } else {
        let values = unsafe { args_from_vector(argc, argv) };
        defer! {
            unsafe {
                args_free_values(values, argc.try_into().unwrap());
                libc::free(values.cast());
            }
        }
        let pr = unsafe {
            cmd_parse_from_arguments(values, argc.try_into().unwrap(), ptr::null_mut())
                .as_ref()
                .unwrap()
        };

        match pr.status {
            crate::tmux_sys::cmd_parse_status_CMD_PARSE_ERROR => {
                error(c, pr.error);
                return;
            }
            crate::tmux_sys::cmd_parse_status_CMD_PARSE_SUCCESS => pr.cmdlist,
            _ => {
                return;
            }
        }
    };

    let new_item = if c.flags & CLIENT_READONLY as u64 != 0
        && unsafe { cmd_list_all_have(cmdlist, CMD_READONLY.try_into().unwrap()) } == 0
    {
        unsafe {
            cmdq_get_callback1(
                c"server_client_read_only".as_ptr(),
                Some(read_only),
                ptr::null_mut(),
            )
        }
    } else {
        unsafe { cmdq_get_command(cmdlist, ptr::null_mut()) }
    };

    unsafe {
        cmdq_append(c, new_item);
        cmdq_append(
            c,
            cmdq_get_callback1(
                c"server_client_command_done".as_ptr(),
                Some(command_done),
                ptr::null_mut(),
            ),
        );
        cmd_list_free(cmdlist);
    }
}

/// Handle identify message.
fn dispatch_identify(c: &mut crate::tmux_sys::client, imsg: &IMsg) {
    use crate::protocol::Msg::*;

    if c.flags & CLIENT_IDENTIFIED as u64 != 0 {
        panic!("out-of-order identify message");
    }

    let data = imsg.data as *mut c_char;
    let data_len = imsg.hdr.len as usize - HEADER_SIZE;

    let c_ptr = c as *const _;
    let msg_type = unsafe { mem::transmute::<_, Msg>(imsg.hdr.type_) };
    match msg_type {
        IdentifyFeatures => {
            if data_len != mem::size_of::<c_int>() {
                panic!("bad MSG_IDENTIFY_FEATURES size");
            }
            let feat = unsafe { ptr::read_unaligned(data as *const c_int) };
            c.term_features |= feat;
            debug!("client {:?} IDENTIFY_FEATURES {}", c_ptr, unsafe {
                CStr::from_ptr(tty_get_features(feat)).to_str().unwrap()
            });
        }
        IdentifyFlags => {
            if data_len != mem::size_of::<c_int>() {
                panic!("bad MSG_IDENTIFY_FLAGS size");
            }
            let flags = unsafe { ptr::read_unaligned(data as *const c_int) };
            c.flags |= flags as u64;
            debug!("client {:?} IDENTIFY_FLAGS {:#x}", c_ptr, flags);
        }
        IdentifyLongFlags => {
            if data_len != mem::size_of::<u64>() {
                panic!("bad MSG_IDENTIFY_LONGFLAGS size");
            }
            let longflags = unsafe { ptr::read_unaligned(data as *const u64) };
            c.flags |= longflags;
            debug!("client {:?} IDENTIFY_LONGFLAGS {:#x}", c_ptr, longflags);
        }
        IdentifyTerm => {
            if data_len == 0 || unsafe { *data.add(data_len - 1) } != 0 {
                panic!("bad MSG_IDENTIFY_TERM string");
            }
            let term_name = unsafe {
                xstrdup(if *data == 0 {
                    c"unknown".as_ptr()
                } else {
                    data
                })
            };
            c.term_name = term_name;
            debug!("client {:?} IDENTIFY_TERM {}", c_ptr, unsafe {
                CStr::from_ptr(data).to_str().unwrap()
            });
        }
        IdentifyTermInfo => {
            if data_len == 0 || unsafe { *data.add(data_len - 1) } != 0 {
                panic!("bad MSG_IDENTIFY_TERMINFO string");
            }
            unsafe {
                c.term_caps = xreallocarray(
                    c.term_caps as *mut c_void,
                    c.term_ncaps as usize + 1,
                    mem::size_of::<*mut c_char>(),
                ) as *mut *mut c_char;
                *c.term_caps.add(c.term_ncaps as usize) = xstrdup(data);
            }
            c.term_ncaps += 1;
            debug!("client {:?} IDENTIFY_TERMINFO {}", c_ptr, unsafe {
                std::ffi::CStr::from_ptr(data).to_str().unwrap()
            });
        }
        IdentifyTtyName => {
            if data_len == 0 || unsafe { *data.add(data_len - 1) } != 0 {
                panic!("bad MSG_IDENTIFY_TTYNAME string");
            }
            c.ttyname = unsafe { xstrdup(data) };
            debug!("client {:?} IDENTIFY_TTYNAME {}", c_ptr, unsafe {
                std::ffi::CStr::from_ptr(data).to_str().unwrap()
            });
        }
        IdentifyCwd => {
            if data_len == 0 || unsafe { *data.add(data_len - 1) } != 0 {
                panic!("bad MSG_IDENTIFY_CWD string");
            }
            c.cwd = unsafe {
                xstrdup(if libc::access(data, libc::X_OK) == 0 {
                    data
                } else if let Some(home) = std::env::home_dir() {
                    util::path_to_c_str(home.as_ref()).unwrap().as_ptr()
                } else {
                    c"/".as_ptr()
                })
            };
            debug!("client {:?} IDENTIFY_CWD {}", c_ptr, unsafe {
                std::ffi::CStr::from_ptr(data).to_str().unwrap()
            });
        }
        IdentifyStdin => {
            if data_len != 0 {
                panic!("bad MSG_IDENTIFY_STDIN size");
            }
            c.fd = unsafe { imsg_get_fd((imsg as *const IMsg).cast_mut()) };
            debug!("client {:?} IDENTIFY_STDIN {}", c_ptr, c.fd);
        }
        IdentifyStdout => {
            if data_len != 0 {
                panic!("bad MSG_IDENTIFY_STDOUT size");
            }
            c.out_fd = unsafe { imsg_get_fd((imsg as *const IMsg).cast_mut()) };
            debug!("client {:?} IDENTIFY_STDOUT {}", c_ptr, c.out_fd);
        }
        IdentifyEnviron => {
            if data_len == 0 || unsafe { *(data.byte_add(data_len - 1) as *const c_char) } != 0 {
                panic!("bad MSG_IDENTIFY_ENVIRON string");
            }
            unsafe {
                if !libc::strchr(data, b'=' as c_int).is_null() {
                    environ_put(c.environ, data, 0);
                }
            }
            debug!("client {:?} IDENTIFY_ENVIRON {}", c_ptr, unsafe {
                CStr::from_ptr(data).to_str().unwrap()
            });
        }
        IdentifyClientPid => {
            if data_len != mem::size_of::<pid_t>() {
                panic!("bad MSG_IDENTIFY_CLIENTPID size");
            }
            c.pid = unsafe { ptr::read_unaligned(data as *const libc::pid_t) };
            debug!("client {:?} IDENTIFY_CLIENTPID {}", c_ptr, c.pid);
        }
        _ => {}
    }

    if !matches!(msg_type, IdentifyDone) {
        return;
    }
    c.flags |= CLIENT_IDENTIFIED as u64;

    unsafe {
        if *c.ttyname != 0 {
            c.name = xstrdup(c.ttyname);
        } else {
            xasprintf(
                (&raw mut c.name) as *mut *mut c_char,
                c"client-%ld".as_ptr(),
                c.pid as c_long,
            );
        };
    }
    debug!("client {:?} name is {}", c_ptr, unsafe {
        CStr::from_ptr(c.name).to_str().unwrap()
    });

    #[cfg(target_os = "windows")]
    unsafe {
        c.fd = libc::open(c.ttyname, libc::O_RDWR | libc::O_NOCTTY);
        c.out_fd = libc::dup(c.fd);
    }

    unsafe {
        if c.flags & CLIENT_CONTROL as u64 != 0 {
            control_start(c);
        } else if c.fd != -1 {
            if tty_init(&raw mut c.tty, c) != 0 {
                libc::close(c.fd);
                c.fd = -1;
            } else {
                tty_resize(&raw mut c.tty);
                c.flags |= CLIENT_TERMINAL as u64;
            }
            libc::close(c.out_fd);
            c.out_fd = -1;
        }
    }

    // If this is the first client, load configuration files. Any later
    // clients are allowed to continue with their command even if the
    // config has not been loaded - they might have been run from inside it
    unsafe {
        if c.flags & CLIENT_EXIT as u64 == 0
            && cfg_finished == 0
            && clients.assume_init_ref().front() == Some(NonNull::from_mut(c))
        {
            start_cfg();
        }
    }
}

/// Handle shell message.
fn dispatch_shell(c: &mut crate::tmux_sys::client) {
    unsafe {
        let mut shell = options_get_string(global_s_options, c"default-shell".as_ptr());
        if checkshell(shell) == 0 {
            shell = _PATH_BSHELL.as_ptr();
        }
        proc_send(
            c.peer,
            mem::transmute(Msg::Shell),
            -1,
            shell.cast(),
            libc::strlen(shell) + 1,
        );

        proc_kill_peer(c.peer);
    }
}
