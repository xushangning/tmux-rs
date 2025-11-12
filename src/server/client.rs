use core::{
    cmp::Ordering,
    convert::TryInto,
    ffi::{CStr, c_char, c_int, c_long, c_short, c_uint, c_void},
    mem::{self, MaybeUninit, offset_of},
    pin::Pin,
    ptr::{self, NonNull},
};
use std::os::{fd::IntoRawFd, unix::net::UnixStream};

use libc::{gettimeofday, pid_t, timeval};
use log::debug;
use nix::errno::Errno;

use crate::{
    Client, ClientExitType, ClientFlags,
    compat::{
        imsg::{HEADER_SIZE, IMsg},
        queue::tailq,
        tree::rb,
    },
    file::ClientFiles,
    libevent::{evtimer_add, evtimer_set},
    protocol::Msg,
    tmux_sys::{
        _PATH_BSHELL, CMD_READONLY, EV_TIMEOUT, KEYC_DOUBLECLICK, TTY_BLOCK, WINDOW_SIZE_LATEST,
        cfg_finished, checkshell, client_file, client_window, clients, cmd_list_all_have,
        cmd_list_copy, cmd_list_free, cmd_parse_from_arguments, cmdq_append, cmdq_get_callback1,
        cmdq_get_command, control_ready, control_start, environ_put, evbuffer_get_length,
        event_initialized, event_pending, file_read_data, file_read_done, file_write_ready,
        global_options, global_s_options, imsg_get_fd, key_bindings_get_table, key_event,
        notify_client, options_get_command, options_get_number, options_get_string, proc_add_peer,
        proc_kill_peer, recalculate_size, recalculate_sizes, server_client_clear_overlay,
        server_client_handle_key, server_client_lost, server_redraw_client,
        session_update_activity, start_cfg, status_at_line, status_init, status_line_size,
        tty_close, tty_get_features, tty_init, tty_repeat_requests, tty_resize, tty_send_requests,
        tty_start_tty, tty_update_mode, xasprintf, xcalloc, xreallocarray, xstrdup,
    },
    util,
    window::{Pane, PaneFlags, Window, WindowFlags},
};

impl Ord for client_window {
    fn cmp(&self, other: &Self) -> Ordering {
        self.window.cmp(&other.window)
    }
}

impl PartialOrd for client_window {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for client_window {
    fn eq(&self, other: &Self) -> bool {
        self.window == other.window
    }
}

impl Eq for client_window {}

/// Set client key table.
pub(crate) fn set_key_table(c: &mut Client, mut name: *const c_char) {
    if name.is_null() {
        name = get_key_table(c);
    }

    unsafe {
        crate::tmux_sys::key_bindings_unref_table(c.keytable);
        c.keytable = crate::tmux_sys::key_bindings_get_table(name, 1);
        let keytable = c.keytable.as_mut().unwrap();
        keytable.references += 1;
        Errno::result(gettimeofday(&mut keytable.activity_time, ptr::null_mut()))
            .expect("gettimeofday failed");
    }
}

/// Get default key table.
pub(crate) fn get_key_table(c: &mut Client) -> *const c_char {
    let Some(s) = (unsafe { c.session.as_mut() }) else {
        return c"root".as_ptr();
    };

    let name = unsafe { options_get_string(s.options, c"key-table".as_ptr()) };
    if unsafe { *name } == 0 {
        c"root".as_ptr()
    } else {
        name
    }
}

/// Create a new client.
pub(super) fn create(sock: UnixStream) -> NonNull<Client> {
    sock.set_nonblocking(true).unwrap();

    let mut ret = unsafe {
        NonNull::<Client>::new_unchecked(
            crate::tmux_sys::xcalloc(1, mem::size_of::<Client>()).cast(),
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

    Errno::result(unsafe { gettimeofday(&mut c.creation_time, ptr::null_mut()) })
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
    c.flags |= ClientFlags::FOCUSED;

    unsafe {
        c.keytable = key_bindings_get_table(c"root".as_ptr(), 1);
        (*c.keytable).references += 1;

        evtimer_set(&mut c.repeat_timer, Some(repeat_timer), ret.as_ptr().cast());
        evtimer_set(&mut c.click_timer, Some(click_timer), ret.as_ptr().cast());
    }

    unsafe {
        Pin::new_unchecked(crate::tmux_sys::clients.assume_init_mut()).push_back(ret);
    }
    debug!("new client {:?}", ret.as_ptr());
    ret
}

/// Has the latest client changed?
fn update_latest(c: &mut Client) {
    let session = unsafe {
        match c.session.as_mut() {
            Some(session) => session,
            None => return,
        }
    };
    let w = unsafe { session.curw.as_mut().unwrap().window.as_mut().unwrap() };

    let c_ptr = c as *mut Client as *mut c_void;
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
    let c = unsafe { (data as *mut Client).as_mut() }.unwrap();

    if c.flags.intersects(ClientFlags::REPEAT) {
        set_key_table(c, ptr::null_mut());
        c.flags.remove(ClientFlags::REPEAT);
        unsafe {
            crate::tmux_sys::server_status_client(c);
        }
    }
}

/// Double-click callback.
extern "C" fn click_timer(_fd: c_int, _events: c_short, data: *mut c_void) {
    let c = unsafe { (data as *mut Client).as_mut() }.unwrap();

    debug!("click timer expired");

    if c.flags.intersects(ClientFlags::TRIPLE_CLICK) {
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
    c.flags
        .remove(ClientFlags::DOUBLE_CLICK | ClientFlags::TRIPLE_CLICK);
}

/// Check if window needs to be resized.
fn check_window_resize(w: &mut Window) {
    if !w.flags.intersects(WindowFlags::RESIZE) {
        return;
    }

    for wl_ptr in unsafe { w.winlinks.assume_init_ref() } {
        let wl = unsafe { wl_ptr.as_ref() };
        let session = unsafe { wl.session.as_ref().unwrap() };
        if session.attached != 0 && session.curw == wl_ptr.as_ptr() {
            debug!(
                "tmux_rs::server::client::check_window_resize: resizing window @{}",
                w.id
            );
            unsafe {
                crate::tmux_sys::resize_window(
                    w,
                    w.new_sx,
                    w.new_sy,
                    w.new_xpixel.try_into().unwrap(),
                    w.new_ypixel.try_into().unwrap(),
                );
            }
            break;
        }
    }
}

/// Resize timer event.
extern "C" fn resize_timer(_fd: c_int, _events: c_short, data: *mut c_void) {
    let wp = unsafe { data.cast::<Pane>().as_mut() }.unwrap();
    debug!(
        "tmux_rs::server::client::resize_timer: %{} resize timer expired",
        wp.id
    );
    unsafe {
        crate::tmux_sys::event_del(&mut wp.resize_timer);
    }
}

/// Check if pane should be resized.
fn check_pane_resize(wp: &mut Pane) {
    use crate::tmux_sys::{window_pane_resize, window_pane_send_resize};

    if unsafe { wp.resize_queue.assume_init_ref().is_empty() } {
        return;
    }

    unsafe {
        if event_initialized(&mut wp.resize_timer) == 0 {
            evtimer_set(
                &mut wp.resize_timer,
                Some(resize_timer),
                (&raw mut *wp).cast(),
            );
        }
        if event_pending(&mut wp.resize_timer, EV_TIMEOUT as c_short, ptr::null_mut()) != 0 {
            return;
        }
    }

    debug!(
        "tmux_rs::server::client::check_pane_resize: %{} needs to be resized",
        wp.id
    );
    for r in unsafe { wp.resize_queue.assume_init_ref() } {
        let r = unsafe { r.as_ref() };
        debug!("queued resize: {}x{} -> {}x{}", r.osx, r.osy, r.sx, r.sy);
    }

    // There are three cases that matter:
    //
    // - Only one resize. It can just be applied.
    //
    // - Multiple resizes and the ending size is different from the
    //   starting size. We can discard all resizes except the most recent.
    //
    // - Multiple resizes and the ending size is the same as the starting
    //   size. We must resize at least twice to force the application to
    //   redraw. So apply the first and leave the last on the queue for
    //   next time.
    let mut tv = timeval {
        tv_sec: 0,
        tv_usec: 250_000,
    };
    unsafe {
        let mut first_nonnull = wp.resize_queue.assume_init_ref().front().unwrap();
        let mut last_nonnull = wp.resize_queue.assume_init_ref().back().unwrap();
        let first = first_nonnull.as_mut();
        let last = last_nonnull.as_mut();
        if first_nonnull == last_nonnull {
            // Only one resize.
            window_pane_send_resize(wp, first.sx, first.sy);
            Pin::new_unchecked(wp.resize_queue.assume_init_mut()).remove(first_nonnull);
            libc::free(first_nonnull.as_ptr().cast());
        } else if last.sx != first.osx || last.sy != first.osy {
            // Multiple resizes ending up with a different size.
            window_pane_send_resize(wp, last.sx, last.sy);
            for r in Pin::new_unchecked(wp.resize_queue.assume_init_mut()).drain() {
                libc::free(r.as_ptr().cast());
            }
        } else {
            // Multiple resizes ending up with the same size. There will
            // not be more than one to the same size in succession so we
            // can just use the last-but-one on the list and leave the last
            // for later. We reduce the time until the next check to avoid
            // a long delay between the resizes.
            let r = mem::transmute::<_, &tailq::Entry<window_pane_resize>>(&last.entry)
                .prev()
                .unwrap()
                .as_mut();
            window_pane_send_resize(wp, r.sx, r.sy);
            let mut resize_queue = Pin::new_unchecked(wp.resize_queue.assume_init_mut());
            resize_queue.as_mut().remove(last_nonnull);
            for r in resize_queue.as_mut().drain() {
                libc::free(r.as_ptr().cast());
            }
            resize_queue.as_mut().push_back(last_nonnull);
            tv.tv_usec = 10_000;
        }
        evtimer_add(&mut wp.resize_timer, &mut tv);
    }
}

/// Check pane buffer size.
fn check_pane_buffer(wp: &mut Pane) {
    use crate::tmux_sys::{EV_READ, control_pane_offset};

    // Work out the minimum used size. This is the most that can be removed
    // from the buffer.
    let mut minimum = wp.offset.used;
    if wp.pipe_fd != -1 && wp.pipe_offset.used < minimum {
        minimum = wp.pipe_offset.used;
    }
    let mut off = true;
    let mut attached_clients = 0;
    for mut c in unsafe { crate::tmux_sys::clients.assume_init_ref() } {
        let c = unsafe { c.as_mut() };
        if c.session.is_null() {
            continue;
        }
        attached_clients += 1;

        if !c.flags.intersects(ClientFlags::CONTROL) {
            off = false;
            continue;
        }
        let mut flag: c_int = 0;
        let Some(wpo) = (unsafe { control_pane_offset(c, wp, &mut flag).as_mut() }) else {
            if flag == 0 {
                off = false;
            }
            continue;
        };
        if flag == 0 {
            off = false;
        }

        let mut new_size: usize = 0;
        unsafe {
            crate::tmux_sys::window_pane_get_new_data(wp, wpo, &mut new_size);
        }
        let name = unsafe { CStr::from_ptr(c.name).to_str().unwrap() };
        debug!(
            "tmux_rs::server::client::check_pane_buffer: {name} has {} bytes used and {new_size} left for %{}",
            wpo.used - wp.base_offset,
            wp.id
        );
        if wpo.used < minimum {
            minimum = wpo.used;
        }
    }
    if attached_clients == 0 {
        off = false;
    }
    minimum -= wp.base_offset;
    if minimum != 0 {
        unsafe {
            // Drain the buffer.
            let evb = wp.event.as_ref().unwrap().input;
            debug!(
                "tmux_rs::server::client::check_pane_buffer: %{} has {minimum} minimum (of {}) bytes used",
                wp.id,
                evbuffer_get_length(evb)
            );
            crate::tmux_sys::evbuffer_drain(evb, minimum);
        }
        // Adjust the base offset. If it would roll over, all the offsets into
        // the buffer need to be adjusted.
        if wp.base_offset > usize::MAX - minimum {
            debug!(
                "tmux_rs::server::client::check_pane_buffer: %{} base offset has wrapped",
                wp.id
            );
            wp.offset.used -= wp.base_offset;
            if wp.pipe_fd != -1 {
                wp.pipe_offset.used -= wp.base_offset;
            }
            for mut c in unsafe { crate::tmux_sys::clients.assume_init_ref() } {
                let c = unsafe { c.as_mut() };
                if c.session.is_null() || !c.flags.intersects(ClientFlags::CONTROL) {
                    continue;
                }
                let mut flag: c_int = 0;
                if let Some(wpo) = unsafe { control_pane_offset(c, wp, &mut flag).as_mut() }
                    && flag == 0
                {
                    wpo.used -= wp.base_offset;
                }
            }
            wp.base_offset = minimum;
        } else {
            wp.base_offset += minimum;
        }

        // If there is data remaining, and there are no clients able to consume
        // it, do not read any more. This is true when there are attached
        // clients, all of which are control clients which are not able to
        // accept any more data.
        debug!(
            "tmux_rs::server::client::check_pane_buffer: pane %{} is {}",
            wp.id,
            if off { "off" } else { "on" }
        );
        unsafe {
            if off {
                crate::tmux_sys::bufferevent_disable(wp.event, EV_READ as c_short);
            } else {
                crate::tmux_sys::bufferevent_enable(wp.event, EV_READ as c_short);
            }
        }
    }
}

/// Check if client should be exited.
fn check_exit(c: &mut Client) {
    if c.flags.intersects(ClientFlags::DEAD | ClientFlags::EXITED) {
        return;
    }
    if !c.flags.intersects(ClientFlags::EXIT) {
        return;
    }

    if c.flags.intersects(ClientFlags::CONTROL) {
        unsafe {
            crate::tmux_sys::control_discard(c);
        }
        if unsafe { crate::tmux_sys::control_all_done(c) } == 0 {
            return;
        }
    }
    for cf in unsafe { mem::transmute::<_, &ClientFiles>(&c.files) } {
        if unsafe { evbuffer_get_length(cf.as_ref().buffer) } != 0 {
            return;
        }
    }
    c.flags |= ClientFlags::EXITED;

    let peer = unsafe { c.peer.as_mut() }.unwrap();
    match c.exit_type {
        ClientExitType::Return => {
            let mut data = Vec::new();
            data.extend_from_slice(bytemuck::bytes_of(&c.retval));
            if !c.exit_message.is_null() {
                let msg = unsafe { CStr::from_ptr(c.exit_message) };
                data.extend_from_slice(msg.to_bytes_with_nul());
            }
            crate::proc::send(peer, Msg::Exit, None, &data);
        }
        ClientExitType::Shutdown => {
            crate::proc::send(peer, Msg::Shutdown, None, &[]);
        }
        ClientExitType::Detach => {
            let name = unsafe { CStr::from_ptr(c.exit_session) };
            crate::proc::send(peer, c.exit_msgtype, None, name.to_bytes_with_nul());
        }
    }
    unsafe {
        libc::free(c.exit_session.cast());
        libc::free(c.exit_message.cast());
    }
}

/// Redraw timer callback.
extern "C" fn redraw_timer(_fd: c_int, _events: c_short, _data: *mut c_void) {
    debug!("redraw timer fired");
}

/// Check if modes need to be updated. Only modes in the current window are
/// updated and it is done when the status line is redrawn.
fn check_modes(c: &mut Client) {
    let w = unsafe {
        c.session
            .as_ref()
            .unwrap()
            .curw
            .as_ref()
            .unwrap()
            .window
            .as_ref()
            .unwrap()
    };

    if c.flags
        .intersects(ClientFlags::CONTROL | ClientFlags::SUSPENDED)
    {
        return;
    }
    if !c.flags.intersects(ClientFlags::REDRAW_STATUS) {
        return;
    }
    unsafe {
        for wp in w.panes.assume_init_ref() {
            if let Some(wme) = wp.as_ref().modes.assume_init_ref().front() {
                if let Some(update) = wme.as_ref().mode.as_ref().unwrap().update {
                    update(wme.as_ptr());
                }
            }
        }
    }
}

/// Check for client redraws.
fn check_redraw(c: &mut Client) {
    use crate::tmux_sys::{TTY_FREEZE, TTY_NOCURSOR};

    static mut EV: MaybeUninit<crate::tmux_sys::event> = MaybeUninit::uninit();

    if c.flags
        .intersects(ClientFlags::CONTROL | ClientFlags::SUSPENDED)
    {
        return;
    }

    let name = unsafe { CStr::from_ptr(c.name).to_str().unwrap_or("unknown") };

    if c.flags.intersects(ClientFlags::ALL_REDRAW_FLAGS) {
        debug!(
            "{name}: redraw{}{}{}{}{}{}",
            if c.flags.intersects(ClientFlags::REDRAW_WINDOW) {
                " window"
            } else {
                ""
            },
            if c.flags.intersects(ClientFlags::REDRAW_STATUS) {
                " status"
            } else {
                ""
            },
            if c.flags.intersects(ClientFlags::REDRAW_BORDERS) {
                " borders"
            } else {
                ""
            },
            if c.flags.intersects(ClientFlags::REDRAW_OVERLAY) {
                " overlay"
            } else {
                ""
            },
            if c.flags.intersects(ClientFlags::REDRAW_PANES) {
                " panes"
            } else {
                ""
            },
            if c.flags.intersects(ClientFlags::REDRAW_SCROLLBARS) {
                " scrollbars"
            } else {
                ""
            }
        );
    }

    let w = unsafe {
        c.session
            .as_ref()
            .unwrap()
            .curw
            .as_ref()
            .unwrap()
            .window
            .as_ref()
            .unwrap()
    };

    // If there is outstanding data, defer the redraw until it has been
    // consumed. We can just add a timer to get out of the event loop and
    // end up back here.
    let mut needed = false;
    let mut client_flags = ClientFlags::empty();
    if c.flags.intersects(ClientFlags::ALL_REDRAW_FLAGS) {
        needed = true;
    } else {
        for wp in unsafe { w.panes.assume_init_ref() } {
            let wp = unsafe { wp.as_ref() };
            if wp.flags.intersects(PaneFlags::REDRAW) {
                needed = true;
                client_flags |= ClientFlags::REDRAW_PANES;
                break;
            }
            if wp.flags.intersects(PaneFlags::REDRAW_SCROLLBAR) {
                needed = true;
                client_flags |= ClientFlags::REDRAW_SCROLLBARS;
                // no break - later panes may need redraw
            }
        }
    }
    let left = unsafe { evbuffer_get_length(c.tty.out) };
    if needed && left != 0 {
        debug!("{name}: redraw deferred ({left} left)");
        let ev = unsafe { EV.as_mut_ptr() };
        if unsafe { event_initialized(ev) } == 0 {
            unsafe {
                evtimer_set(ev, Some(redraw_timer), ptr::null_mut());
            }
        }
        if unsafe { event_pending(ev, EV_TIMEOUT as c_short, ptr::null_mut()) } == 0 {
            debug!("redraw timer started");
            unsafe {
                evtimer_add(
                    ev,
                    &mut timeval {
                        tv_sec: 0,
                        tv_usec: 1_000,
                    },
                );
            }
        }

        if !c.flags.intersects(ClientFlags::REDRAW_WINDOW) {
            let mut bit = 0u32;
            for wp in unsafe { w.panes.assume_init_ref() } {
                let wp = unsafe { wp.as_ref() };
                if wp.flags.intersects(PaneFlags::REDRAW) {
                    debug!("{name}: pane %{} needs redraw", wp.id);
                    c.redraw_panes |= 1u64 << bit;
                } else if wp.flags.intersects(PaneFlags::REDRAW_SCROLLBAR) {
                    debug!("{name}: pane %{} scrollbar needs redraw", wp.id);
                    c.redraw_scrollbars |= 1u64 << bit;
                }
                bit += 1;
                if bit == 64 {
                    // If more that 64 panes, give up and
                    // just redraw the window.
                    client_flags.remove(ClientFlags::REDRAW_PANES | ClientFlags::REDRAW_SCROLLBARS);
                    client_flags |= ClientFlags::REDRAW_WINDOW;
                    break;
                }
            }
            if c.redraw_panes != 0 {
                c.flags |= ClientFlags::REDRAW_PANES;
            }
            if c.redraw_scrollbars != 0 {
                c.flags |= ClientFlags::REDRAW_SCROLLBARS;
            }
        }
        c.flags |= client_flags;
        return;
    }
    if needed {
        debug!("{name}: redraw needed");
    }

    let tty_flags = c.tty.flags & (TTY_BLOCK | TTY_FREEZE | TTY_NOCURSOR) as c_int;
    c.tty.flags = c.tty.flags & !(TTY_BLOCK | TTY_FREEZE) as c_int | TTY_NOCURSOR as c_int;

    if !c.flags.intersects(ClientFlags::REDRAW_WINDOW) {
        // If not redrawing the entire window, check whether each pane
        // needs to be redrawn.
        let mut bit = 0u32;
        for mut wp in unsafe { w.panes.assume_init_ref() } {
            let wp = unsafe { wp.as_mut() };
            let mut redraw_pane = false;
            let mut redraw_scrollbar_only = false;
            if wp.flags.intersects(PaneFlags::REDRAW) {
                redraw_pane = true;
            } else if c.flags.intersects(ClientFlags::REDRAW_PANES) {
                if (c.redraw_panes & (1u64 << bit)) != 0 {
                    redraw_pane = true;
                }
            } else if c.flags.intersects(ClientFlags::REDRAW_SCROLLBARS) {
                if (c.redraw_scrollbars & (1u64 << bit)) != 0 {
                    redraw_scrollbar_only = true;
                }
            }
            bit += 1;
            if !redraw_pane && !redraw_scrollbar_only {
                continue;
            }
            if redraw_scrollbar_only {
                debug!(
                    "tmux_rs::server::client::check_redraw: redrawing (scrollbar only) pane %{}",
                    wp.id
                );
            } else {
                debug!(
                    "tmux_rs::server::client::check_redraw: redrawing pane %{}",
                    wp.id
                );
            }
            unsafe {
                crate::tmux_sys::screen_redraw_pane(c, wp, redraw_scrollbar_only as c_int);
            }
        }
        c.redraw_panes = 0;
        c.redraw_scrollbars = 0;
        c.flags
            .remove(ClientFlags::REDRAW_PANES | ClientFlags::REDRAW_SCROLLBARS);
    }

    if c.flags.intersects(ClientFlags::ALL_REDRAW_FLAGS) {
        if unsafe {
            options_get_number(c.session.as_ref().unwrap().options, c"set-titles".as_ptr())
        } != 0
        {
            set_title(c);
            set_path(c);
        }
        unsafe {
            crate::tmux_sys::screen_redraw_screen(c);
        }
    }

    let tty = &mut c.tty;
    unsafe {
        tty.flags = tty.flags & !TTY_NOCURSOR as c_int | tty_flags & TTY_NOCURSOR as c_int;
        tty_update_mode(tty, tty.mode, ptr::null_mut());
        tty.flags = tty.flags & !(TTY_BLOCK | TTY_FREEZE | TTY_NOCURSOR) as c_int | tty_flags;
    }

    c.flags
        .remove(ClientFlags::ALL_REDRAW_FLAGS | ClientFlags::STATUS_FORCE);

    // We would have deferred the redraw unless the output buffer
    // was empty, so we can record how many bytes the redraw
    // generated.
    if needed {
        c.redraw = unsafe { evbuffer_get_length((*tty).out) };
        debug!("{name}: redraw added {} bytes", c.redraw);
    }
}

/// Set client title.
fn set_title(c: &mut Client) {
    let template = unsafe {
        options_get_string(
            c.session.as_ref().unwrap().options,
            c"set-titles-string".as_ptr(),
        )
    };

    let ft = unsafe {
        crate::tmux_sys::format_create(c, ptr::null_mut(), crate::tmux_sys::FORMAT_NONE as c_int, 0)
    };
    unsafe {
        crate::tmux_sys::format_defaults(ft, c, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    }

    let title = unsafe { crate::tmux_sys::format_expand_time(ft, template) };
    if c.title.is_null() || unsafe { libc::strcmp(title, c.title) != 0 } {
        unsafe {
            libc::free(c.title.cast());
            c.title = xstrdup(title);
            crate::tmux_sys::tty_set_title(&mut c.tty, c.title);
        }
    }
    unsafe {
        libc::free(title.cast());

        crate::tmux_sys::format_free(ft);
    }
}

/// Set client path.
fn set_path(c: &mut Client) {
    let Some(curw) = (unsafe { c.session.as_ref().unwrap().curw.as_ref() }) else {
        return;
    };
    let mut path = unsafe {
        curw.window
            .as_ref()
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .base
            .path
            .cast_const()
    };
    if path.is_null() {
        path = c"".as_ptr();
    };
    if unsafe { c.path.is_null() || libc::strcmp(path, c.path) != 0 } {
        unsafe {
            libc::free(c.path.cast());
            c.path = xstrdup(path);
            crate::tmux_sys::tty_set_path(&mut c.tty, c.path);
        }
    }
}

/// Update cursor position and mode settings. The scroll region and attributes
/// are cleared when idle (waiting for an event) as this is the most likely time
/// a user may interrupt tmux, for example with ~^Z in ssh(1). This is a
/// compromise between excessive resets and likelihood of an interrupt.
///
/// tty_region/tty_reset/tty_update_mode already take care of not resetting
/// things that are already in their default state.
fn reset_state(c: &mut Client) {
    use crate::tmux_sys::MODE_MOUSE_ALL;

    if c.flags
        .intersects(ClientFlags::CONTROL | ClientFlags::SUSPENDED)
    {
        return;
    }

    // Disable the block flag.
    let flags = c.tty.flags & TTY_BLOCK as c_int;
    c.tty.flags &= !(TTY_BLOCK as c_int);

    // Get mode from overlay if any, else from screen.
    let mut cx: c_uint = 0;
    let mut cy: c_uint = 0;
    let s = if c.overlay_draw.is_some() {
        match c.overlay_mode {
            Some(overlay_mode) => unsafe { overlay_mode(c, c.overlay_data, &mut cx, &mut cy) },
            None => ptr::null_mut(),
        }
    } else if c.prompt_string.is_null() {
        c.pane().unwrap().screen
    } else {
        c.status.active
    };
    let mut mode: c_int = 0;
    if let Some(s) = unsafe { s.as_ref() } {
        mode = s.mode;
    }
    if unsafe { crate::tmux_sys::log_get_level() } != 0 {
        let name = unsafe { CStr::from_ptr(c.name).to_str().unwrap() };
        let mode_str = unsafe {
            CStr::from_ptr(crate::tmux_sys::screen_mode_to_string(mode))
                .to_str()
                .unwrap()
        };
        debug!("tmux_rs::server::client::reset_state: client {name} mode {mode_str}");
    }

    // Reset region and margin.
    unsafe {
        crate::tmux_sys::tty_region_off(&mut c.tty);
        crate::tmux_sys::tty_margin_off(&mut c.tty);
    }

    // Move cursor to pane cursor and offset.
    let oo = unsafe { c.session.as_ref().unwrap().options };
    if !c.prompt_string.is_null() {
        let n = unsafe { options_get_number(oo, c"status-position".as_ptr()) };
        cy = if n == 0 {
            0
        } else {
            let status_size = unsafe { status_line_size(c) };
            c.tty.sy - if status_size == 0 { 1 } else { status_size }
        };
        cx = c.prompt_cursor as u32;
    } else if c.overlay_draw.is_none() {
        let mut cursor = false;
        let mut ox: c_uint = 0;
        let mut oy: c_uint = 0;
        let mut sx: c_uint = 0;
        let mut sy: c_uint = 0;
        unsafe {
            crate::tmux_sys::tty_window_offset(&mut c.tty, &mut ox, &mut oy, &mut sx, &mut sy);
        }
        let s = unsafe { s.as_ref().unwrap() };
        let wp = c.pane().unwrap();
        if wp.xoff + s.cx >= ox
            && wp.xoff + s.cx <= ox + sx
            && wp.yoff + s.cy >= oy
            && wp.yoff + s.cy <= oy + sy
        {
            cursor = true;

            cx = wp.xoff + s.cx - ox;
            cy = wp.yoff + s.cy - oy;

            if unsafe { status_at_line(c) } == 0 {
                cy += unsafe { status_line_size(c) as u32 };
            }
        }
        if !cursor {
            mode &= !(crate::tmux_sys::MODE_CURSOR as c_int);
        }
    }
    debug!("tmux_rs::server::client::reset_state: cursor to {cx},{cy}");
    unsafe {
        crate::tmux_sys::tty_cursor(&mut c.tty, cx, cy);
    }

    // Set mouse mode if requested. To support dragging, always use button
    // mode.
    let w = unsafe {
        c.session
            .as_ref()
            .unwrap()
            .curw
            .as_ref()
            .unwrap()
            .window
            .as_ref()
            .unwrap()
    };
    if unsafe { options_get_number(oo, c"mouse".as_ptr()) } != 0 {
        if c.overlay_draw.is_none() {
            mode &= !(crate::tmux_sys::ALL_MOUSE_MODES as c_int);
            if unsafe {
                w.panes.assume_init_ref().iter().any(|loop_pane| {
                    loop_pane.as_ref().screen.as_ref().unwrap().mode & MODE_MOUSE_ALL as i32 != 0
                })
            } {
                mode |= MODE_MOUSE_ALL as c_int;
            }
        }
        if mode & (MODE_MOUSE_ALL as c_int) == 0 {
            mode |= crate::tmux_sys::MODE_MOUSE_BUTTON as c_int;
        }
    }

    // Clear bracketed paste mode if at the prompt.
    if c.overlay_draw.is_none() && !c.prompt_string.is_null() {
        mode &= !(crate::tmux_sys::MODE_BRACKETPASTE as c_int);
    }

    unsafe {
        // Set the terminal mode and reset attributes.
        tty_update_mode(&mut c.tty, mode, s);
        crate::tmux_sys::tty_reset(&mut c.tty);

        // All writing must be done, send a sync end (if it was started).
        crate::tmux_sys::tty_sync_end(&mut c.tty);
        c.tty.flags |= flags;
    }
}

/// Client functions that need to happen every loop.
pub(super) fn loop_() {
    unsafe {
        // Check for window resize. This is done before redrawing.
        for mut w in &crate::tmux_sys::windows {
            check_window_resize(w.as_mut());
        }

        // Check clients.
        for mut c in crate::tmux_sys::clients.assume_init_ref() {
            let c = c.as_mut();
            check_exit(c);
            if !c.session.is_null() {
                check_modes(c);
                check_redraw(c);
                reset_state(c);
            }
        }

        // Any windows will have been redrawn as part of clients, so clear
        // their flags now.
        for mut w in &crate::tmux_sys::windows {
            let w = w.as_mut();
            for mut wp in w.panes.assume_init_ref() {
                let wp = wp.as_mut();
                if wp.fd != -1 {
                    check_pane_resize(wp);
                    check_pane_buffer(wp);
                }
                wp.flags
                    .remove(PaneFlags::REDRAW | PaneFlags::REDRAW_SCROLLBAR);
            }
            crate::tmux_sys::check_window_name(w);
        }

        // Send theme updates.
        for w in &crate::tmux_sys::windows {
            for wp in w.as_ref().panes.assume_init_ref() {
                crate::tmux_sys::window_pane_send_theme_update(wp.as_ptr());
            }
        }
    }
}

/// Dispatch message from client.
extern "C" fn dispatch(imsg: *mut crate::tmux_sys::imsg, arg: *mut c_void) {
    use crate::protocol::Msg::*;

    let c = unsafe { (arg as *mut Client).as_mut() }.unwrap();

    if c.flags.intersects(ClientFlags::DEAD) {
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

            if !c.flags.intersects(ClientFlags::CONTROL) {
                update_latest(c);
                unsafe {
                    tty_resize(&mut c.tty);
                    tty_repeat_requests(&mut c.tty);
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

            c.set_session(ptr::null_mut());
            unsafe {
                recalculate_sizes();
                tty_close(&mut c.tty);
                crate::proc::send(&mut *c.peer, Msg::Exited, None, &[]);
            }
        }
        WakeUp | Unlock => {
            if data_len != 0 {
                panic!("bad MSG_WAKEUP size");
            }

            if !c.flags.intersects(ClientFlags::SUSPENDED) {
                return;
            }
            c.flags.remove(ClientFlags::SUSPENDED);

            if c.fd == -1 || c.session.is_null() {
                // exited already
                return;
            }

            Errno::result(unsafe { gettimeofday(&mut c.activity_time, ptr::null_mut()) })
                .expect("gettimeofday failed");

            unsafe {
                tty_start_tty(&mut c.tty);
                server_redraw_client(c);
                recalculate_sizes();

                session_update_activity(c.session, &mut c.activity_time);
            }
        }
        Shell => {
            if data_len != 0 {
                panic!("bad MSG_SHELL size");
            }

            dispatch_shell(c);
        }
        WriteReady => unsafe {
            file_write_ready(&mut c.files, imsg);
        },
        Read => unsafe {
            file_read_data(&mut c.files, imsg);
        },
        ReadDone => unsafe {
            file_read_done(&mut c.files, imsg);
        },
        _ => {}
    }
}

/// Callback when command is not allowed.
extern "C" fn read_only(
    item: *mut crate::tmux_sys::cmdq_item,
    _data: *mut c_void,
) -> crate::cmd::Retval {
    unsafe {
        crate::tmux_sys::cmdq_error(item, c"client is read-only".as_ptr());
    }
    crate::cmd::Retval::Error
}

/// Callback when command is done.
extern "C" fn command_done(
    item: *mut crate::tmux_sys::cmdq_item,
    _data: *mut c_void,
) -> crate::cmd::Retval {
    let c = unsafe { crate::tmux_sys::cmdq_get_client(item).as_mut().unwrap() };

    if !c.flags.intersects(ClientFlags::ATTACHED) {
        c.flags |= ClientFlags::EXIT;
    } else if !c.flags.intersects(ClientFlags::EXIT) {
        if c.flags.intersects(ClientFlags::CONTROL) {
            unsafe {
                control_ready(c);
            }
        }
        unsafe {
            tty_send_requests(&mut c.tty);
        }
    }
    crate::cmd::Retval::Normal
}

/// Handle command message.
fn dispatch_command(c: &mut Client, imsg: &IMsg) {
    if c.flags.intersects(ClientFlags::EXIT) {
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
    let error = |c: &mut Client, cause: &str| {
        unsafe {
            cmdq_append(c, crate::cmd::queue::get_error(cause));
        }

        c.flags |= ClientFlags::EXIT;
    };
    let Some(args) =
        crate::cmd::unpack_argv(unsafe { core::slice::from_raw_parts(buf, len) }, argc)
    else {
        error(c, "command too long");
        return;
    };

    let cmdlist = if argc == 0 {
        unsafe {
            cmd_list_copy(
                options_get_command(global_options, c"default-client-command".as_ptr()),
                0,
                ptr::null_mut(),
            )
        }
    } else {
        let mut values = crate::args::from_vector(args.iter());
        let pr = unsafe {
            cmd_parse_from_arguments(
                values.as_mut_ptr(),
                argc.try_into().unwrap(),
                ptr::null_mut(),
            )
            .as_ref()
            .unwrap()
        };

        match pr.status {
            crate::tmux_sys::cmd_parse_status_CMD_PARSE_ERROR => {
                unsafe {
                    let err = CStr::from_ptr(pr.error).to_str().unwrap();
                    error(c, err);
                    libc::free(pr.error.cast());
                }
                return;
            }
            crate::tmux_sys::cmd_parse_status_CMD_PARSE_SUCCESS => pr.cmdlist,
            _ => {
                return;
            }
        }
    };

    let new_item = if c.flags.intersects(ClientFlags::READ_ONLY)
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
fn dispatch_identify(c: &mut Client, imsg: &IMsg) {
    use crate::protocol::Msg::*;

    if c.flags.intersects(ClientFlags::IDENTIFIED) {
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
            c.flags |= ClientFlags::from_bits_retain(flags as u64);
            debug!("client {:?} IDENTIFY_FLAGS {:#x}", c_ptr, flags);
        }
        IdentifyLongFlags => {
            if data_len != mem::size_of::<u64>() {
                panic!("bad MSG_IDENTIFY_LONGFLAGS size");
            }
            let longflags = unsafe { ptr::read_unaligned(data as *const u64) };
            c.flags |= ClientFlags::from_bits_retain(longflags);
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
    c.flags |= ClientFlags::IDENTIFIED;

    unsafe {
        if *c.ttyname != 0 {
            c.name = xstrdup(c.ttyname);
        } else {
            xasprintf(
                (&raw mut c.name).cast(),
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
        if c.flags.intersects(ClientFlags::CONTROL) {
            control_start(c);
        } else if c.fd != -1 {
            if tty_init(&mut c.tty, c) != 0 {
                libc::close(c.fd);
                c.fd = -1;
            } else {
                tty_resize(&mut c.tty);
                c.flags |= ClientFlags::TERMINAL;
            }
            libc::close(c.out_fd);
            c.out_fd = -1;
        }
    }

    // If this is the first client, load configuration files. Any later
    // clients are allowed to continue with their command even if the
    // config has not been loaded - they might have been run from inside it
    unsafe {
        if !c.flags.intersects(ClientFlags::EXIT)
            && cfg_finished == 0
            && clients.assume_init_ref().front() == Some(NonNull::from_mut(c))
        {
            start_cfg();
        }
    }
}

/// Handle shell message.
fn dispatch_shell(c: &mut Client) {
    unsafe {
        let mut shell = options_get_string(global_s_options, c"default-shell".as_ptr());
        if checkshell(shell) == 0 {
            shell = _PATH_BSHELL.as_ptr();
        }
        crate::proc::send(
            &mut *c.peer,
            Msg::Shell,
            None,
            CStr::from_ptr(shell).to_bytes_with_nul(),
        );

        proc_kill_peer(c.peer);
    }
}

impl Client {
    /// Set client session.
    pub(crate) fn set_session(&mut self, s: *mut crate::tmux_sys::session) {
        use crate::tmux_sys::window_update_focus;

        let old = self.session;

        if s.is_null() || self.session != s {
            self.last_session = s;
        }
        self.session = s;
        self.flags |= ClientFlags::FOCUSED;

        unsafe {
            if let Some(old) = old.as_mut()
                && let Some(curw) = old.curw.as_mut()
            {
                window_update_focus(curw.window);
            }
            if let Some(s) = s.as_mut() {
                recalculate_sizes();
                window_update_focus(s.curw.as_mut().unwrap().window);
                session_update_activity(s, ptr::null_mut());
                crate::tmux_sys::session_theme_changed(s);
                gettimeofday(&mut s.last_attached_time, ptr::null_mut());
                {
                    let curw = s.curw.as_mut().unwrap_unchecked();
                    curw.flags &= !crate::tmux_sys::WINLINK_ALERTFLAGS as i32;
                    curw.window.as_mut().unwrap().latest = (&raw mut *self).cast();
                }
                crate::tmux_sys::alerts_check_session(s);
                crate::tmux_sys::tty_update_client_offset(self);
                crate::tmux_sys::status_timer_start(self);
                crate::tmux_sys::notify_client(c"client-session-changed".as_ptr(), self);
                server_redraw_client(self);
            }

            crate::tmux_sys::server_check_unattached();
        }
        super::update_socket();
    }

    /// Get client window.
    pub(crate) fn get_client_window(&mut self, id: c_uint) -> Option<&mut client_window> {
        unsafe {
            let mut cw = MaybeUninit::<client_window>::uninit();
            cw.as_mut_ptr()
                .byte_add(offset_of!(client_window, window))
                .cast::<c_uint>()
                .write(id);
            self.windows
                .get(cw.assume_init_ref())
                .map(|mut non_null| non_null.as_mut())
        }
    }

    /// Get client active pane.
    pub(crate) fn pane(&mut self) -> Option<&mut Pane> {
        let w = unsafe {
            self.session
                .as_mut()?
                .curw
                .as_mut()
                .unwrap()
                .window
                .as_mut()
                .unwrap()
        };

        unsafe {
            if self.flags.intersects(ClientFlags::ACTIVE_PANE)
                && let Some(cw) = self.get_client_window(w.id)
            {
                cw.pane
            } else {
                w.active
            }
            .as_mut()
        }
    }
}
