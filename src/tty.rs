use core::ffi::{c_int, c_uint};

use bitflags::bitflags;

use crate::{
    Client,
    tmux_sys::{evbuffer, grid_cell, mouse_event},
};

bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(crate) struct TtyFlags: c_int {
        const NO_CURSOR = 1;
        const FREEZE = 1 << 1;
        const TIMER = 1 << 2;
        const NO_BLOCK = 1 << 3;
        const STARTED = 1 << 4;
        const OPENED = 1 << 5;
        const OSC52_QUERY = 1 << 6;
        const BLOCK = 1 << 7;
        const HAVE_DA = 1 << 8;
        const HAVE_XDA = 1 << 9;
        const SYNCING = 1 << 10;
        const HAVE_DA2 = 1 << 11;
        const WINSIZE_QUERY = 1 << 12;
        const HAVE_FG = 1 << 13;
        const HAVE_BG = 1 << 14;
        const ALL_REQUEST_FLAGS = Self::HAVE_DA.bits()
            | Self::HAVE_DA2.bits()
            | Self::HAVE_XDA.bits()
            | Self::HAVE_FG.bits()
            | Self::HAVE_BG.bits();
    }
}

#[repr(C)]
pub struct Tty {
    pub(crate) client: *mut Client,
    pub(crate) start_timer: crate::tmux_sys::event,
    pub(crate) clipboard_timer: crate::tmux_sys::event,
    pub(crate) last_requests: libc::time_t,
    pub(crate) sx: c_uint,
    pub(crate) sy: c_uint,
    pub(crate) xpixel: c_uint,
    pub(crate) ypixel: c_uint,
    pub(crate) cx: c_uint,
    pub(crate) cy: c_uint,
    pub(crate) cstyle: crate::tmux_sys::screen_cursor_style,
    pub(crate) ccolour: c_int,
    pub(crate) oflag: c_int,
    pub(crate) oox: c_uint,
    pub(crate) ooy: c_uint,
    pub(crate) osx: c_uint,
    pub(crate) osy: c_uint,
    pub(crate) mode: c_int,
    pub(crate) fg: c_int,
    pub(crate) bg: c_int,
    pub(crate) rlower: c_uint,
    pub(crate) rupper: c_uint,
    pub(crate) rleft: c_uint,
    pub(crate) rright: c_uint,
    pub(crate) event_in: crate::tmux_sys::event,
    pub(crate) in_: *mut evbuffer,
    pub(crate) event_out: crate::tmux_sys::event,
    pub(crate) out: *mut evbuffer,
    pub(crate) timer: crate::tmux_sys::event,
    pub(crate) discarded: usize,
    pub(crate) tio: crate::tmux_sys::termios,
    pub(crate) cell: grid_cell,
    pub(crate) last_cell: grid_cell,
    pub(crate) flags: TtyFlags,
    pub(crate) term: *mut crate::tmux_sys::tty_term,
    pub(crate) mouse_last_x: c_uint,
    pub(crate) mouse_last_y: c_uint,
    pub(crate) mouse_last_b: c_uint,
    pub(crate) mouse_drag_flag: c_int,
    pub(crate) mouse_scrolling_flag: c_int,
    pub(crate) mouse_slider_mpos: c_int,
    pub(crate) mouse_drag_update:
        Option<unsafe extern "C" fn(arg1: *mut Client, arg2: *mut mouse_event)>,
    pub(crate) mouse_drag_release:
        Option<unsafe extern "C" fn(arg1: *mut Client, arg2: *mut mouse_event)>,
    pub(crate) key_timer: crate::tmux_sys::event,
    pub(crate) key_tree: *mut crate::tmux_sys::tty_key,
}
