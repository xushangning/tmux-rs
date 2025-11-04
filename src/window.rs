use core::{
    ffi::{c_char, c_int, c_uint},
    mem::{MaybeUninit, offset_of},
};

use bitflags::bitflags;

use crate::{
    compat::{queue::tailq, tree::rb},
    tmux_sys::{
        bufferevent, colour_palette, grid_cell, input_ctx, layout_cell, options, window_mode_entry,
        window_pane_offset, window_pane_resizes,
    },
};

bitflags! {
    #[repr(C)]
    pub(crate) struct PaneFlags: c_int {
        const REDRAW = 1;
        const EXITED = 1 << 8;
        const STATUS_READY = 1 << 9;
        const REDRAW_SCROLLBAR = 1 << 15;
    }
}

#[repr(C)]
pub struct Pane {
    pub(crate) id: c_uint,
    active_point: c_uint,
    window: *mut crate::tmux_sys::window,
    options: *mut options,
    layout_cell: *mut layout_cell,
    saved_layout_cell: *mut layout_cell,
    sx: c_uint,
    sy: c_uint,
    pub(crate) xoff: c_uint,
    pub(crate) yoff: c_uint,
    pub(crate) flags: PaneFlags,
    sb_slider_y: c_uint,
    sb_slider_h: c_uint,
    argc: c_int,
    argv: *mut *mut c_char,
    shell: *mut c_char,
    cwd: *mut c_char,
    pub(crate) pid: libc::pid_t,
    tty: [c_char; 32],
    pub(crate) status: c_int,
    dead_time: libc::timeval,
    pub(crate) fd: c_int,
    pub(crate) event: *mut bufferevent,
    pub(crate) offset: window_pane_offset,
    pub(crate) base_offset: usize,
    pub(crate) resize_queue: window_pane_resizes,
    pub(crate) resize_timer: crate::tmux_sys::event,
    ictx: *mut input_ctx,
    cached_gc: grid_cell,
    cached_active_gc: grid_cell,
    palette: colour_palette,
    pub(crate) pipe_fd: c_int,
    pipe_event: *mut bufferevent,
    pub(crate) pipe_offset: window_pane_offset,
    pub(crate) screen: *mut crate::tmux_sys::screen,
    pub(crate) base: crate::tmux_sys::screen,
    status_screen: crate::tmux_sys::screen,
    status_size: usize,
    pub(crate) modes:
        MaybeUninit<tailq::Head<window_mode_entry, { offset_of!(window_mode_entry, entry) }>>,
    searchstr: *mut c_char,
    searchregex: c_int,
    border_gc_set: c_int,
    border_gc: grid_cell,
    control_bg: c_int,
    control_fg: c_int,
    scrollbar_style: crate::tmux_sys::style,
    pub(crate) entry: tailq::Entry<Self>,
    pub(crate) sentry: tailq::Entry<Self>,
    pub(crate) tree_entry: rb::Entry<Self>,
}
