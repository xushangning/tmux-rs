use core::{
    ffi::{c_char, c_int, c_void},
    marker::{PhantomData, PhantomPinned},
};

use crate::{imsg::IMsg, protocol::Msg};

#[repr(C)]
pub(crate) struct Proc {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
pub(crate) struct Peer {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn proc_start(name: *const c_char) -> *mut Proc;
    pub(crate) fn proc_exit(tp: *mut Proc);
    pub(crate) fn proc_send(
        peer: *mut Peer,
        msgtype: Msg,
        fd: c_int,
        buf: *const c_void,
        len: usize,
    ) -> c_int;
    pub(crate) fn proc_loop(tp: *mut Proc, loopcb: Option<extern "C" fn() -> c_int>);
    pub(crate) fn proc_set_signals(tp: *mut Proc, signalcb: extern "C" fn(c_int));
    pub(crate) fn proc_clear_signals(tp: *mut Proc, defaults: c_int);
    pub(crate) fn proc_add_peer(
        tp: *mut Proc,
        fd: c_int,
        dispatchcb: extern "C" fn(*mut IMsg, *mut c_void),
        arg: *mut c_void,
    ) -> *mut Peer;
    pub(crate) fn proc_flush_peer(tp: *mut Peer);
}
