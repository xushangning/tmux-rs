use core::{
    ffi::{c_char, c_int, c_void},
    marker::{PhantomData, PhantomPinned},
};

use crate::{compat::tree::RbHead, imsg::IMsg, libevent::EvBuffer, proc::Peer};

#[repr(C)]
pub(crate) struct ClientFile {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

pub(crate) type ClientFiles = RbHead<ClientFile>;

pub(crate) type ClientFileCb =
    extern "C" fn(*mut crate::Client, *const c_char, c_int, c_int, *mut EvBuffer, *mut c_void);

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn file_write_left(client_files: *mut ClientFiles) -> c_int;
    pub(crate) fn file_read_open(
        files: *mut ClientFiles,
        peer: *mut Peer,
        imsg: *mut IMsg,
        allow_streams: c_int,
        close_received: c_int,
        cb: ClientFileCb,
        cbdata: *mut c_void,
    );
    pub(crate) fn file_read_cancel(files: *mut ClientFiles, imsg: *mut IMsg);
    pub(crate) fn file_write_open(
        files: *mut ClientFiles,
        peer: *mut Peer,
        imsg: *mut IMsg,
        allow_streams: c_int,
        close_received: c_int,
        cb: ClientFileCb,
        cbdata: *mut c_void,
    );
    pub(crate) fn file_write_data(files: *mut ClientFiles, imsg: *mut IMsg);
    pub(crate) fn file_write_close(files: *mut ClientFiles, imsg: *mut IMsg);
}
