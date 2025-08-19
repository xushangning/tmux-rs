//! IPC file handling. Both client and server use the same data structures
//! (client_file and client_files) to store list of active files. Most functions
//! are for use either in client or server but not both.

use core::{
    ffi::c_int,
    mem::{self, MaybeUninit, offset_of},
};

use log::debug;

use crate::{
    compat::imsg::IMsg,
    tmux_sys::{
        bufferevent_write, client_file, client_files, client_files_RB_FIND, msg_write_data,
    },
};

/// Handle a file write data message (client).
pub(crate) fn write_data(files: &mut client_files, imsg: &mut IMsg) {
    let msg = imsg.data.cast::<msg_write_data>();
    let msg_len = imsg.hdr.len as usize - crate::compat::imsg::HEADER_SIZE;
    if msg_len < unsafe { mem::size_of_val_raw(msg) } {
        panic!("bad MSG_WRITE size");
    }
    let mut find = MaybeUninit::<client_file>::uninit();
    unsafe {
        find.as_mut_ptr()
            .byte_add(offset_of!(client_file, stream))
            .cast::<c_int>()
            .write(msg.as_mut().unwrap().stream);
    }
    let Some(cf) = (unsafe { client_files_RB_FIND(files, find.as_mut_ptr()).as_mut() }) else {
        panic!("unknown stream number");
    };
    let size = msg_len - unsafe { mem::size_of_val_raw(msg) };
    debug!("write {size} to file {}", cf.stream);

    if !cf.event.is_null() {
        unsafe {
            bufferevent_write(cf.event, msg.add(1).cast(), size);
        }
    }
}
