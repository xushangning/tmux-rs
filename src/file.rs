//! IPC file handling. Both client and server use the same data structures
//! (client_file and client_files) to store list of active files. Most functions
//! are for use either in client or server but not both.

use core::{
    ffi::c_int,
    mem::{self, MaybeUninit, offset_of},
};

use log::debug;

use crate::{
    compat::{imsg::IMsg, tree::rb},
    tmux_sys::{bufferevent_write, client_file, client_files, msg_write_data},
};

impl Ord for client_file {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.stream.cmp(&other.stream)
    }
}

impl PartialOrd for client_file {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for client_file {
    fn eq(&self, other: &Self) -> bool {
        self.stream == other.stream
    }
}

impl Eq for client_file {}

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
    let cf = unsafe {
        mem::transmute::<_, &rb::Head<client_file, { offset_of!(client_file, entry) }>>(files)
            .get(find.assume_init_ref())
            .expect("unknown stream number")
            .as_mut()
    };
    let size = msg_len - unsafe { mem::size_of_val_raw(msg) };
    debug!("write {size} to file {}", cf.stream);

    if !cf.event.is_null() {
        unsafe {
            bufferevent_write(cf.event, msg.add(1).cast(), size);
        }
    }
}
