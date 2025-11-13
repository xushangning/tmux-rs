use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    mem, ptr,
};
use std::{ffi::CString, mem::MaybeUninit};

use libc::time_t;
use log::debug;
use mbox::MBox;

use crate::{
    ClientFlags,
    compat::queue::tailq,
    tmux_sys::{
        cmd_find_state, cmd_list, cmdq_cb, cmdq_list, cmdq_new_state, cmdq_state, xasprintf,
        xcalloc,
    },
};

/// Command queue item type.
#[repr(C)]
enum ItemType {
    #[allow(dead_code)]
    Command,
    Callback,
}

/// Command queue item.
#[repr(C)]
pub struct Item {
    name: *mut c_char,
    queue: *mut cmdq_list,
    next: *mut Item,

    client: *mut crate::tmux_sys::client,
    target_client: *mut crate::tmux_sys::client,

    type_: ItemType,
    group: c_uint,

    number: c_uint,
    time: time_t,

    flags: c_int,

    state: *mut cmdq_state,
    source: cmd_find_state,
    target: cmd_find_state,

    cmdlist: *mut cmd_list,
    cmd: *mut crate::tmux_sys::cmd,

    cb: cmdq_cb,
    data: *mut c_void,

    entry: tailq::Entry<Item>,
}

/// Get a callback for the command queue.
pub(crate) fn get_callback1(name: &str, cb: cmdq_cb, data: *mut c_void) -> MBox<Item> {
    let mut ret =
        unsafe { MBox::from_raw(xcalloc(1, mem::size_of::<Item>()).cast::<MaybeUninit<Item>>()) };
    let item = ret.as_mut_ptr();
    unsafe {
        xasprintf(
            &mut (*item).name,
            c"[%s/%p]".as_ptr(),
            CString::new(name.as_bytes()).unwrap().as_ptr(),
            item,
        );
        (*item).type_ = ItemType::Callback;

        (*item).group = 0;
        (*item).state = cmdq_new_state(ptr::null_mut(), ptr::null_mut(), 0);

        (*item).cb = cb;
        (*item).data = data;

        ret.assume_init()
    }
}

/// Generic error callback.
extern "C" fn error_callback(item: *mut Item, data: *mut c_void) -> crate::cmd::Retval {
    error(unsafe { item.as_mut().unwrap() }, &mut unsafe {
        Box::from_raw(data.cast::<Box<str>>())
    });
    crate::cmd::Retval::Normal
}

/// Get an error callback for the command queue.
pub(crate) fn get_error(error: &str) -> MBox<Item> {
    get_callback1(
        "cmdq_error_callback",
        Some(error_callback),
        Box::into_raw(Box::new(error.to_owned().into_boxed_str())).cast(),
    )
}

/// Show error from command.
pub(crate) fn error(item: &mut Item, msg: &mut str) {
    use crate::tmux_sys::{
        cfg_add_cause, cmd_get_source, control_write, file_error, server_add_message,
        status_message_set, utf8_sanitize,
    };

    debug!("tmux_rs::cmd::queue::error: {msg}");

    let msg = CString::new(&*msg).unwrap();
    match unsafe { item.client.as_mut() } {
        None => {
            let mut file = MaybeUninit::<*const c_char>::uninit();
            let mut line = MaybeUninit::<c_uint>::uninit();
            unsafe {
                cmd_get_source(item.cmd, file.as_mut_ptr(), line.as_mut_ptr());
                cfg_add_cause(
                    c"%s:%u: %s".as_ptr(),
                    file.assume_init(),
                    line.assume_init(),
                    msg.as_ptr(),
                );
            }
        }
        Some(c) => {
            if c.session.is_null() || c.flags.intersects(ClientFlags::CONTROL) {
                unsafe {
                    server_add_message(c"%s message: %s".as_ptr(), c.name, msg.as_ptr());
                }
                let mut msg_ptr = msg.as_ptr();
                let mut changed = false;
                if !c.flags.intersects(ClientFlags::UTF8) {
                    msg_ptr = unsafe { utf8_sanitize(msg_ptr) };
                    changed = true;
                }
                if c.flags.intersects(ClientFlags::CONTROL) {
                    unsafe {
                        control_write(c, c"%s".as_ptr(), msg_ptr);
                    }
                } else {
                    unsafe {
                        file_error(c, c"%s\n".as_ptr(), msg_ptr);
                    }
                }
                c.retval = 1;
                if changed {
                    unsafe {
                        libc::free(msg_ptr.cast_mut().cast());
                    }
                }
            } else {
                unsafe {
                    let msg = msg.into_raw();
                    msg.write(libc::toupper(msg.read() as c_int).try_into().unwrap());
                    let msg = CString::from_raw(msg);
                    status_message_set(c, -1, 1, 0, 0, c"%s".as_ptr(), msg.as_ptr());
                }
            }
        }
    }
}
