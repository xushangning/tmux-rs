use core::mem::{self, MaybeUninit};
use std::ffi::CString;

use crate::tmux_sys::{args_type_ARGS_COMMANDS, args_type_ARGS_STRING, args_value};

impl Drop for args_value {
    /// Free a value.
    fn drop(&mut self) {
        #[allow(non_upper_case_globals)]
        match self.type_ {
            args_type_ARGS_STRING => unsafe {
                mem::drop(CString::from_raw(self.__bindgen_anon_1.string));
            },
            args_type_ARGS_COMMANDS => unsafe {
                crate::tmux_sys::cmd_list_free(self.__bindgen_anon_1.cmdlist);
            },
            _ => {}
        }
        unsafe {
            libc::free(self.cached.cast());
        }
    }
}

/// Convert arguments from vector.
pub(crate) fn from_vector<'a>(args: impl Iterator<Item = &'a String>) -> Vec<args_value> {
    args.map(|arg| {
        // The original tmux code doesn't explicitly requires memory
        // returned by malloc to be zeroed. However, it never initializes
        // the args_value::cached field, so if malloc returned a non-zeroed
        // memory, the program will crash when freeing the pointer in
        // args_value::cached in the args_free_value() function.
        let mut value = unsafe { MaybeUninit::<args_value>::zeroed().assume_init() };
        value.type_ = args_type_ARGS_STRING;
        value.__bindgen_anon_1.string = CString::new(arg.as_bytes()).unwrap().into_raw();
        value
    })
    .collect()
}
