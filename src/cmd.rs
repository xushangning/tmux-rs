use core::{
    ffi::{c_char, c_int, c_uint},
    marker::{PhantomData, PhantomPinned},
};

use bitflags::bitflags;

use crate::arguments::Value;

#[repr(C)]
pub(crate) struct CmdList {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
#[allow(dead_code)]
pub(crate) enum ParseStatus {
    Error,
    Success,
}

#[repr(C)]
pub(crate) struct ParseResult {
    pub(crate) status: ParseStatus,
    pub(crate) cmd_list: *mut CmdList,
    pub(crate) error: *mut c_char,
}

#[repr(C)]
pub(crate) struct ParseInput {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

bitflags! {
    pub(crate) struct Flag: c_int {
        const START_SERVER = 1;
    }
}

#[link(name = "tmux")]
unsafe extern "C" {
    pub(crate) fn cmd_list_free(cmd_list: *mut CmdList);
    pub(crate) fn cmd_list_any_have(cmd_list: *mut CmdList, flag: c_int) -> c_int;

    pub(crate) fn cmd_parse_from_arguments(
        args_value: *mut Value,
        count: c_uint,
        pi: *mut ParseInput,
    ) -> *mut ParseResult;
    pub(crate) fn cmd_pack_argv(
        argc: c_int,
        argv: *mut *mut c_char,
        buf: *mut c_char,
        len: usize,
    ) -> c_int;
}
