use core::ffi::{CStr, c_char, c_int, c_longlong, c_uint};

use bitflags::bitflags;

mod compat;
mod options;
mod tmux;

pub use compat::{getptmfd, pledge};
pub use options::{Options, OptionsEntry};
pub use tmux::get_shell;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum ModeKey {
    Emacs,
    Vi,
}

/// Option table entries.
#[repr(C)]
pub enum OptionsTableType {
    String,
    Number,
    Key,
    Colour,
    Flag,
    Choice,
    Command,
}

bitflags! {
    #[repr(C)]
    pub struct OptionsTableScope: c_int {
        const NONE = 0;
        const SERVER = 1;
        const SESSION = 1 << 1;
        const WINDOW = 1 << 2;
        const PANE = 1 << 3;
    }
}

#[repr(C)]
pub struct OptionsTableEntry {
    pub name: *const c_char,
    alternative_name: *const c_char,
    entry_type: OptionsTableType,
    pub scope: OptionsTableScope,
    flags: c_int,

    minimum: c_uint,
    maximum: c_uint,
    choices: *const *const c_char,

    default_str: *const c_char,
    default_num: c_longlong,
    default_arr: *const *const c_char,

    separator: *const c_char,
    pattern: *const c_char,

    text: *const c_char,
    unit: *const c_char,
}

/// Skip until end.
pub fn format_skip_rust(bs: &[u8], end: &[u8]) -> Option<usize> {
    let mut brackets = 0;
    let mut prev_is_hash = false;
    for (i, b) in bs.iter().enumerate() {
        if prev_is_hash {
            prev_is_hash = false;
            if b",#{}:".contains(b) {
                if *b == b'{' {
                    brackets += 1;
                }
                continue;
            }
        }

        if *b == b'}' {
            brackets -= 1;
        }
        prev_is_hash = *b == b'#';

        if end.contains(b) && brackets == 0 {
            return Some(i);
        }
    }

    None
}

#[unsafe(no_mangle)]
pub extern "C" fn format_skip(s: *const c_char, end: *const c_char) -> *const c_char {
    match format_skip_rust(
        unsafe { CStr::from_ptr(s) }.to_bytes(),
        unsafe { CStr::from_ptr(end) }.to_bytes(),
    ) {
        Some(i) => unsafe { s.add(i) },
        None => std::ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn skip_hash_escape() {
        // Make sure a hash only escape its next character so in this case the
        // second hash does not escape the third character.
        assert_eq!(crate::format_skip_rust(b"##,", b","), Some(2));
    }
}
