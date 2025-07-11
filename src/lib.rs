use std::ffi::{CStr, c_char};

mod compat;
mod tmux;

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
