use core::ffi::c_int;

use bitflags::bitflags;

bitflags! {
    #[derive(Default)]
    pub(crate) struct ModeFlags: c_int {
        const CURSOR = 1;
        const INSERT = 1 << 1;
        const KCURSOR = 1 << 2;
        const KKEYPAD = 1 << 3;
        const WRAP = 1 << 4;
        const MOUSE_STANDARD = 1 << 5;
        const MOUSE_BUTTON = 1 << 6;
        const CURSOR_BLINKING = 1 << 7;
        const MOUSE_UTF8 = 1 << 8;
        const MOUSE_SGR = 1 << 9;
        const BRACKET_PASTE = 1 << 10;
        const FOCUS_ON = 1 << 11;
        const MOUSE_ALL = 1 << 12;
        const ORIGIN = 1 << 13;
        const CRLF = 1 << 14;
        const KEYS_EXTENDED = 1 << 15;
        const CURSOR_VERY_VISIBLE = 1 << 16;
        const CURSOR_BLINKING_SET = 1 << 17;
        const KEYS_EXTENDED_2 = 1 << 18;
        const THEME_UPDATES = 1 << 19;

        const ALL_MOUSE_MODES = Self::MOUSE_STANDARD.bits() | Self::MOUSE_BUTTON.bits() | Self::MOUSE_ALL.bits();
        const MOTION_MOUSE_MODES = Self::MOUSE_BUTTON.bits() | Self::MOUSE_ALL.bits();
        const CURSOR_MODES = Self::CURSOR.bits() | Self::CURSOR_BLINKING.bits() | Self::CURSOR_VERY_VISIBLE.bits();
        const EXTENDED_KEY_MODES = Self::KEYS_EXTENDED.bits() | Self::KEYS_EXTENDED_2.bits();
    }
}
