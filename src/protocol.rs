use core::ffi::c_int;

use bytemuck::NoUninit;

/// Protocol version.
pub(crate) const VERSION: i32 = 8;

/// Message types.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum Msg {
    Version = 12,

    IdentifyFlags = 100,
    IdentifyTerm,
    IdentifyTtyName,
    IdentifyOldCwd, // unused
    IdentifyStdin,
    IdentifyEnviron,
    IdentifyDone,
    IdentifyClientPid,
    IdentifyCwd,
    IdentifyFeatures,
    IdentifyStdout,
    IdentifyLongFlags,
    IdentifyTermInfo,

    Command = 200,
    Detach,
    DetachKill,
    Exit,
    Exited,
    Exiting,
    Lock,
    Ready,
    Resize,
    Shell,
    Shutdown,
    OldStderr, // unused
    OldStdin,  // unused
    OldStdout, // unused
    Suspend,
    Unlock,
    WakeUp,
    Exec,
    Flags,

    ReadOpen = 300,
    Read,
    ReadDone,
    WriteOpen,
    Write,
    WriteReady,
    WriteClose,
    ReadCancel,
}

/// Message data.
///
/// Don't forget to bump PROTOCOL_VERSION if any of these change!
#[repr(C)]
#[derive(NoUninit, Clone, Copy)]
pub(crate) struct MsgCommand {
    pub(crate) argc: c_int,
} // followed by packed argv
