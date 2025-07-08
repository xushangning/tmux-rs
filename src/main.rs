use core::{
    ffi::{c_char, c_int},
    marker::{PhantomData, PhantomPinned},
};
use std::{env, ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf};

use clap::Parser;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(short = '2')]
    force_256: bool,

    #[arg(short = 'c')]
    shell_command: Option<String>,

    #[arg(short = 'D')]
    no_daemon: bool,

    #[arg(short = 'C', action = clap::ArgAction::Count)]
    control: u8,

    #[arg(short = 'f')]
    config: Option<PathBuf>,

    #[arg(short = 'l')]
    login: bool,

    #[arg(short = 'L')]
    socket_name: Option<String>,

    #[arg(short = 'N')]
    no_start_server: bool,

    #[arg(short = 'S', value_name = "SOCKET_PATH")]
    path: Option<PathBuf>,

    #[arg(short = 'T')]
    features: Option<String>,

    #[arg(short = 'u')]
    utf_8: bool,

    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

#[repr(C)]
struct Environ {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
struct EventBase {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    static environ: *const *const c_char;

    static mut global_environ: *mut Environ;
    fn environ_create() -> *mut Environ;
    fn environ_put(env: *mut Environ, var: *const c_char, flags: c_int);
    fn environ_set(env: *mut Environ, name: *const c_char, flags: c_int, fmt: *const c_char, ...);

    fn log_add_level();

    fn osdep_event_init() -> *mut EventBase;
}

fn main() {
    unsafe {
        global_environ = environ_create();
        let mut var = environ;
        while !(*var).is_null() {
            environ_put(global_environ, *var, 0);
            var = var.add(1);
        }
        if let Ok(cwd) = env::current_dir() {
            environ_set(
                global_environ,
                c"PWD".as_ptr(),
                0,
                c"%s".as_ptr(),
                CString::new(cwd.into_os_string().as_bytes())
                    .unwrap()
                    .as_ptr(),
            );
        }
    }

    let cli = Cli::parse();
    for _ in 0..cli.verbose {
        unsafe {
            log_add_level();
        }
    }

    dbg!(unsafe { osdep_event_init() });
}
