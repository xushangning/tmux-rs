use core::{
    ffi::{c_char, c_int},
    marker::{PhantomData, PhantomPinned},
};
use std::{env, ffi::CString, os::unix::ffi::OsStrExt, path::PathBuf, ptr};

use clap::Parser;

use tmux_rs::{Options, OptionsEntry, OptionsTableEntry, OptionsTableScope};

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

    /// server options
    static mut global_options: *mut Options;
    /// session options
    static mut global_s_options: *mut Options;
    /// window options
    static mut global_w_options: *mut Options;
    fn options_create(parent: *mut Options) -> *mut Options;
    fn options_default(oo: *mut Options, oe: *const OptionsTableEntry) -> *mut OptionsEntry;
    fn options_set_string(
        oo: *mut Options,
        name: *const c_char,
        append: c_int,
        fmt: *const c_char,
        ...
    ) -> *mut OptionsEntry;

    // https://github.com/rust-lang/rust/issues/54450
    static options_table: OptionsTableEntry;

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

    unsafe {
        global_options = options_create(ptr::null_mut());
        global_s_options = options_create(ptr::null_mut());
        global_w_options = options_create(ptr::null_mut());
        let mut oe_ptr = &options_table as *const OptionsTableEntry;
        loop {
            let oe = oe_ptr.as_ref().unwrap();
            if oe.name.is_null() {
                break;
            }

            if oe.scope.contains(OptionsTableScope::SERVER) {
                options_default(global_options, oe_ptr);
            } else if oe.scope.contains(OptionsTableScope::SESSION) {
                options_default(global_s_options, oe_ptr);
            } else if oe.scope.contains(OptionsTableScope::WINDOW) {
                options_default(global_w_options, oe_ptr);
            }

            oe_ptr = oe_ptr.add(1);
        }
    }

    // The default shell comes from SHELL or from the user's passwd entry
    // if available.
    if let Some(shell) = tmux_rs::get_shell() {
        unsafe {
            options_set_string(
                global_s_options,
                c"default-shell".as_ptr(),
                0,
                c"%s".as_ptr(),
                CString::new(shell.as_os_str().as_bytes()).unwrap().as_ptr(),
            );
        }
    }

    dbg!(unsafe { osdep_event_init() });
}
