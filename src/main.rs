use core::{
    ffi::{CStr, c_char, c_int, c_longlong},
    marker::{PhantomData, PhantomPinned},
};
use std::{
    env,
    ffi::CString,
    fs::{self, DirBuilder},
    io::ErrorKind,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process, ptr,
};

use anyhow::{Context, Result, anyhow};
use clap::{CommandFactory, Parser};
use libc::{self, CODESET, LC_CTYPE, LC_TIME};
use nix::unistd::Uid;

use tmux_rs::{
    Client, ModeKey, Options, OptionsEntry, OptionsTableEntry, OptionsTableScope, TMUX_CONF,
    TMUX_SOCK_PERM,
};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(short = '2')]
    force_256: bool,

    #[arg(short = 'c', value_name = "SHELL_COMMAND")]
    sh_command: Option<String>,

    #[arg(short = 'D')]
    no_daemon: bool,

    #[arg(short = 'C', action = clap::ArgAction::Count)]
    control: u8,

    #[arg(short = 'f')]
    config: Vec<PathBuf>,

    #[arg(short = 'l')]
    login: bool,

    #[arg(short = 'L', value_name = "SOCKET_NAME")]
    label: Option<String>,

    #[arg(short = 'N')]
    no_start_server: bool,

    #[arg(short = 'S', value_name = "SOCKET_PATH")]
    path: Option<PathBuf>,

    #[arg(short = 'T')]
    features: Vec<String>,

    #[arg(short = 'u')]
    utf_8: bool,

    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

#[repr(C)]
struct Environ {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[repr(C)]
struct EnvironEntry {
    name: *const c_char,
    value: *const c_char,
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
    fn options_set_number(
        oo: *mut Options,
        name: *const c_char,
        value: c_longlong,
    ) -> *mut OptionsEntry;

    // https://github.com/rust-lang/rust/issues/54450
    static options_table: OptionsTableEntry;

    static mut global_environ: *mut Environ;
    fn environ_create() -> *mut Environ;
    fn environ_put(env: *mut Environ, var: *const c_char, flags: c_int);
    fn environ_set(env: *mut Environ, name: *const c_char, flags: c_int, fmt: *const c_char, ...);
    fn environ_find(env: *mut Environ, name: *const c_char) -> *const EnvironEntry;

    static mut socket_path: *const c_char;
    static mut ptm_fd: c_int;
    static mut shell_command: *const c_char;

    fn tty_add_features(feat: *mut c_int, s: *const c_char, separators: *const c_char);

    fn log_add_level();

    fn osdep_event_init() -> *mut EventBase;
    fn client_main(
        event_base: *mut EventBase,
        argc: c_int,
        argv: *mut *mut c_char,
        flags: u64,
        fd: c_int,
    ) -> c_int;

    static mut cfg_quiet: c_int;
    static mut cfg_files: *mut *mut c_char;
    static mut cfg_nfiles: c_int;
}

fn expand_path(path: &str, home: Option<&Path>) -> Option<PathBuf> {
    if path.starts_with("~/") {
        return Some(home?.join(&path[2..]));
    }

    if path.starts_with('$') {
        let end = path.find('/').unwrap_or(path.len());
        let name = &path[1..end];
        let value = unsafe {
            CStr::from_ptr(
                environ_find(global_environ, CString::new(name).unwrap().as_ptr())
                    .as_ref()?
                    .value,
            )
        }
        .to_str()
        .unwrap();
        return Some(Path::new(value).join(Path::new(&path[end..])));
    }

    Some(PathBuf::from(path))
}

fn expand_paths(s: &str, ignore_errors: bool) -> impl Iterator<Item = PathBuf> {
    let home = env::home_dir();
    s.split(':').filter_map(move |next| {
        let expanded = expand_path(next, home.as_ref().map(|p| p.as_path()))?;
        fs::canonicalize(&expanded)
            .ok()
            .or(if ignore_errors { None } else { Some(expanded) })
    })
}

fn make_label(label: Option<&str>) -> Result<PathBuf> {
    let label = label.unwrap_or("default");
    let uid = Uid::current();

    let tmux_sock = String::from("$TMUX_TMPDIR:") + env::temp_dir().as_os_str().to_str().unwrap();
    let mut path = expand_paths(&tmux_sock, true)
        .next()
        .ok_or(anyhow!("no suitable socket path"))?;

    path.push(format!("tmux-{uid}"));
    if let Err(e) = DirBuilder::new().mode(0o700).create(&path) {
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(e)
                .with_context(|| format!("couldn't create directory {}", path.display()))?;
        }
    }
    let sb = fs::symlink_metadata(&path)
        .with_context(|| format!("couldn't read directory {}", path.display()))?;
    if !sb.is_dir() {
        return Err(anyhow!("{} is not a directory", path.display()));
    }
    if Uid::from_raw(sb.uid()) != uid || sb.mode() & TMUX_SOCK_PERM != 0 {
        return Err(anyhow!(
            "directory {} has unsafe permissions",
            path.display()
        ));
    }
    path.push(label);
    Ok(path)
}

fn main() {
    unsafe {
        if libc::setlocale(LC_CTYPE, c"en_US.UTF-8".as_ptr()).is_null()
            && libc::setlocale(LC_CTYPE, c"C.UTF-8".as_ptr()).is_null()
        {
            if libc::setlocale(LC_CTYPE, c"".as_ptr()).is_null() {
                panic!("invalid LC_ALL, LC_CTYPE or LANG");
            }
            let s = libc::nl_langinfo(CODESET);
            let s = str::from_utf8(if s.is_null() {
                b""
            } else {
                CStr::from_ptr(s).to_bytes()
            })
            .unwrap();
            if !s.eq_ignore_ascii_case("UTF-8") && !s.eq_ignore_ascii_case("UTF8") {
                panic!("need UTF-8 locale (LC_CTYPE) but have {s}",);
            }
        }

        libc::setlocale(LC_TIME, c"".as_ptr());
        // tzset();
    }

    let mut flags = Client::empty();
    if env::args().next().map_or(false, |arg| arg.starts_with("-")) {
        flags = Client::LOGIN;
    }

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
    let mut cfg_paths = expand_paths(TMUX_CONF, true)
        .map(|path| {
            CString::new(path.into_os_string().as_bytes())
                .unwrap()
                .into_raw()
        })
        .collect::<Vec<_>>();
    unsafe {
        cfg_files = cfg_paths.as_mut_ptr();
        cfg_nfiles = cfg_paths.len().try_into().unwrap();
    }

    let cli = Cli::parse();
    let mut feat: c_int = 0;
    if cli.force_256 {
        unsafe {
            tty_add_features(&mut feat as *mut c_int, c"256".as_ptr(), c":,".as_ptr());
        }
    }
    if let Some(command) = cli.sh_command.as_ref() {
        unsafe {
            shell_command = CString::new(command.as_str()).unwrap().into_raw();
        }
    }
    if cli.no_daemon {
        flags |= Client::NO_FORK;
    }
    if cli.control > 0 {
        flags |= Client::CONTROL;
        if cli.control > 1 {
            flags |= Client::CONTROL_CONTROL;
        }
    }
    if !cli.config.is_empty() {
        cfg_paths.clear();
        cfg_paths.extend(cli.config.iter().map(|path| {
            CString::new(path.as_os_str().as_bytes())
                .unwrap()
                .into_raw()
        }));
        unsafe {
            cfg_files = cfg_paths.as_mut_ptr();
            cfg_nfiles = cfg_paths.len().try_into().unwrap();
            cfg_quiet = 0;
        }
    }
    if cli.login {
        flags |= Client::LOGIN;
    }
    if cli.no_start_server {
        flags |= Client::NO_START_SERVER;
    }
    for feat_s in &cli.features {
        unsafe {
            tty_add_features(
                &mut feat as *mut c_int,
                CString::new(feat_s.as_bytes()).unwrap().as_ptr(),
                c":,".as_ptr(),
            );
        }
    }
    if cli.utf_8 {
        flags |= Client::UTF8;
    }
    for _ in 0..cli.verbose {
        unsafe {
            log_add_level();
        }
    }

    if !cli.command.is_empty() && (cli.sh_command.is_some() || flags.contains(Client::NO_FORK)) {
        Cli::command().print_help().unwrap();
        process::exit(1);
    }

    unsafe {
        ptm_fd = tmux_rs::getptmfd();
        if ptm_fd == -1 {
            panic!("getptmfd");
        }
    }
    if tmux_rs::pledge(
        Some("stdio rpath wpath cpath flock fattr unix getpw sendfd recvfd proc exec tty ps"),
        None,
    ) != 0
    {
        panic!("pledge");
    }

    // tmux is a UTF-8 terminal, so if TMUX is set, assume UTF-8.
    // Otherwise, if the user has set LC_ALL, LC_CTYPE or LANG to contain
    // UTF-8, it is a safe assumption that either they are using a UTF-8
    // terminal, or if not they know that output from UTF-8-capable
    // programs may be wrong.
    if env::var_os("TMUX").is_some() {
        flags |= Client::UTF8;
    } else {
        let s = match env::var("LC_ALL").ok() {
            Some(s) => {
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            None => None,
        }
        .or(match env::var("LC_CTYPE").ok() {
            Some(s) => {
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            None => None,
        })
        .or(env::var("LANG").ok())
        .unwrap_or_default();
        if s.eq_ignore_ascii_case("UTF-8") || s.eq_ignore_ascii_case("UTF8") {
            flags |= Client::UTF8;
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

    // Override keys to vi if VISUAL or EDITOR are set.
    if let Ok(s) = env::var("VISUAL").or(env::var("EDITOR")) {
        unsafe {
            options_set_string(
                global_options,
                c"editor".as_ptr(),
                0,
                c"%s".as_ptr(),
                CString::new(s.as_bytes()).unwrap().as_ptr(),
            );
        }
        let keys = if PathBuf::from(s)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default()
            .contains("vi")
        {
            ModeKey::Vi
        } else {
            ModeKey::Emacs
        };
        unsafe {
            options_set_number(
                global_s_options,
                c"status-keys".as_ptr(),
                keys as c_longlong,
            );
            options_set_number(global_w_options, c"mode-keys".as_ptr(), keys as c_longlong);
        }
    }

    // If socket is specified on the command-line with -S or -L, it is
    // used. Otherwise, $TMUX is checked and if that fails "default" is
    // used.
    let path = cli.path.unwrap_or_else(|| {
        if cli.label.is_none() {
            let s = env::var("TMUX").unwrap_or_default();
            let s = s.split(',').next().unwrap_or_default();
            if s != "" {
                return PathBuf::from(s);
            }
        }

        flags |= Client::DEFAULT_SOCKET;
        make_label(cli.label.as_deref()).unwrap()
    });
    unsafe {
        socket_path = CString::new(path.into_os_string().as_bytes())
            .unwrap()
            .into_raw();
    }

    let mut argv = cli
        .command
        .iter()
        .map(|s| CString::new(s.as_bytes()).unwrap().into_raw())
        .collect::<Vec<_>>();
    let argc = argv.len();
    argv.push(ptr::null::<c_char>() as *mut c_char);
    // Pass control to the client.
    process::exit(unsafe {
        client_main(
            osdep_event_init(),
            argc.try_into().unwrap(),
            argv.as_mut_ptr(),
            flags.bits(),
            feat,
        )
    });
}
