use core::ffi::{CStr, c_int, c_longlong};
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
    self, ClientFlag, ModeKey, TMUX_CONF, TMUX_SOCK_PERM,
    tmux_sys::{
        OPTIONS_TABLE_SERVER, OPTIONS_TABLE_SESSION, OPTIONS_TABLE_WINDOW, cfg_files, cfg_nfiles,
        cfg_quiet, environ_create, environ_find, environ_put, environ_set, global_environ,
        global_options, global_s_options, global_w_options, options_create, options_default,
        options_set_number, options_set_string, options_table, tty_add_features,
    },
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
    // Let the log crate, not the spdlog crate handle log filtering.
    spdlog::default_logger().set_level_filter(spdlog::LevelFilter::All);
    spdlog::init_log_crate_proxy().unwrap();

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
        // The call to tzset appears very early in the Git history of tmux
        // (actually the second commit a41ece5ff0d3ce7a0b7d987baa9759f8a012b48b).
        // I don't believe it's still necessary as time zone related functions
        // will automatically call tzset() if needed.
        // tzset();
    }

    let mut flags = ClientFlag::empty();
    if env::args().next().map_or(false, |arg| arg.starts_with("-")) {
        flags = ClientFlag::LOGIN;
    }

    unsafe {
        global_environ = environ_create();
        let mut var = tmux_rs::tmux_sys::environ;
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
            tty_add_features(&raw mut feat, c"256".as_ptr(), c":,".as_ptr());
        }
    }
    if let Some(command) = cli.sh_command.as_ref() {
        unsafe {
            tmux_rs::tmux_sys::shell_command = CString::new(command.as_str()).unwrap().into_raw();
        }
    }
    if cli.no_daemon {
        flags |= ClientFlag::NO_FORK;
    }
    if cli.control > 0 {
        flags |= ClientFlag::CONTROL;
        if cli.control > 1 {
            flags |= ClientFlag::CONTROL_CONTROL;
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
        flags |= ClientFlag::LOGIN;
    }
    if cli.no_start_server {
        flags |= ClientFlag::NO_START_SERVER;
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
        flags |= ClientFlag::UTF8;
    }
    for _ in 0..cli.verbose {
        tmux_rs::log::add_level();
    }

    if !cli.command.is_empty() && (cli.sh_command.is_some() || flags.contains(ClientFlag::NO_FORK))
    {
        Cli::command().print_help().unwrap();
        process::exit(1);
    }

    unsafe {
        tmux_rs::tmux_sys::ptm_fd = tmux_rs::getptmfd();
        if tmux_rs::tmux_sys::ptm_fd == -1 {
            panic!("getptmfd");
        }
    }
    tmux_rs::pledge(
        Some("stdio rpath wpath cpath flock fattr unix getpw sendfd recvfd proc exec tty ps"),
        None,
    )
    .expect("pledge");

    // tmux is a UTF-8 terminal, so if TMUX is set, assume UTF-8.
    // Otherwise, if the user has set LC_ALL, LC_CTYPE or LANG to contain
    // UTF-8, it is a safe assumption that either they are using a UTF-8
    // terminal, or if not they know that output from UTF-8-capable
    // programs may be wrong.
    if env::var_os("TMUX").is_some() {
        flags |= ClientFlag::UTF8;
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
            flags |= ClientFlag::UTF8;
        }
    }

    unsafe {
        global_options = options_create(ptr::null_mut());
        global_s_options = options_create(ptr::null_mut());
        global_w_options = options_create(ptr::null_mut());
        let mut oe_ptr = options_table.as_ptr();
        loop {
            let oe = oe_ptr.as_ref().unwrap();
            if oe.name.is_null() {
                break;
            }

            let scope: u32 = oe.scope.try_into().unwrap();
            if oe.scope as u32 & OPTIONS_TABLE_SERVER != 0 {
                options_default(global_options, oe_ptr);
            } else if scope & OPTIONS_TABLE_SESSION != 0 {
                options_default(global_s_options, oe_ptr);
            } else if scope & OPTIONS_TABLE_WINDOW != 0 {
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

        flags |= ClientFlag::DEFAULT_SOCKET;
        make_label(cli.label.as_deref()).unwrap()
    });
    unsafe {
        tmux_rs::tmux_sys::socket_path = CString::new(path.into_os_string().as_bytes())
            .unwrap()
            .into_raw();
    }

    // Pass control to the client.
    process::exit(tmux_rs::client::main(
        tmux_rs::osdep::event_init(),
        &cli.command,
        flags,
        feat,
    ));
}
