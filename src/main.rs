use core::marker::{PhantomData, PhantomPinned};
use std::path::PathBuf;

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
struct EventBase {
    _data: (),
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

#[link(name = "tmux")]
unsafe extern "C" {
    fn log_add_level();

    fn osdep_event_init() -> *mut EventBase;
}

fn main() {
    let cli = Cli::parse();
    for _ in 0..cli.verbose {
        unsafe {
            log_add_level();
        }
    }

    dbg!(unsafe { osdep_event_init() });
}
