use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // Get the directory of the Cargo.toml (project root)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Construct the path to the .libs directory relative to the project root
    let libs_path = Path::new(&manifest_dir).join(".libs");
    // Convert the path to a string and print the rustc-link-search directive
    println!("cargo:rustc-link-search={}", libs_path.display());

    println!("cargo:rustc-link-lib=event_core");
    println!("cargo:rustc-link-lib=tmux");
    let bindings = bindgen::Builder::default()
        .header("tmux.h")
        .blocklist_type("timeval")
        .raw_line("use libc::timeval;")
        .blocklist_type("clients")
        .raw_line("type clients = core::mem::MaybeUninit<crate::compat::queue::tailq::Head<client, { core::mem::offset_of!(client, entry) }>>;")
        .blocklist_type("message_list")
        .raw_line("type message_list = core::mem::MaybeUninit<crate::compat::queue::tailq::Head<message_entry, { core::mem::offset_of!(message_entry, entry) }>>;")
        .blocklist_type("windows")
        .raw_line("type windows = crate::compat::tree::rb::Head<window, { core::mem::offset_of!(window, entry) }>;")
        .blocklist_type("window_pane_tree")
        .raw_line("type window_pane_tree = crate::compat::tree::rb::Head<window_pane, { core::mem::offset_of!(window_pane, tree_entry) }>;")
        .blocklist_type("sessions")
        .raw_line("type sessions = crate::compat::tree::rb::Head<session, { core::mem::offset_of!(session, entry) }>;")
        .blocklist_type("window_pane")
        .raw_line("type window_pane = crate::window::Pane;")
        .blocklist_type("window_panes")
        .raw_line("type window_panes = core::mem::MaybeUninit<crate::compat::queue::tailq::Head<window_pane, { core::mem::offset_of!(window_pane, sentry) }>>;")
        .blocklist_type("winlink")
        .raw_line("pub(crate) type winlink = crate::window::Winlink;")
        .blocklist_type("window")
        .raw_line("type window = crate::window::Window;")
        .blocklist_type("tmuxproc")
        .raw_line("pub type tmuxproc = crate::proc::Proc;")
        .blocklist_type("tmuxpeer")
        .raw_line("pub type tmuxpeer = crate::proc::Peer;")
        .blocklist_type("client_windows")
        .raw_line("pub type client_windows = crate::compat::tree::rb::Head<client_window, { core::mem::offset_of!(client_window, entry) }>;")
        .blocklist_type("imsg")
        .raw_line("pub type imsg = crate::compat::imsg::IMsg;")
        .blocklist_type("imsg_hdr")
        .raw_line("pub type imsg_hdr = crate::compat::imsg::Hdr;")
        .blocklist_type("ibuf")
        .raw_line("pub type ibuf = crate::compat::imsg::IBuf;")
        .no_copy("args_value")
        .blocklist_type("cmdq_item")
        .raw_line("pub type cmdq_item = crate::cmd::queue::Item;")
        .blocklist_type("client")
        .raw_line("pub(crate) type client = crate::Client;")
        // Fix error ./compat.h:384:7: error: conflicting types for 'clock_gettime'
        .clang_arg("-D HAVE_CLOCK_GETTIME")
        .use_core()
        .generate_cstr(true)
        .wrap_unsafe_ops(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    let mut out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    out_path.push("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
