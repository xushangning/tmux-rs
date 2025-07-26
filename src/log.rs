#[link(name = "tmux")]
unsafe extern "C" {
    fn log_add_level();
}

/// Increment log level.
pub fn add_level() {
    log::set_max_level(log::LevelFilter::Debug);
    unsafe {
        log_add_level();
    }
}
