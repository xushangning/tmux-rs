use std::{ffi::CString, sync::Arc};

use log::error;
use spdlog::sink::FileSink;

use crate::tmux_sys::{log_add_level, log_get_level, log_open};

/// Increment log level.
pub fn add_level() {
    log::set_max_level(log::LevelFilter::Debug);
    unsafe {
        log_add_level();
    }
}

/// Open logging to file.
pub(crate) fn open(name: &str) {
    if unsafe { log_get_level() } == 0 {
        return;
    }

    spdlog::set_default_logger(
        spdlog::default_logger()
            .fork_with(|new_logger| {
                new_logger.sinks_mut().clear();
                new_logger.sinks_mut().push(Arc::new(
                    FileSink::builder()
                        .path(format!("tmux-rs-{name}-{}.log", std::process::id()))
                        .build()?,
                ));
                new_logger.set_name(Some(name)).unwrap();

                // If we don't flush on every logging operation, some log
                // records may not be flushed until after forking, leading to
                // duplicate records in two processes being sent to the same
                // file.
                //
                // There are other ways to solve this problem, such as manually
                // flushing the logger before forking, but in the original tmux
                // log_open function, without explanation it configures the log
                // file to be line buffered, essentially equivalent to flushing
                // on every logging operation. In the spirit of following the
                // original tmux source code, we chose this flush policy.
                new_logger.set_flush_level_filter(spdlog::LevelFilter::All);

                Ok(())
            })
            .unwrap(),
    );
    std::panic::set_hook(Box::new(|panic_hook_info| {
        error!("{panic_hook_info}");
    }));

    unsafe {
        // TODO: move the rest of log_open's code here. We haven't completely
        // port the log_open function yet because we can't let other code in libtmux call
        // our log_debug functions without recompiling the lib, something we
        // don't want to do right now. We only partially port the code to set
        // logging to file for the server process.
        log_open(CString::new(name).unwrap().as_ptr());
    }
}
