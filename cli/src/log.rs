//! Where the library's progress, notes and warnings go.
//!
//! The library never prints. Every command takes a [`Logger`] from its
//! context; the default, [`NoopLogger`], drops everything. The `safe` binary
//! passes a [`ConsoleLogger`], which writes to stderr.
//!
//! ```
//! use safe_rs_cli::log::{self, Level};
//!
//! // Any closure becomes a logger through `log::from_fn`.
//! let logger = log::from_fn(|level: Level, message: std::fmt::Arguments<'_>| {
//!     let _ = (level, message.to_string());
//! });
//! # let _ = logger;
//! ```

use std::fmt;
use std::sync::Arc;

/// How much a message matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Room for a later `-v`; nothing logs at this level yet
    Debug,
    /// Progress: what is being sent, the simulation result, call traces
    Info,
    /// Something the user should act on or know about. Warnings also stay in
    /// the outcome's `warnings` field, so a host with a [`NoopLogger`] still
    /// gets them.
    Warn,
}

/// Where the library's progress, notes and warnings go.
pub trait Logger: Send + Sync {
    fn log(&self, level: Level, message: fmt::Arguments<'_>);

    /// Lets the library skip building costly text, such as call traces.
    fn enabled(&self, level: Level) -> bool {
        let _ = level;
        true
    }
}

impl<L: Logger + ?Sized> Logger for Arc<L> {
    fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        (**self).log(level, message);
    }

    fn enabled(&self, level: Level) -> bool {
        (**self).enabled(level)
    }
}

impl<L: Logger + ?Sized> Logger for Box<L> {
    fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        (**self).log(level, message);
    }

    fn enabled(&self, level: Level) -> bool {
        (**self).enabled(level)
    }
}

/// Drops everything. The library default.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopLogger;

impl Logger for NoopLogger {
    fn log(&self, _level: Level, _message: fmt::Arguments<'_>) {}

    fn enabled(&self, _level: Level) -> bool {
        false
    }
}

/// A logger made from a closure, by [`from_fn`].
#[derive(Clone)]
pub struct FnLogger<F>(F);

impl<F> fmt::Debug for FnLogger<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FnLogger")
    }
}

impl<F: Fn(Level, fmt::Arguments<'_>) + Send + Sync> Logger for FnLogger<F> {
    fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        (self.0)(level, message);
    }
}

/// Turns a closure into a [`Logger`]:
/// `ctx.with_logger(log::from_fn(|level, msg| my_log(level, msg)))`.
pub fn from_fn<F: Fn(Level, fmt::Arguments<'_>) + Send + Sync>(f: F) -> FnLogger<F> {
    FnLogger(f)
}

/// What the `safe` binary uses: everything at `min` or above goes to stderr,
/// warnings prefixed "warning: ".
#[derive(Clone, Copy, Debug)]
pub struct ConsoleLogger {
    min: Level,
}

impl ConsoleLogger {
    pub fn new(min: Level) -> Self {
        Self { min }
    }
}

impl Logger for ConsoleLogger {
    #[allow(
        clippy::print_stderr,
        reason = "the console logger is where the binary's progress reaches the terminal"
    )]
    fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        if !self.enabled(level) {
            return;
        }
        if level == Level::Warn {
            eprintln!("warning: {message}");
        } else {
            eprintln!("{message}");
        }
    }

    fn enabled(&self, level: Level) -> bool {
        level >= self.min
    }
}

/// Forwards to `tracing` events with target `safe_rs_cli`, for a host that
/// already has a subscriber.
#[cfg(feature = "tracing")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingLogger;

#[cfg(feature = "tracing")]
impl Logger for TracingLogger {
    fn log(&self, level: Level, message: fmt::Arguments<'_>) {
        match level {
            Level::Debug => tracing::debug!(target: "safe_rs_cli", "{message}"),
            Level::Info => tracing::info!(target: "safe_rs_cli", "{message}"),
            Level::Warn => tracing::warn!(target: "safe_rs_cli", "{message}"),
        }
    }

    fn enabled(&self, level: Level) -> bool {
        match level {
            Level::Debug => tracing::enabled!(target: "safe_rs_cli", tracing::Level::DEBUG),
            Level::Info => tracing::enabled!(target: "safe_rs_cli", tracing::Level::INFO),
            Level::Warn => tracing::enabled!(target: "safe_rs_cli", tracing::Level::WARN),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn closures_and_shared_loggers_receive_messages() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let logger: Arc<dyn Logger> = Arc::new(from_fn(move |level, message| {
            sink.lock().unwrap().push((level, message.to_string()));
        }));
        // An `Arc<dyn Logger>` is itself a logger, so one can be shared.
        let shared = logger.clone();
        shared.log(Level::Info, format_args!("one {}", 1));
        logger.log(Level::Warn, format_args!("two"));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                (Level::Info, "one 1".to_string()),
                (Level::Warn, "two".to_string())
            ]
        );
    }

    #[test]
    fn the_console_logger_filters_by_level() {
        let logger = ConsoleLogger::new(Level::Warn);
        assert!(!logger.enabled(Level::Info));
        assert!(logger.enabled(Level::Warn));
        assert!(!NoopLogger.enabled(Level::Warn));
    }
}
