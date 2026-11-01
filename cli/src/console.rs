//! The logger and prompt a command runs with, and the result documents
//! [`run`](crate::run) prints when it is done.

use std::fmt::Display;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::log::{Level, Logger, NoopLogger};
use crate::output::Report;
use crate::prompt::{Prompt, TerminalPrompt};

/// What a command logs to, asks, and (under [`run`](crate::run)) reports to.
#[derive(Clone)]
pub(crate) struct Console {
    logger: Arc<dyn Logger>,
    prompt: Arc<dyn Prompt>,
    reports: Option<Arc<Reports>>,
}

impl Default for Console {
    fn default() -> Self {
        Self::new(Arc::new(NoopLogger), Arc::new(TerminalPrompt::new()))
    }
}

impl Console {
    pub fn new(logger: Arc<dyn Logger>, prompt: Arc<dyn Prompt>) -> Self {
        Self {
            logger,
            prompt,
            reports: None,
        }
    }

    /// Collects result documents for [`Reports::print`].
    pub fn with_reports(mut self, reports: Arc<Reports>) -> Self {
        self.reports = Some(reports);
        self
    }

    pub fn logger(&self) -> &Arc<dyn Logger> {
        &self.logger
    }

    pub fn prompt(&self) -> &Arc<dyn Prompt> {
        &self.prompt
    }

    /// Progress.
    pub fn line(&self, text: impl Display) {
        self.logger.log(Level::Info, format_args!("{text}"));
    }

    pub fn warn(&self, text: impl Display) {
        self.logger.log(Level::Warn, format_args!("{text}"));
    }

    #[cfg_attr(
        not(feature = "hd-wallet"),
        allow(dead_code, reason = "only the HD wallet commands collect warnings")
    )]
    pub fn warnings(&self, warnings: &[String]) {
        for warning in warnings {
            self.warn(warning);
        }
    }

    pub fn confirm(&self, question: &str, details: &str) -> bool {
        self.prompt.confirm(question, details)
    }

    pub fn secret(&self, label: &str) -> io::Result<Zeroizing<String>> {
        self.prompt.secret(label)
    }

    /// Whether the result documents are printed: under [`run`](crate::run),
    /// not for a host calling the library.
    pub fn prints_results(&self) -> bool {
        self.reports.is_some()
    }

    /// Stdout carries a document of its own (`--raw-out -`), so a human
    /// result goes to stderr instead.
    pub fn stdout_carries_data(&self) {
        if let Some(reports) = &self.reports {
            reports.stdout_is_data.store(true, Ordering::Relaxed);
        }
    }

    /// The command's result, as JSON or text.
    pub fn emit(&self, report: &impl Report) {
        if let Some(reports) = &self.reports {
            reports.push(Rendered {
                json: Some(json(report)),
                human: report.human(),
            });
        }
    }

    /// A result only text mode prints, because JSON mode already has it on
    /// stdout.
    pub fn emit_human(&self, report: &impl Report) {
        if let Some(reports) = &self.reports {
            reports.push(Rendered {
                json: None,
                human: report.human(),
            });
        }
    }

    /// A result the caller would otherwise not see (a failed simulation and
    /// its traces): emitted under `run`, logged for a host.
    pub fn emit_or_line(&self, report: &impl Report) {
        if self.prints_results() {
            self.emit(report);
        } else {
            self.line(report.human());
        }
    }
}

fn json(report: &impl Report) -> String {
    serde_json::to_string_pretty(report)
        .unwrap_or_else(|e| format!("{{\"error\": \"cannot encode the result: {e}\"}}"))
}

struct Rendered {
    json: Option<String>,
    human: String,
}

/// The result documents of one command, printed once it returns.
#[derive(Default)]
pub(crate) struct Reports {
    docs: Mutex<Vec<Rendered>>,
    stdout_is_data: AtomicBool,
}

impl Reports {
    fn push(&self, doc: Rendered) {
        self.docs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(doc);
    }

    /// Prints the documents: JSON on stdout, or text on stdout (stderr when
    /// stdout carries `--raw-out -`).
    #[allow(
        clippy::print_stdout,
        clippy::print_stderr,
        reason = "where `run` prints a command's result"
    )]
    pub fn print(&self, json: bool) {
        let docs = std::mem::take(
            &mut *self
                .docs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let to_stderr = self.stdout_is_data.load(Ordering::Relaxed);
        for doc in docs {
            if json {
                if let Some(document) = doc.json {
                    println!("{document}");
                }
            } else if to_stderr {
                eprintln!("{}", doc.human);
            } else {
                println!("{}", doc.human);
            }
        }
    }
}
