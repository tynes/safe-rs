//! Where the library's questions go: confirmations, passwords and keys.
//!
//! A separate trait from [`Logger`](crate::log::Logger) on purpose: a host
//! that passes a no-op logger must not have that logger answer "Deploy new
//! Safe?" for it.

use std::io;
use std::sync::Arc;

use zeroize::Zeroizing;

/// Answers the library's questions.
pub trait Prompt: Send + Sync {
    /// Asked before anything is broadcast. `details` is what the user is
    /// agreeing to (Safe address, owners, calls, payer), so the question makes
    /// sense even when progress goes nowhere.
    fn confirm(&self, question: &str, details: &str) -> bool;

    /// A password or private key, read without echo.
    fn secret(&self, label: &str) -> io::Result<Zeroizing<String>>;
}

impl<P: Prompt + ?Sized> Prompt for Arc<P> {
    fn confirm(&self, question: &str, details: &str) -> bool {
        (**self).confirm(question, details)
    }

    fn secret(&self, label: &str) -> io::Result<Zeroizing<String>> {
        (**self).secret(label)
    }
}

impl<P: Prompt + ?Sized> Prompt for Box<P> {
    fn confirm(&self, question: &str, details: &str) -> bool {
        (**self).confirm(question, details)
    }

    fn secret(&self, label: &str) -> io::Result<Zeroizing<String>> {
        (**self).secret(label)
    }
}

/// Asks on the terminal (stderr and `/dev/tty`). Declines every confirmation
/// when stdin is not a terminal. The library default.
#[derive(Clone, Copy, Debug)]
pub struct TerminalPrompt {
    show_details: bool,
}

impl Default for TerminalPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalPrompt {
    /// Shows a confirmation's details above its question.
    pub fn new() -> Self {
        Self { show_details: true }
    }

    /// Shows only the question: for a caller whose logger already printed
    /// the details as progress, as the `safe` binary's does.
    pub fn hide_details(mut self) -> Self {
        self.show_details = false;
        self
    }
}

impl Prompt for TerminalPrompt {
    #[allow(
        clippy::print_stderr,
        reason = "the terminal prompt shows what is being confirmed"
    )]
    #[allow(
        clippy::disallowed_methods,
        reason = "the terminal prompt is the one place that asks the terminal"
    )]
    fn confirm(&self, question: &str, details: &str) -> bool {
        if self.show_details && !details.is_empty() {
            eprintln!("{details}");
        }
        dialoguer::Confirm::new()
            .with_prompt(question)
            .default(false)
            .interact()
            .unwrap_or(false)
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "the terminal prompt is the one place that asks the terminal"
    )]
    fn secret(&self, label: &str) -> io::Result<Zeroizing<String>> {
        rpassword::prompt_password(label).map(Zeroizing::new)
    }
}

/// Declines every confirmation and refuses every secret: for servers and
/// tests. Set `no_confirm` on the options to send without asking.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrompt;

impl Prompt for NoPrompt {
    fn confirm(&self, _question: &str, _details: &str) -> bool {
        false
    }

    fn secret(&self, label: &str) -> io::Result<Zeroizing<String>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "no prompt to ask for {}: supply it as an option",
                label.trim_end_matches([':', ' '])
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_prompt_declines_and_refuses() {
        assert!(!NoPrompt.confirm("Deploy?", "details"));
        let error = NoPrompt.secret("Keystore password: ").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("Keystore password"), "{error}");
    }
}
