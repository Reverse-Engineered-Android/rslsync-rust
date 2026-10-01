//! Caller-supplied input that this implementation rejects.
//!
//! A malformed share key, a sync link whose access contradicts its key, a
//! folder path that is not an existing directory, or two conflicting fields in
//! one request are all *caller* errors: the request was wrong, not the server.
//! Carrying them as a distinct error type lets the HTTP layer answer with the
//! right 4xx status and a machine-readable code instead of masking them behind
//! a generic 500, which told the web console nothing useful.

use anyhow::Result;
use std::fmt;

/// A request rejected because of the input it carried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerError {
    status: u16,
    code: &'static str,
    message: String,
}

impl CallerError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CallerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CallerError {}

/// A rejected share key: an Advanced Folder key, an unknown key type, a
/// malformed body, or a role that cannot be derived from the given key.
pub fn invalid_key(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CallerError::new(400, "invalid_key", message))
}

/// A malformed request that is not specifically about the share key itself,
/// such as a folder path that does not exist or two contradictory fields.
pub fn invalid_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CallerError::new(400, "invalid_request", message))
}

/// A request that is well formed but collides with existing state, such as a
/// folder path that is already registered.
pub fn conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CallerError::new(409, "conflict", message))
}

/// Recover a caller rejection from a propagated error chain.
pub fn caller_error_from(error: &anyhow::Error) -> Option<&CallerError> {
    error.downcast_ref::<CallerError>()
}

/// Reclassify a nested operation's failure as caller error.
///
/// Some validators (the selection-pattern parser, for instance) return plain
/// `anyhow` errors. This keeps their detail but marks the failure as the
/// caller's fault, so the HTTP layer reports a 4xx and the console can show
/// what was actually wrong with the input.
pub fn reclassify<T>(result: Result<T>, context: impl std::fmt::Display) -> Result<T> {
    result.map_err(|error| invalid_request(format!("{context}: {error:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_errors_carry_their_status_and_code() {
        let key = invalid_key("Advanced Folder keys are not supported");
        let recovered = caller_error_from(&key).expect("invalid_key carries a CallerError");
        assert_eq!(recovered.status(), 400);
        assert_eq!(recovered.code(), "invalid_key");
        assert_eq!(
            recovered.message(),
            "Advanced Folder keys are not supported"
        );

        let request = invalid_request("folder path must be absolute");
        let recovered = caller_error_from(&request).unwrap();
        assert_eq!(
            (recovered.status(), recovered.code()),
            (400, "invalid_request")
        );

        let clash = conflict("folder path is already registered");
        let recovered = caller_error_from(&clash).unwrap();
        assert_eq!((recovered.status(), recovered.code()), (409, "conflict"));
    }

    #[test]
    fn unrelated_errors_are_not_mistaken_for_caller_errors() {
        let io = anyhow::anyhow!("disk on fire");
        assert!(caller_error_from(&io).is_none());

        // The classification survives being wrapped in context, which is how
        // most of these travel out of the state layer.
        let wrapped = invalid_key("bad key").context("folder sync key");
        assert!(caller_error_from(&wrapped).is_some());
    }

    #[test]
    fn reclassify_marks_a_plain_failure_as_caller_error() {
        let plain: Result<()> = Err(anyhow::anyhow!("unclosed character class"));
        let mapped = reclassify(plain, "invalid selection pattern")
            .expect_err("reclassify preserves the failure");
        let recovered = caller_error_from(&mapped).unwrap();
        assert_eq!(recovered.code(), "invalid_request");
        // Both the caller-facing context and the underlying detail survive.
        assert!(recovered.message().contains("invalid selection pattern"));
        assert!(recovered.message().contains("unclosed character class"));
    }
}
