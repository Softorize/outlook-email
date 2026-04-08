//! Canonical error set + Diagnostic struct shared by every module.
//!
//! A single error set keeps function signatures honest: callers see exactly
//! what can go wrong, and the CLI layer has one place to map errors to
//! human-friendly messages and exit codes.
//!
//! For anything that needs more context than an enum value (HTTP status,
//! Retry-After, server message, Graph request-id), modules also populate a
//! `Diagnostic` that the render layer knows how to print.

const std = @import("std");

pub const Error = error{
    // --- network / transport -----------------------------------------------
    NetworkUnreachable,
    TlsHandshakeFailed,
    ProxyAuthRequired,

    // --- HTTP ---------------------------------------------------------------
    HttpStatus,
    RateLimited,
    Unauthorized,

    // --- auth ---------------------------------------------------------------
    TokenExpiredNoRefresh,
    DeviceFlowDenied,
    DeviceFlowExpired,
    DeviceFlowPollFailed,
    NotSignedIn,

    // --- keystore -----------------------------------------------------------
    KeystoreUnavailable,
    KeystoreItemMissing,
    KeystoreAccessDenied,

    // --- graph / parsing ----------------------------------------------------
    GraphMalformedJson,
    GraphUnknownSchema,
    GraphBadRequest,

    // --- accounts -----------------------------------------------------------
    NoCurrentAccount,
    AccountNotFound,

    // --- CLI / config -------------------------------------------------------
    InvalidArgument,
    MissingClientId,
    BadConfigFile,

    // --- misc ---------------------------------------------------------------
    UserAborted,
    Io,
    OutOfMemory,
};

/// Extra context attached to an `Error` before it bubbles up to the CLI
/// layer. None of the fields are required; they are populated opportunistically
/// so the user sees "Microsoft is throttling us, retry in 42s" instead of
/// "RateLimited".
pub const Diagnostic = struct {
    err: Error,
    http_status: ?u16 = null,
    retry_after_seconds: ?u32 = null,
    server_message: ?[]const u8 = null,
    request_id: ?[]const u8 = null,
    hint: ?[]const u8 = null,

    pub fn simple(err: Error) Diagnostic {
        return .{ .err = err };
    }
};

/// Convert an `Error` into a short, colour-free one-liner suitable for
/// `--json` output or a last-resort stderr print.
pub fn shortName(err: Error) []const u8 {
    return @errorName(err);
}

/// Best-effort human-readable message for a bare error, used when no
/// `Diagnostic` is available.
pub fn defaultMessage(err: Error) []const u8 {
    return switch (err) {
        error.NetworkUnreachable => "Cannot reach the network. Check your internet connection.",
        error.TlsHandshakeFailed => "TLS handshake failed. If you're on a corporate network with a TLS-intercepting proxy, try --ca-bundle <path> or set OCLI_CA_BUNDLE.",
        error.ProxyAuthRequired => "The HTTPS proxy requires authentication. Embed credentials in HTTPS_PROXY (http://user:pass@host:port).",
        error.HttpStatus => "The server returned an unexpected status.",
        error.RateLimited => "Microsoft Graph is throttling this app. Wait a moment and retry.",
        error.Unauthorized => "Sign-in expired. Run 'ocli login' again.",
        error.TokenExpiredNoRefresh => "Your saved sign-in has expired and could not be refreshed. Run 'ocli login'.",
        error.DeviceFlowDenied => "You denied the sign-in request.",
        error.DeviceFlowExpired => "The device code expired before sign-in completed. Run 'ocli login' again.",
        error.DeviceFlowPollFailed => "The sign-in poll failed. Check your network and retry 'ocli login'.",
        error.NotSignedIn => "Not signed in. Run 'ocli login' first.",
        error.KeystoreUnavailable => "No credential store is available on this machine. The encrypted file fallback is in use; see README.",
        error.KeystoreItemMissing => "The requested credential was not found in the keystore.",
        error.KeystoreAccessDenied => "Access to the OS credential store was denied.",
        error.GraphMalformedJson => "Microsoft Graph returned malformed JSON. Retry with --verbose to see the raw response.",
        error.GraphUnknownSchema => "Microsoft Graph returned a response this version of the tool does not understand. Please update.",
        error.GraphBadRequest => "Microsoft Graph rejected the request.",
        error.NoCurrentAccount => "No account is selected. Run 'ocli login' or 'ocli use <email>'.",
        error.AccountNotFound => "That account is not signed in on this machine.",
        error.InvalidArgument => "Invalid command-line arguments. Run 'ocli --help'.",
        error.MissingClientId => "This build has no Azure client ID baked in. Contact your IT team or pass --client-id.",
        error.BadConfigFile => "The user config file is malformed.",
        error.UserAborted => "Cancelled.",
        error.Io => "I/O error.",
        error.OutOfMemory => "Out of memory.",
    };
}
