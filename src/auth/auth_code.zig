//! OAuth 2.0 authorization code flow with PKCE, "paste-URL" variant.
//!
//! Modelled on dbxcli's auth UX: the CLI prints a URL, the user opens it in
//! their own browser (Chrome, Firefox, whatever), completes sign-in, and the
//! browser lands on the native-client redirect page with `?code=...` in the
//! address bar. The user copies that URL (or just the code) back into the
//! terminal and the CLI exchanges the code for tokens.
//!
//! This file is transport-free so it can be unit-tested with string inputs.
//! The HTTP POST to the token endpoint lives in auth.zig.

const std = @import("std");
const http_util = @import("../util/http_util.zig");

pub const Pkce = struct {
    /// High-entropy random string, kept secret by the client.
    verifier: []u8,
    /// SHA-256(verifier) base64url-no-pad -- sent in the authorize request.
    challenge: []u8,
    /// Literal "S256" for convenience when form-encoding the request.
    method: []const u8 = "S256",

    pub fn deinit(self: *Pkce, gpa: std.mem.Allocator) void {
        gpa.free(self.verifier);
        gpa.free(self.challenge);
    }
};

/// Generate a fresh PKCE pair. The verifier is 64 bytes of base64url-no-pad
/// random data (well within the 43..128 char window RFC 7636 allows).
pub fn generatePkce(gpa: std.mem.Allocator) !Pkce {
    var raw: [48]u8 = undefined;
    std.crypto.random.bytes(&raw);

    const enc = std.base64.url_safe_no_pad.Encoder;
    const verifier_len = enc.calcSize(raw.len);
    const verifier = try gpa.alloc(u8, verifier_len);
    errdefer gpa.free(verifier);
    _ = enc.encode(verifier, &raw);

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});
    const challenge_len = enc.calcSize(hash.len);
    const challenge = try gpa.alloc(u8, challenge_len);
    errdefer gpa.free(challenge);
    _ = enc.encode(challenge, &hash);

    return .{ .verifier = verifier, .challenge = challenge };
}

/// Cryptographically random anti-CSRF state token (base64url, no padding).
pub fn generateState(gpa: std.mem.Allocator) ![]u8 {
    var raw: [16]u8 = undefined;
    std.crypto.random.bytes(&raw);
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try gpa.alloc(u8, enc.calcSize(raw.len));
    errdefer gpa.free(out);
    _ = enc.encode(out, &raw);
    return out;
}

pub const AuthorizeUrlArgs = struct {
    authorize_endpoint: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    scopes_joined: []const u8, // space-separated
    code_challenge: []const u8,
    state: []const u8,
};

/// Build the full authorize URL the user pastes into their browser.
pub fn buildAuthorizeUrl(gpa: std.mem.Allocator, args: AuthorizeUrlArgs) ![]u8 {
    const query = try http_util.formEncodeAlloc(gpa, &.{
        .{ "client_id", args.client_id },
        .{ "response_type", "code" },
        .{ "redirect_uri", args.redirect_uri },
        .{ "response_mode", "query" },
        .{ "scope", args.scopes_joined },
        .{ "state", args.state },
        .{ "code_challenge", args.code_challenge },
        .{ "code_challenge_method", "S256" },
        .{ "prompt", "select_account" },
    });
    defer gpa.free(query);
    return std.fmt.allocPrint(gpa, "{s}?{s}", .{ args.authorize_endpoint, query });
}

pub const ExtractedCode = struct {
    code: []u8,
    state: ?[]u8,

    pub fn deinit(self: *ExtractedCode, gpa: std.mem.Allocator) void {
        gpa.free(self.code);
        if (self.state) |s| gpa.free(s);
    }
};

/// Accept either:
///   - a bare authorization code like "0.AXoAabc..."
///   - a full redirect URL like "https://login.microsoftonline.com/.../nativeclient?code=...&state=..."
///   - just the query portion "?code=...&state=..." or "code=...&state=..."
///
/// and return the percent-decoded `code` and (if present) `state` values.
///
/// If the input looks like a URL/query but contains no `code=` (e.g. the user
/// pasted an error page URL with `error=access_denied`), surfaces the server
/// error string under `error.AuthCodeServerError`. We write the raw error to
/// stderr so the user can see what AAD said.
pub fn extractCode(gpa: std.mem.Allocator, input: []const u8) !ExtractedCode {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.AuthCodeEmpty;

    // Does this look like a URL or query string?
    const looks_like_query = std.mem.indexOfScalar(u8, trimmed, '=') != null or
        std.mem.startsWith(u8, trimmed, "http://") or
        std.mem.startsWith(u8, trimmed, "https://") or
        trimmed[0] == '?' or trimmed[0] == '&';

    if (!looks_like_query) {
        // Treat the whole thing as a bare code.
        return .{ .code = try gpa.dupe(u8, trimmed), .state = null };
    }

    // Isolate the query portion.
    const query_start = if (std.mem.indexOfScalar(u8, trimmed, '?')) |i| i + 1 else 0;
    const q = trimmed[query_start..];

    var code_val: ?[]u8 = null;
    var state_val: ?[]u8 = null;
    var err_val: ?[]u8 = null;
    var err_desc: ?[]u8 = null;
    errdefer {
        if (code_val) |v| gpa.free(v);
        if (state_val) |v| gpa.free(v);
    }
    defer {
        if (err_val) |v| gpa.free(v);
        if (err_desc) |v| gpa.free(v);
    }

    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        const decoded = try urlDecodeAlloc(gpa, val);
        if (std.mem.eql(u8, key, "code")) {
            if (code_val) |old| gpa.free(old);
            code_val = decoded;
        } else if (std.mem.eql(u8, key, "state")) {
            if (state_val) |old| gpa.free(old);
            state_val = decoded;
        } else if (std.mem.eql(u8, key, "error")) {
            if (err_val) |old| gpa.free(old);
            err_val = decoded;
        } else if (std.mem.eql(u8, key, "error_description")) {
            if (err_desc) |old| gpa.free(old);
            err_desc = decoded;
        } else {
            gpa.free(decoded);
        }
    }

    if (code_val) |c| {
        return .{ .code = c, .state = state_val };
    }

    if (err_val) |e| {
        @import("../util/io.zig").errPrint(
            "ocli: Microsoft rejected the sign-in request:\n  {s}\n  {s}\n",
            .{ e, err_desc orelse "" },
        );
        return error.AuthCodeServerError;
    }

    return error.AuthCodeMissing;
}

fn urlDecodeAlloc(gpa: std.mem.Allocator, src: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (c == '%' and i + 2 < src.len) {
            const hi = hexDigit(src[i + 1]) orelse return error.AuthCodeBadEncoding;
            const lo = hexDigit(src[i + 2]) orelse return error.AuthCodeBadEncoding;
            try out.append(gpa, (hi << 4) | lo);
            i += 3;
        } else if (c == '+') {
            try out.append(gpa, ' ');
            i += 1;
        } else {
            try out.append(gpa, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(gpa);
}

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

test "pkce verifier and challenge have expected shapes" {
    const gpa = std.testing.allocator;
    var p = try generatePkce(gpa);
    defer p.deinit(gpa);
    // 48 raw bytes -> 64 base64url chars (no padding).
    try std.testing.expectEqual(@as(usize, 64), p.verifier.len);
    // SHA-256 (32 bytes) -> 43 base64url chars.
    try std.testing.expectEqual(@as(usize, 43), p.challenge.len);
    // Challenge must differ from verifier.
    try std.testing.expect(!std.mem.eql(u8, p.verifier, p.challenge));
}

test "extractCode accepts a bare code" {
    const gpa = std.testing.allocator;
    var r = try extractCode(gpa, "0.AXoAabc123");
    defer r.deinit(gpa);
    try std.testing.expectEqualStrings("0.AXoAabc123", r.code);
    try std.testing.expect(r.state == null);
}

test "extractCode accepts a full redirect URL" {
    const gpa = std.testing.allocator;
    const url = "https://login.microsoftonline.com/common/oauth2/nativeclient?code=0.AbC%2Fdef&state=xyz";
    var r = try extractCode(gpa, url);
    defer r.deinit(gpa);
    try std.testing.expectEqualStrings("0.AbC/def", r.code);
    try std.testing.expectEqualStrings("xyz", r.state.?);
}

test "extractCode accepts a bare query string" {
    const gpa = std.testing.allocator;
    var r = try extractCode(gpa, "code=abc&state=s1");
    defer r.deinit(gpa);
    try std.testing.expectEqualStrings("abc", r.code);
    try std.testing.expectEqualStrings("s1", r.state.?);
}

test "extractCode reports server errors" {
    const gpa = std.testing.allocator;
    const url = "https://login.microsoftonline.com/.../nativeclient?error=access_denied&error_description=User+declined";
    try std.testing.expectError(
        error.AuthCodeServerError,
        extractCode(gpa, url),
    );
}

test "buildAuthorizeUrl encodes scopes and challenge" {
    const gpa = std.testing.allocator;
    const url = try buildAuthorizeUrl(gpa, .{
        .authorize_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        .client_id = "abc-123",
        .redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient",
        .scopes_joined = "offline_access Mail.Send",
        .code_challenge = "CHALL",
        .state = "STATE",
    });
    defer gpa.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "client_id=abc-123") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge=CHALL") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=offline_access%20Mail.Send") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "state=STATE") != null);
}
