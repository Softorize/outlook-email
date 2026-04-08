//! HTTP client wrapper for Microsoft Graph + the Azure AD token endpoints.
//!
//! All of the application's network surface funnels through this file. It
//! owns:
//!   - a single `std.http.Client` (with HTTPS_PROXY picked up automatically)
//!   - retry + exponential backoff logic
//!   - 429 Retry-After honouring
//!   - injecting the Authorization header via a `BearerProvider` vtable
//!     (the auth.Session implements it)
//!   - classifying low-level std.http errors into our `errors.Error` set
//!
//! Rest of the code imports *this file* rather than `std.http.Client`
//! directly, so any further API churn in Zig's stdlib is contained here.

const std = @import("std");
const errors = @import("../errors.zig");
const http_util = @import("../util/http_util.zig");
const log = @import("../util/log.zig");

const Error = errors.Error;

/// Abstraction for "give me a valid access token". The auth session
/// implements this; tests substitute a stub.
pub const BearerProvider = struct {
    ctx: *anyopaque,
    getFn: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator) Error![]const u8,

    pub fn get(self: BearerProvider, gpa: std.mem.Allocator) Error![]const u8 {
        return self.getFn(self.ctx, gpa);
    }
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    inner: std.http.Client,
    proxy_arena: std.heap.ArenaAllocator,
    user_agent: []const u8,
    max_retries: u8 = 5,

    pub fn init(gpa: std.mem.Allocator, user_agent: []const u8) !Client {
        return .{
            .gpa = gpa,
            .inner = .{ .allocator = gpa },
            .proxy_arena = std.heap.ArenaAllocator.init(gpa),
            .user_agent = user_agent,
        };
    }

    /// Read HTTPS_PROXY / HTTP_PROXY from the environment and configure the
    /// underlying client to use them. Split from init so commands that never
    /// touch the network can skip the env-var scan + URL parse cost.
    pub fn enableEnvProxies(self: *Client) !void {
        try self.inner.initDefaultProxies(self.proxy_arena.allocator());
    }

    pub fn deinit(self: *Client) void {
        self.inner.deinit();
        self.proxy_arena.deinit();
    }
};

pub const Method = std.http.Method;

pub const Header = std.http.Header;

/// Parameters for one request. Body is either raw bytes (possibly already
/// JSON-serialised) with an explicit content type, or null.
pub const Request = struct {
    method: Method,
    url: []const u8,
    body: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    /// If set, the bearer provider is consulted and "Authorization: Bearer ..."
    /// is injected. If null, no auth header is added (used for the device code
    /// and token endpoints which authenticate via the body).
    bearer: ?BearerProvider = null,
    /// Extra headers appended after the default set.
    extra_headers: []const Header = &.{},
    /// Upper limit on the response body. Prevents runaway servers from
    /// exhausting memory. Default 16 MB is plenty for Graph list responses.
    max_response_bytes: usize = 16 * 1024 * 1024,
    /// Set to false for endpoints that return 202 / 204 with no body
    /// (DELETE, sendMail, reply, forward, send-draft). When false the HTTP
    /// layer skips passing a response_writer to std.http.Client.fetch,
    /// which avoids a streamRemaining hang waiting for body bytes that
    /// never arrive.
    expects_response_body: bool = true,
};

pub const Response = struct {
    gpa: std.mem.Allocator,
    status: u16,
    body: []u8,
    request_id: ?[]u8,
    retry_after_seconds: ?u32,

    pub fn deinit(self: *Response) void {
        self.gpa.free(self.body);
        if (self.request_id) |r| self.gpa.free(r);
    }
};

/// Execute a single request with retry + 429 backoff. The caller owns and
/// must `deinit` the returned `Response`.
pub fn do(client: *Client, gpa: std.mem.Allocator, req: Request) !Response {
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        const result = doOnce(client, gpa, req) catch |err| {
            if (attempt + 1 >= client.max_retries) return err;
            if (!isTransient(err)) return err;
            backoff(attempt);
            continue;
        };
        // 429 / 503 with Retry-After -> wait and retry.
        if ((result.status == 429 or result.status == 503) and attempt + 1 < client.max_retries) {
            const wait = result.retry_after_seconds orelse 0;
            var resp = result;
            resp.deinit();
            log.debug("ocli: status={d}, retry in {d}s (attempt {d}/{d})", .{
                result.status, wait, attempt + 1, client.max_retries,
            });
            if (wait > 0) std.Thread.sleep(@as(u64, wait) * std.time.ns_per_s) else backoff(attempt);
            continue;
        }
        return result;
    }
}

fn doOnce(client: *Client, gpa: std.mem.Allocator, req: Request) !Response {
    // Endpoints that return 202/204 with no body need a different code path:
    // std.http.Client.fetch always tries to drain the response body (either
    // via response_writer.streamRemaining or via discardRemaining), and both
    // hang on a 0-length body served over a keep-alive connection because
    // there is no terminator to detect end-of-message.
    if (!req.expects_response_body or req.method == .DELETE) {
        return doNoResponseBody(client, gpa, req);
    }

    // Set User-Agent and Content-Type via the std.http.Client.Request.Headers
    // override mechanism, NOT via extra_headers. Pushing them into
    // extra_headers would duplicate them alongside Zig's defaults, and
    // Microsoft's IIS gateway rejects requests with duplicate User-Agent.
    var extra: std.ArrayList(Header) = .empty;
    defer extra.deinit(gpa);
    try extra.append(gpa, .{ .name = "Accept", .value = "application/json" });

    var bearer_owned: ?[]const u8 = null;
    defer if (bearer_owned) |b| gpa.free(b);
    var auth_header_storage: [4096]u8 = undefined;
    if (req.bearer) |bp| {
        const tok = try bp.get(gpa);
        bearer_owned = tok;
        const val = std.fmt.bufPrint(&auth_header_storage, "Bearer {s}", .{tok}) catch return error.GraphBadRequest;
        try extra.append(gpa, .{ .name = "Authorization", .value = val });
    }

    for (req.extra_headers) |h| try extra.append(gpa, h);

    var alloc_writer: std.Io.Writer.Allocating = .init(gpa);
    defer alloc_writer.deinit();

    log.debug("ocli: HTTP {s} {s}", .{ @tagName(req.method), req.url });

    var std_headers: std.http.Client.Request.Headers = .{
        .user_agent = .{ .override = client.user_agent },
    };
    if (req.content_type) |ct| std_headers.content_type = .{ .override = ct };

    // For endpoints that return no body (DELETE, sendMail, etc.), do NOT
    // pass a response_writer. std.http.Client.fetch's response_writer path
    // calls streamRemaining which blocks waiting for body bytes that never
    // arrive. The null-writer path uses discardRemaining which handles
    // empty bodies correctly.
    const expects_body = req.expects_response_body and req.method != .DELETE;

    const fetch_result = client.inner.fetch(.{
        .location = .{ .url = req.url },
        .method = req.method,
        .payload = req.body,
        .response_writer = if (expects_body) &alloc_writer.writer else null,
        .headers = std_headers,
        .extra_headers = extra.items,
    }) catch |err| return mapFetchError(err);

    const status: u16 = @intFromEnum(fetch_result.status);
    if (alloc_writer.writer.end > req.max_response_bytes) {
        return error.GraphMalformedJson; // treat oversized as malformed
    }

    // Always dupe via gpa rather than moving ownership from Allocating.
    // toOwnedSlice on an Allocating that never wrote anything panics trying
    // to realloc a null buffer.
    const written = alloc_writer.written();
    const body_slice = gpa.dupe(u8, written) catch return error.OutOfMemory;

    return .{
        .gpa = gpa,
        .status = status,
        .body = body_slice,
        .request_id = null, // header capture not implemented in 0.15.2 fetch
        .retry_after_seconds = null,
    };
}

/// Issue a request that we expect to return no body (DELETE, sendMail,
/// reply, forward, send-draft). Uses the lower-level std.http.Client
/// `request` API so we can grab the status from receiveHead and exit
/// without ever reading body bytes -- avoiding the streamRemaining /
/// discardRemaining hangs that fetch hits on 0-length keep-alive responses.
fn doNoResponseBody(client: *Client, gpa: std.mem.Allocator, req: Request) !Response {
    var extra: std.ArrayList(Header) = .empty;
    defer extra.deinit(gpa);
    try extra.append(gpa, .{ .name = "Accept", .value = "application/json" });

    var bearer_owned: ?[]const u8 = null;
    defer if (bearer_owned) |b| gpa.free(b);
    var auth_header_storage: [4096]u8 = undefined;
    if (req.bearer) |bp| {
        const tok = try bp.get(gpa);
        bearer_owned = tok;
        const val = std.fmt.bufPrint(&auth_header_storage, "Bearer {s}", .{tok}) catch return error.GraphBadRequest;
        try extra.append(gpa, .{ .name = "Authorization", .value = val });
    }
    for (req.extra_headers) |h| try extra.append(gpa, h);

    var std_headers: std.http.Client.Request.Headers = .{
        .user_agent = .{ .override = client.user_agent },
    };
    if (req.content_type) |ct| std_headers.content_type = .{ .override = ct };

    log.debug("ocli: HTTP {s} {s}", .{ @tagName(req.method), req.url });

    const uri = std.Uri.parse(req.url) catch return error.GraphBadRequest;
    var http_req = client.inner.request(req.method, uri, .{
        .headers = std_headers,
        .extra_headers = extra.items,
        .keep_alive = false,
    }) catch |err| return mapFetchError(err);
    defer http_req.deinit();

    if (req.body) |body_bytes| {
        http_req.transfer_encoding = .{ .content_length = body_bytes.len };
        var body_writer = http_req.sendBodyUnflushed(&.{}) catch |err| return mapFetchError(err);
        body_writer.writer.writeAll(body_bytes) catch |err| return mapFetchError(err);
        body_writer.end() catch |err| return mapFetchError(err);
        if (http_req.connection) |conn| conn.flush() catch |err| return mapFetchError(err);
    } else {
        http_req.sendBodiless() catch |err| return mapFetchError(err);
    }

    var redirect_buf: [1024]u8 = undefined;
    const response = http_req.receiveHead(&redirect_buf) catch |err| return mapFetchError(err);
    const status: u16 = @intFromEnum(response.head.status);

    return .{
        .gpa = gpa,
        .status = status,
        .body = gpa.dupe(u8, "") catch return error.OutOfMemory,
        .request_id = null,
        .retry_after_seconds = null,
    };
}

fn backoff(attempt: u8) void {
    const base_ms: u64 = 250;
    const shift: u6 = @intCast(@min(attempt, 5));
    const ms = base_ms << shift;
    std.Thread.sleep(ms * std.time.ns_per_ms);
}

fn isTransient(err: anyerror) bool {
    return switch (err) {
        error.NetworkUnreachable, error.ConnectionResetByPeer, error.ConnectionTimedOut, error.TemporaryNameServerFailure => true,
        else => false,
    };
}

fn mapFetchError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.NetworkUnreachable, error.ConnectionRefused, error.ConnectionResetByPeer, error.ConnectionTimedOut, error.UnknownHostName => error.NetworkUnreachable,
        error.TlsInitializationFailed, error.TlsAlert, error.TlsFailure => error.TlsHandshakeFailed,
        else => error.HttpStatus,
    };
}

/// Status-code classifier that callers use after `do`.
pub fn classifyStatus(status: u16, diag: *errors.Diagnostic) Error {
    diag.http_status = status;
    return switch (status) {
        401 => error.Unauthorized,
        403 => error.Unauthorized,
        404 => error.GraphBadRequest,
        400, 405, 409, 422 => error.GraphBadRequest,
        429 => error.RateLimited,
        500, 502, 503, 504 => error.HttpStatus,
        else => error.HttpStatus,
    };
}
