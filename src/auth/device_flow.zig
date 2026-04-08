//! OAuth 2.0 device authorization grant state machine, separated from the
//! HTTP transport so it can be unit-tested with canned inputs.
//!
//! Microsoft Graph documents the flow at:
//!   https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-device-code
//!
//! The caller is responsible for:
//!   1. POSTing to the devicecode endpoint and feeding the response to
//!      `startFromJson`, which returns a `Start` with user-visible details.
//!   2. Periodically POSTing to the token endpoint and feeding that response
//!      to `pollFromJson`, which tells the caller whether to wait longer,
//!      whether to increase the polling interval, whether the user denied or
//!      the code expired, or whether we have a token.

const std = @import("std");
const errors = @import("../errors.zig");

pub const Start = struct {
    user_code: []const u8,
    device_code: []const u8,
    verification_uri: []const u8,
    expires_in: u32,
    interval: u32,
    message: ?[]const u8,

    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Start) void {
        self.arena.deinit();
    }
};

pub fn startFromJson(gpa: std.mem.Allocator, body: []const u8) !Start {
    var parsed = std.json.parseFromSlice(
        struct {
            user_code: []const u8,
            device_code: []const u8,
            verification_uri: []const u8,
            expires_in: u32,
            interval: u32,
            message: ?[]const u8 = null,
        },
        gpa,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return error.GraphMalformedJson;
    defer parsed.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    return .{
        .user_code = try a.dupe(u8, parsed.value.user_code),
        .device_code = try a.dupe(u8, parsed.value.device_code),
        .verification_uri = try a.dupe(u8, parsed.value.verification_uri),
        .expires_in = parsed.value.expires_in,
        .interval = parsed.value.interval,
        .message = if (parsed.value.message) |m| try a.dupe(u8, m) else null,
        .arena = arena,
    };
}

pub const PollOutcome = union(enum) {
    pending: void,
    slow_down: void, // increase interval by 5 seconds
    success: Success,
    denied: void,
    expired: void,
    other: []const u8, // server error code we don't recognise
};

pub const Success = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    expires_in: u32,
    scope: ?[]const u8,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Success) void {
        self.arena.deinit();
    }
};

pub fn pollFromJson(
    gpa: std.mem.Allocator,
    http_status: u16,
    body: []const u8,
) !PollOutcome {
    if (http_status == 200) {
        var parsed = std.json.parseFromSlice(
            struct {
                access_token: []const u8,
                refresh_token: []const u8 = "",
                expires_in: u32,
                scope: ?[]const u8 = null,
            },
            gpa,
            body,
            .{ .ignore_unknown_fields = true },
        ) catch return error.GraphMalformedJson;
        defer parsed.deinit();

        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        return .{ .success = .{
            .access_token = try a.dupe(u8, parsed.value.access_token),
            .refresh_token = try a.dupe(u8, parsed.value.refresh_token),
            .expires_in = parsed.value.expires_in,
            .scope = if (parsed.value.scope) |s| try a.dupe(u8, s) else null,
            .arena = arena,
        } };
    }
    // Error responses from AAD have shape {"error":"...","error_description":"..."}
    var parsed = std.json.parseFromSlice(
        struct { @"error": []const u8 = "", error_description: ?[]const u8 = null },
        gpa,
        body,
        .{ .ignore_unknown_fields = true },
    ) catch return error.GraphMalformedJson;
    defer parsed.deinit();

    const code = parsed.value.@"error";
    if (std.mem.eql(u8, code, "authorization_pending")) return .pending;
    if (std.mem.eql(u8, code, "slow_down")) return .slow_down;
    if (std.mem.eql(u8, code, "authorization_declined")) return .denied;
    if (std.mem.eql(u8, code, "expired_token")) return .expired;
    if (std.mem.eql(u8, code, "bad_verification_code")) return .expired;
    return .{ .other = try gpa.dupe(u8, code) };
}

test "pending then success" {
    const pending_body =
        \\{"error":"authorization_pending","error_description":"waiting"}
    ;
    const outcome = try pollFromJson(std.testing.allocator, 400, pending_body);
    try std.testing.expect(outcome == .pending);

    const success_body =
        \\{"access_token":"at","refresh_token":"rt","expires_in":3600,"scope":"User.Read"}
    ;
    var s = try pollFromJson(std.testing.allocator, 200, success_body);
    defer switch (s) {
        .success => |*ss| {
            var mut = ss.*;
            mut.deinit();
        },
        else => {},
    };
    try std.testing.expect(s == .success);
}

test "denied and expired" {
    const a = std.testing.allocator;
    {
        const o = try pollFromJson(a,
            400,
            \\{"error":"authorization_declined"}
        );
        try std.testing.expect(o == .denied);
    }
    {
        const o = try pollFromJson(a,
            400,
            \\{"error":"expired_token"}
        );
        try std.testing.expect(o == .expired);
    }
    {
        const o = try pollFromJson(a,
            400,
            \\{"error":"slow_down"}
        );
        try std.testing.expect(o == .slow_down);
    }
}
