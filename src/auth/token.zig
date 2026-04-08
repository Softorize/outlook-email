//! Token + account data types used by the auth layer.

const std = @import("std");
const base64url = @import("../util/base64url.zig");

pub const Account = struct {
    upn: []const u8,
    display_name: []const u8,
    home_tenant_id: []const u8,
    object_id: []const u8,
};

pub const Token = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    expires_at_unix: i64, // absolute, computed at issue time
    scopes: []const []const u8,

    pub fn isExpiringSoon(self: Token, now_unix: i64, skew_secs: i64) bool {
        return now_unix + skew_secs >= self.expires_at_unix;
    }
};

/// Decode an access-token JWT's payload and pull out the `upn` / `oid` /
/// `tid` / `name` claims. Returns owned slices in the provided allocator.
pub fn peekAccessTokenClaims(
    gpa: std.mem.Allocator,
    access_token: []const u8,
) !Account {
    const payload = base64url.decodeJwtPayloadAlloc(gpa, access_token) catch return error.GraphMalformedJson;
    defer gpa.free(payload);

    var parsed = std.json.parseFromSlice(std.json.Value, gpa, payload, .{}) catch return error.GraphMalformedJson;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.GraphMalformedJson,
    };

    const upn_s = stringField(obj, "upn") orelse stringField(obj, "preferred_username") orelse stringField(obj, "unique_name") orelse "unknown";
    const name_s = stringField(obj, "name") orelse upn_s;
    const tid_s = stringField(obj, "tid") orelse "";
    const oid_s = stringField(obj, "oid") orelse "";

    return .{
        .upn = try gpa.dupe(u8, upn_s),
        .display_name = try gpa.dupe(u8, name_s),
        .home_tenant_id = try gpa.dupe(u8, tid_s),
        .object_id = try gpa.dupe(u8, oid_s),
    };
}

fn stringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// Serialised form that lives in the keystore as `token_meta` alongside the
/// separate `refresh_token` entry.
pub const SavedMeta = struct {
    access_token: []const u8,
    expires_at_unix: i64,
};

pub fn serialiseMetaAlloc(gpa: std.mem.Allocator, meta: SavedMeta) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "{{\"access_token\":\"{s}\",\"expires_at_unix\":{d}}}",
        .{ meta.access_token, meta.expires_at_unix },
    );
}

pub fn parseMeta(gpa: std.mem.Allocator, raw: []const u8) !SavedMeta {
    var parsed = std.json.parseFromSlice(
        struct { access_token: []const u8, expires_at_unix: i64 },
        gpa,
        raw,
        .{ .ignore_unknown_fields = true },
    ) catch return error.GraphMalformedJson;
    defer parsed.deinit();
    return .{
        .access_token = try gpa.dupe(u8, parsed.value.access_token),
        .expires_at_unix = parsed.value.expires_at_unix,
    };
}

test "expiring soon boundary" {
    const tok: Token = .{
        .access_token = "x",
        .refresh_token = "y",
        .expires_at_unix = 1000,
        .scopes = &.{},
    };
    try std.testing.expect(!tok.isExpiringSoon(800, 60));
    try std.testing.expect(tok.isExpiringSoon(940, 60));
    try std.testing.expect(tok.isExpiringSoon(1000, 0));
}
