//! Base64url decoding helpers, used to peek at JWT claims.

const std = @import("std");

pub fn decodeAlloc(gpa: std.mem.Allocator, src: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const dest_len = decoder.calcSizeForSlice(src) catch return error.InvalidBase64;
    const out = try gpa.alloc(u8, dest_len);
    errdefer gpa.free(out);
    decoder.decode(out, src) catch return error.InvalidBase64;
    return out;
}

/// JWTs are `header.payload.signature`. Returns the decoded payload bytes.
pub fn decodeJwtPayloadAlloc(gpa: std.mem.Allocator, jwt: []const u8) ![]u8 {
    var it = std.mem.splitScalar(u8, jwt, '.');
    _ = it.next() orelse return error.InvalidJwt;
    const payload_b64 = it.next() orelse return error.InvalidJwt;
    return decodeAlloc(gpa, payload_b64);
}

test "decode unpadded base64url" {
    const gpa = std.testing.allocator;
    const out = try decodeAlloc(gpa, "aGVsbG8");
    defer gpa.free(out);
    try std.testing.expectEqualStrings("hello", out);
}
