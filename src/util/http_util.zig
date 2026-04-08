//! Small HTTP-related parsers and helpers used across the graph layer.

const std = @import("std");
const time = @import("time.zig");

/// Parse a Retry-After header value. Accepts either an integer number of
/// seconds or an HTTP-date (RFC 7231). Returns `null` if the header is
/// missing or unparseable; callers that care about the distinction should
/// check for the empty string themselves.
pub fn parseRetryAfter(header_value: []const u8, now_unix: i64) ?u32 {
    if (header_value.len == 0) return null;

    // Integer seconds form.
    if (std.fmt.parseInt(u32, std.mem.trim(u8, header_value, " \t"), 10)) |secs| {
        return secs;
    } else |_| {}

    // HTTP-date form, e.g. "Tue, 15 Nov 1994 08:12:31 GMT".
    if (parseHttpDate(header_value)) |target_unix| {
        if (target_unix <= now_unix) return 0;
        const diff = target_unix - now_unix;
        if (diff > std.math.maxInt(u32)) return std.math.maxInt(u32);
        return @intCast(diff);
    }
    return null;
}

/// Very permissive HTTP-date parser: accepts `DD Mon YYYY HH:MM:SS` anywhere
/// in the string. Graph's Retry-After is essentially always a numeric second
/// count; this branch exists so we don't choke on spec-compliant servers.
fn parseHttpDate(s: []const u8) ?i64 {
    // Find a month name; the date format starts the day before it.
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    var month: u32 = 0;
    var month_pos: usize = 0;
    outer: for (0..s.len) |i| {
        if (i + 3 > s.len) break;
        for (months, 0..) |name, mi| {
            if (std.mem.eql(u8, s[i .. i + 3], name)) {
                month = @intCast(mi + 1);
                month_pos = i;
                break :outer;
            }
        }
    }
    if (month == 0) return null;
    if (month_pos < 3) return null;
    // Back up across whitespace then 1-2 digit day.
    var i = month_pos - 1;
    while (i > 0 and s[i] == ' ') i -= 1;
    const day_end = i + 1;
    var day_start = day_end;
    while (day_start > 0 and s[day_start - 1] >= '0' and s[day_start - 1] <= '9') day_start -= 1;
    if (day_start == day_end) return null;
    const day = std.fmt.parseInt(u32, s[day_start..day_end], 10) catch return null;

    var j = month_pos + 4; // past "Mon "
    if (j + 4 > s.len) return null;
    const year = std.fmt.parseInt(u32, s[j .. j + 4], 10) catch return null;
    j += 5; // past "YYYY "
    if (j + 8 > s.len) return null;
    const hour = std.fmt.parseInt(u32, s[j .. j + 2], 10) catch return null;
    const minute = std.fmt.parseInt(u32, s[j + 3 .. j + 5], 10) catch return null;
    const second = std.fmt.parseInt(u32, s[j + 6 .. j + 8], 10) catch return null;

    // Reuse time.zig by constructing a synthetic ISO string.
    var buf: [32]u8 = undefined;
    const iso = std.fmt.bufPrint(
        &buf,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{ year, month, day, hour, minute, second },
    ) catch return null;
    return time.parseIso8601Utc(iso) catch null;
}

/// Percent-encode a value for safe use in a URL query string. Encodes
/// everything except unreserved characters per RFC 3986 (A-Z a-z 0-9 - _ . ~).
pub fn urlEncodeAlloc(gpa: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, value.len);
    for (value) |c| {
        if ((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~')
        {
            try out.append(gpa, c);
        } else {
            const hex = "0123456789ABCDEF";
            try out.append(gpa, '%');
            try out.append(gpa, hex[(c >> 4) & 0xF]);
            try out.append(gpa, hex[c & 0xF]);
        }
    }
    return out.toOwnedSlice(gpa);
}

/// Encode the body for `application/x-www-form-urlencoded`. Takes a slice of
/// name/value pairs.
pub fn formEncodeAlloc(
    gpa: std.mem.Allocator,
    pairs: []const [2][]const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    for (pairs, 0..) |pair, i| {
        if (i != 0) try out.append(gpa, '&');
        const k = try urlEncodeAlloc(gpa, pair[0]);
        defer gpa.free(k);
        const v = try urlEncodeAlloc(gpa, pair[1]);
        defer gpa.free(v);
        try out.appendSlice(gpa, k);
        try out.append(gpa, '=');
        try out.appendSlice(gpa, v);
    }
    return out.toOwnedSlice(gpa);
}

test "parse Retry-After integer" {
    try std.testing.expectEqual(@as(?u32, 42), parseRetryAfter("42", 0));
    try std.testing.expectEqual(@as(?u32, 0), parseRetryAfter("0", 0));
    try std.testing.expectEqual(@as(?u32, null), parseRetryAfter("", 0));
    try std.testing.expectEqual(@as(?u32, null), parseRetryAfter("soon", 0));
}

test "urlEncodeAlloc escapes" {
    const gpa = std.testing.allocator;
    const out = try urlEncodeAlloc(gpa, "hello world/?=&");
    defer gpa.free(out);
    try std.testing.expectEqualStrings("hello%20world%2F%3F%3D%26", out);
}

test "formEncodeAlloc pairs" {
    const gpa = std.testing.allocator;
    const out = try formEncodeAlloc(gpa, &.{
        .{ "grant_type", "device_code" },
        .{ "client_id", "abc-123" },
    });
    defer gpa.free(out);
    try std.testing.expectEqualStrings("grant_type=device_code&client_id=abc-123", out);
}
