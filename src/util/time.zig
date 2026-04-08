//! ISO-8601 / RFC3339 helpers.
//!
//! Microsoft Graph returns timestamps like `2026-04-08T14:23:00Z` or with a
//! fractional second (`2026-04-08T14:23:00.1234567Z`). We don't need a full
//! datetime library; we just need to (a) parse Graph strings into an epoch
//! seconds value for comparison and (b) render a local-timezone-aware short
//! form for human output. For scripting output we pass the original string
//! through untouched.

const std = @import("std");

pub const ParseError = error{BadIsoTimestamp};

/// Parse a subset of ISO-8601 sufficient for Microsoft Graph responses.
/// Accepts `YYYY-MM-DDTHH:MM:SS[.fff...][Z|+HH:MM|-HH:MM]`.
/// Returns Unix epoch seconds (UTC).
pub fn parseIso8601Utc(s: []const u8) ParseError!i64 {
    if (s.len < 19) return error.BadIsoTimestamp;
    const year = parseDigits(s[0..4]) catch return error.BadIsoTimestamp;
    if (s[4] != '-') return error.BadIsoTimestamp;
    const month = parseDigits(s[5..7]) catch return error.BadIsoTimestamp;
    if (s[7] != '-') return error.BadIsoTimestamp;
    const day = parseDigits(s[8..10]) catch return error.BadIsoTimestamp;
    if (s[10] != 'T' and s[10] != 't' and s[10] != ' ') return error.BadIsoTimestamp;
    const hour = parseDigits(s[11..13]) catch return error.BadIsoTimestamp;
    if (s[13] != ':') return error.BadIsoTimestamp;
    const minute = parseDigits(s[14..16]) catch return error.BadIsoTimestamp;
    if (s[16] != ':') return error.BadIsoTimestamp;
    const second = parseDigits(s[17..19]) catch return error.BadIsoTimestamp;

    var idx: usize = 19;
    if (idx < s.len and s[idx] == '.') {
        idx += 1;
        while (idx < s.len and s[idx] >= '0' and s[idx] <= '9') idx += 1;
    }

    var tz_offset_seconds: i32 = 0;
    if (idx < s.len) {
        const tz = s[idx];
        if (tz == 'Z' or tz == 'z') {
            idx += 1;
        } else if (tz == '+' or tz == '-') {
            if (idx + 6 > s.len) return error.BadIsoTimestamp;
            const sign: i32 = if (tz == '+') 1 else -1;
            const tz_h = parseDigits(s[idx + 1 .. idx + 3]) catch return error.BadIsoTimestamp;
            if (s[idx + 3] != ':') return error.BadIsoTimestamp;
            const tz_m = parseDigits(s[idx + 4 .. idx + 6]) catch return error.BadIsoTimestamp;
            tz_offset_seconds = sign * (@as(i32, @intCast(tz_h)) * 3600 + @as(i32, @intCast(tz_m)) * 60);
            idx += 6;
        } else {
            return error.BadIsoTimestamp;
        }
    }
    if (idx != s.len) return error.BadIsoTimestamp;

    const epoch = civilToUnix(
        @intCast(year),
        @intCast(month),
        @intCast(day),
        @intCast(hour),
        @intCast(minute),
        @intCast(second),
    );
    return epoch - tz_offset_seconds;
}

fn parseDigits(s: []const u8) !u32 {
    var n: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.NotDigit;
        n = n * 10 + (c - '0');
    }
    return n;
}

/// Howard Hinnant's civil_from_days, inlined.
fn civilToUnix(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) i64 {
    var y = year;
    var m = month;
    if (m <= 2) {
        y -= 1;
        m += 12;
    }
    const era = @divFloor(y, 400);
    const yoe: i64 = y - era * 400; // [0, 399]
    const mm: i64 = @intCast(m);
    const dd: i64 = @intCast(day);
    const doy: i64 = @divFloor(153 * (mm - 3) + 2, 5) + dd - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days_since_epoch: i64 = @as(i64, @intCast(era)) * 146097 + doe - 719468;
    return days_since_epoch * 86400 +
        @as(i64, @intCast(hour)) * 3600 +
        @as(i64, @intCast(minute)) * 60 +
        @as(i64, @intCast(second));
}

/// Format "today HH:MM" / "yesterday HH:MM" / "Mon DD" / "YYYY-MM-DD" based on
/// how recent `ts` is relative to `now`. Keeps output short for the inbox
/// list view.
pub fn formatShort(buf: []u8, ts: i64, now: i64) []u8 {
    const delta = now - ts;
    const day_secs: i64 = 86400;
    const days = @divFloor(delta, day_secs);

    // Extract HH:MM of the timestamp in UTC (good enough for now; proper local
    // TZ would need /etc/localtime parsing on Unix and GetTimeZoneInformation
    // on Windows -- out of scope for v1).
    const day_start = @divFloor(ts, day_secs) * day_secs;
    const secs_in_day: u32 = @intCast(ts - day_start);
    const hh = secs_in_day / 3600;
    const mm = (secs_in_day % 3600) / 60;

    if (days == 0) {
        return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ hh, mm }) catch buf[0..0];
    }
    if (days < 7) {
        return std.fmt.bufPrint(buf, "{d}d ago", .{days}) catch buf[0..0];
    }
    // Fall back to a date stamp. Walk the civil calendar backwards from the
    // Unix epoch.
    const civil = unixToCivil(ts);
    return std.fmt.bufPrint(
        buf,
        "{d:0>4}-{d:0>2}-{d:0>2}",
        .{ civil.year, civil.month, civil.day },
    ) catch buf[0..0];
}

pub const Civil = struct { year: i32, month: u32, day: u32 };

pub fn unixToCivil(ts: i64) Civil {
    const day_secs: i64 = 86400;
    const z = @divFloor(ts, day_secs) + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: i64 = z - era * 146097; // [0, 146096]
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m: i64 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (m <= 2) y + 1 else y;
    return .{
        .year = @intCast(year),
        .month = @intCast(m),
        .day = @intCast(d),
    };
}

test "parse Z suffix" {
    const ts = try parseIso8601Utc("2026-04-08T14:23:00Z");
    try std.testing.expectEqual(@as(i64, 1775996580), ts);
}

test "parse fractional seconds" {
    const ts = try parseIso8601Utc("2026-04-08T14:23:00.1234567Z");
    try std.testing.expectEqual(@as(i64, 1775996580), ts);
}

test "parse positive offset" {
    const ts = try parseIso8601Utc("2026-04-08T16:23:00+02:00");
    try std.testing.expectEqual(@as(i64, 1775996580), ts);
}

test "reject malformed" {
    try std.testing.expectError(error.BadIsoTimestamp, parseIso8601Utc("not a date"));
    try std.testing.expectError(error.BadIsoTimestamp, parseIso8601Utc("2026/04/08"));
}
