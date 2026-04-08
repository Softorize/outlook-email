//! Tiny mime-type lookup used when building attachment payloads. Only
//! common types are listed; everything else falls back to
//! `application/octet-stream`, which Outlook handles fine.

const std = @import("std");

pub fn guessFromFilename(filename: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, filename, '.') orelse return default;
    const ext_raw = filename[dot + 1 ..];
    // lower-case compare without allocating.
    var buf: [16]u8 = undefined;
    if (ext_raw.len > buf.len) return default;
    for (ext_raw, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    const ext = buf[0..ext_raw.len];

    const table = [_]struct { []const u8, []const u8 }{
        .{ "pdf", "application/pdf" },
        .{ "txt", "text/plain" },
        .{ "log", "text/plain" },
        .{ "csv", "text/csv" },
        .{ "json", "application/json" },
        .{ "xml", "application/xml" },
        .{ "html", "text/html" },
        .{ "htm", "text/html" },
        .{ "md", "text/markdown" },
        .{ "png", "image/png" },
        .{ "jpg", "image/jpeg" },
        .{ "jpeg", "image/jpeg" },
        .{ "gif", "image/gif" },
        .{ "webp", "image/webp" },
        .{ "svg", "image/svg+xml" },
        .{ "zip", "application/zip" },
        .{ "gz", "application/gzip" },
        .{ "tar", "application/x-tar" },
        .{ "doc", "application/msword" },
        .{ "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
        .{ "xls", "application/vnd.ms-excel" },
        .{ "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
        .{ "ppt", "application/vnd.ms-powerpoint" },
        .{ "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
        .{ "mp3", "audio/mpeg" },
        .{ "mp4", "video/mp4" },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, ext, entry[0])) return entry[1];
    }
    return default;
}

const default = "application/octet-stream";

test "mime guesses" {
    try std.testing.expectEqualStrings("application/pdf", guessFromFilename("report.pdf"));
    try std.testing.expectEqualStrings("image/jpeg", guessFromFilename("pic.JPG"));
    try std.testing.expectEqualStrings("application/octet-stream", guessFromFilename("weird.xyz"));
    try std.testing.expectEqualStrings("application/octet-stream", guessFromFilename("no_extension"));
}
