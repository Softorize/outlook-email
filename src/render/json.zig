//! Machine-readable JSON output for --json mode.
//!
//! We hand-write the JSON rather than using std.json.Stringify because our
//! types live in an arena and get re-shaped at the boundary; rolling it by
//! hand keeps output stable and removes a layer of reflection.

const std = @import("std");
const types = @import("../graph/types.zig");
const errors = @import("../errors.zig");
const io = @import("../util/io.zig");

const stdoutWrite = io.out;

fn writeEscaped(w: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    for (s) |ch| switch (ch) {
        '"' => try w.appendSlice(gpa, "\\\""),
        '\\' => try w.appendSlice(gpa, "\\\\"),
        '\n' => try w.appendSlice(gpa, "\\n"),
        '\r' => try w.appendSlice(gpa, "\\r"),
        '\t' => try w.appendSlice(gpa, "\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
            var bb: [8]u8 = undefined;
            const hex = std.fmt.bufPrint(&bb, "\\u{x:0>4}", .{ch}) catch unreachable;
            try w.appendSlice(gpa, hex);
        },
        else => try w.append(gpa, ch),
    };
}

fn flush(w: *std.ArrayList(u8)) void {
    stdoutWrite(w.items);
}

pub fn writeMessageList(list: []const types.MessageSummary, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.append(gpa, '[');
    for (list, 0..) |m, i| {
        if (i != 0) try buf.append(gpa, ',');
        try buf.appendSlice(gpa, "{\"id\":\"");
        try writeEscaped(&buf, gpa, m.id);
        try buf.appendSlice(gpa, "\",\"subject\":\"");
        try writeEscaped(&buf, gpa, m.subject);
        try buf.appendSlice(gpa, "\",\"from\":{\"address\":\"");
        try writeEscaped(&buf, gpa, m.from.address);
        try buf.append(gpa, '"');
        if (m.from.name) |n| {
            try buf.appendSlice(gpa, ",\"name\":\"");
            try writeEscaped(&buf, gpa, n);
            try buf.append(gpa, '"');
        }
        try buf.appendSlice(gpa, "},\"received_at\":\"");
        try writeEscaped(&buf, gpa, m.received_at);
        try buf.appendSlice(gpa, "\",\"is_read\":");
        try buf.appendSlice(gpa, if (m.is_read) "true" else "false");
        try buf.appendSlice(gpa, ",\"has_attachments\":");
        try buf.appendSlice(gpa, if (m.has_attachments) "true" else "false");
        try buf.appendSlice(gpa, ",\"preview\":\"");
        try writeEscaped(&buf, gpa, m.preview);
        try buf.appendSlice(gpa, "\"}");
    }
    try buf.appendSlice(gpa, "]\n");
    flush(&buf);
}

pub fn writeMessage(m: types.Message, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"id\":\"");
    try writeEscaped(&buf, gpa, m.id);
    try buf.appendSlice(gpa, "\",\"conversation_id\":\"");
    try writeEscaped(&buf, gpa, m.conversation_id);
    try buf.appendSlice(gpa, "\",\"subject\":\"");
    try writeEscaped(&buf, gpa, m.subject);
    try buf.appendSlice(gpa, "\",\"from\":");
    try writeRecipient(&buf, gpa, m.from);
    try buf.appendSlice(gpa, ",\"to\":");
    try writeRecipients(&buf, gpa, m.to);
    try buf.appendSlice(gpa, ",\"cc\":");
    try writeRecipients(&buf, gpa, m.cc);
    try buf.appendSlice(gpa, ",\"received_at\":\"");
    try writeEscaped(&buf, gpa, m.received_at);
    try buf.appendSlice(gpa, "\",\"body\":{\"content_type\":\"");
    try buf.appendSlice(gpa, switch (m.body.content_type) {
        .text => "text",
        .html => "html",
    });
    try buf.appendSlice(gpa, "\",\"content\":\"");
    try writeEscaped(&buf, gpa, m.body.content);
    try buf.appendSlice(gpa, "\"},\"attachments\":[");
    for (m.attachments, 0..) |a, i| {
        if (i != 0) try buf.append(gpa, ',');
        try buf.appendSlice(gpa, "{\"id\":\"");
        try writeEscaped(&buf, gpa, a.id);
        try buf.appendSlice(gpa, "\",\"name\":\"");
        try writeEscaped(&buf, gpa, a.name);
        try buf.appendSlice(gpa, "\",\"content_type\":\"");
        try writeEscaped(&buf, gpa, a.content_type);
        try buf.appendSlice(gpa, "\",\"size\":");
        var num_buf: [32]u8 = undefined;
        const s = try std.fmt.bufPrint(&num_buf, "{d}", .{a.size});
        try buf.appendSlice(gpa, s);
        try buf.append(gpa, '}');
    }
    try buf.appendSlice(gpa, "]}\n");
    flush(&buf);
}

fn writeRecipient(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, r: types.Recipient) !void {
    try buf.appendSlice(gpa, "{\"address\":\"");
    try writeEscaped(buf, gpa, r.address);
    try buf.append(gpa, '"');
    if (r.name) |n| {
        try buf.appendSlice(gpa, ",\"name\":\"");
        try writeEscaped(buf, gpa, n);
        try buf.append(gpa, '"');
    }
    try buf.append(gpa, '}');
}

fn writeRecipients(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, rs: []const types.Recipient) !void {
    try buf.append(gpa, '[');
    for (rs, 0..) |r, i| {
        if (i != 0) try buf.append(gpa, ',');
        try writeRecipient(buf, gpa, r);
    }
    try buf.append(gpa, ']');
}

pub fn writeFolderList(list: []const types.Folder, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.append(gpa, '[');
    for (list, 0..) |f, i| {
        if (i != 0) try buf.append(gpa, ',');
        try buf.appendSlice(gpa, "{\"id\":\"");
        try writeEscaped(&buf, gpa, f.id);
        try buf.appendSlice(gpa, "\",\"display_name\":\"");
        try writeEscaped(&buf, gpa, f.display_name);
        try buf.appendSlice(gpa, "\",\"total\":");
        var nb: [32]u8 = undefined;
        try buf.appendSlice(gpa, try std.fmt.bufPrint(&nb, "{d}", .{f.total_item_count}));
        try buf.appendSlice(gpa, ",\"unread\":");
        try buf.appendSlice(gpa, try std.fmt.bufPrint(&nb, "{d}", .{f.unread_item_count}));
        try buf.append(gpa, '}');
    }
    try buf.appendSlice(gpa, "]\n");
    flush(&buf);
}

pub fn writeAccounts(list: []const []const u8, current: ?[]const u8, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"current\":");
    if (current) |c| {
        try buf.append(gpa, '"');
        try writeEscaped(&buf, gpa, c);
        try buf.append(gpa, '"');
    } else {
        try buf.appendSlice(gpa, "null");
    }
    try buf.appendSlice(gpa, ",\"accounts\":[");
    for (list, 0..) |a, i| {
        if (i != 0) try buf.append(gpa, ',');
        try buf.append(gpa, '"');
        try writeEscaped(&buf, gpa, a);
        try buf.append(gpa, '"');
    }
    try buf.appendSlice(gpa, "]}\n");
    flush(&buf);
}

pub fn writeError(diag: errors.Diagnostic, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"error\":\"");
    try writeEscaped(&buf, gpa, errors.shortName(diag.err));
    try buf.appendSlice(gpa, "\",\"message\":\"");
    try writeEscaped(&buf, gpa, errors.defaultMessage(diag.err));
    try buf.append(gpa, '"');
    if (diag.http_status) |s| {
        var nb: [16]u8 = undefined;
        try buf.appendSlice(gpa, ",\"http_status\":");
        try buf.appendSlice(gpa, try std.fmt.bufPrint(&nb, "{d}", .{s}));
    }
    if (diag.retry_after_seconds) |s| {
        var nb: [16]u8 = undefined;
        try buf.appendSlice(gpa, ",\"retry_after_seconds\":");
        try buf.appendSlice(gpa, try std.fmt.bufPrint(&nb, "{d}", .{s}));
    }
    if (diag.server_message) |msg| {
        try buf.appendSlice(gpa, ",\"server_message\":\"");
        try writeEscaped(&buf, gpa, msg);
        try buf.append(gpa, '"');
    }
    try buf.appendSlice(gpa, "}\n");
    io.err(buf.items);
}

pub fn writeOk(message: []const u8, gpa: std.mem.Allocator) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try buf.appendSlice(gpa, "{\"ok\":true,\"message\":\"");
    try writeEscaped(&buf, gpa, message);
    try buf.appendSlice(gpa, "\"}\n");
    flush(&buf);
}
