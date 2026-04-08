//! Read a message body from stdin.
//!
//! The user types the body, then terminates with either:
//!   - EOF (Ctrl-D on Unix, Ctrl-Z then Enter on Windows), or
//!   - a single "." on its own line (the classic telnet-era convention).
//!
//! We also prompt for headers (To, Subject) if they weren't passed via
//! flags. Prompt output goes to stderr so --json mode still gets a clean
//! stdout.

const std = @import("std");
const io = @import("../util/io.zig");

const promptWrite = io.err;

pub fn promptLine(gpa: std.mem.Allocator, prompt: []const u8) ![]u8 {
    promptWrite(prompt);

    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(gpa);
    var byte: [1]u8 = undefined;
    const stdin = std.fs.File.stdin();
    while (true) {
        const n = try stdin.read(&byte);
        if (n == 0) break;
        if (byte[0] == '\n') break;
        if (byte[0] == '\r') continue;
        try buf.append(gpa, byte[0]);
    }
    return buf.toOwnedSlice(gpa);
}

/// Read the body. Displays a prompt explaining the terminator. Stops on EOF
/// or on a line containing exactly ".".
pub fn readBody(gpa: std.mem.Allocator) ![]u8 {
    promptWrite(
        "Enter message body. Finish with Ctrl-D (Unix) / Ctrl-Z then Enter (Windows),\n" ++
            "or type a single '.' on its own line.\n",
    );

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);

    var byte: [1]u8 = undefined;
    const stdin = std.fs.File.stdin();
    while (true) {
        const n = try stdin.read(&byte);
        if (n == 0) break;
        const c = byte[0];
        if (c == '\r') continue;
        if (c == '\n') {
            if (line.items.len == 1 and line.items[0] == '.') {
                // Body terminator.
                return out.toOwnedSlice(gpa);
            }
            try out.appendSlice(gpa, line.items);
            try out.append(gpa, '\n');
            line.clearRetainingCapacity();
            continue;
        }
        try line.append(gpa, c);
    }
    if (line.items.len > 0) try out.appendSlice(gpa, line.items);
    return out.toOwnedSlice(gpa);
}

/// Parse a comma-separated recipient list like "alice@x.com, Bob <bob@x.com>"
/// into a slice of Recipient. The return slice is owned by the caller.
pub const ParsedRecipient = struct {
    address: []const u8,
    name: ?[]const u8,
};

pub fn parseRecipientList(gpa: std.mem.Allocator, raw: []const u8) ![]ParsedRecipient {
    var list: std.ArrayList(ParsedRecipient) = .empty;
    errdefer {
        for (list.items) |r| {
            gpa.free(r.address);
            if (r.name) |n| gpa.free(n);
        }
        list.deinit(gpa);
    }
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |chunk| {
        const trimmed = std.mem.trim(u8, chunk, " \t");
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, '<')) |lt| {
            const gt = std.mem.indexOfScalar(u8, trimmed, '>') orelse return error.InvalidRecipient;
            if (gt <= lt) return error.InvalidRecipient;
            const name = std.mem.trim(u8, trimmed[0..lt], " \t\"");
            const addr = try gpa.dupe(u8, std.mem.trim(u8, trimmed[lt + 1 .. gt], " \t"));
            errdefer gpa.free(addr);
            const name_owned: ?[]const u8 = if (name.len > 0) try gpa.dupe(u8, name) else null;
            try list.append(gpa, .{ .address = addr, .name = name_owned });
        } else {
            const addr = try gpa.dupe(u8, trimmed);
            errdefer gpa.free(addr);
            try list.append(gpa, .{ .address = addr, .name = null });
        }
    }
    return list.toOwnedSlice(gpa);
}
