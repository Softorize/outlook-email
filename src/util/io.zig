//! Centralised stdout / stderr helpers.
//!
//! Every CLI subcommand and the renderer used to inline
//! `_ = std.fs.File.stdout().write(s) catch {}` in roughly fifteen places.
//! This file collapses that pattern so the rest of the code never needs to
//! think about which file handle, which error path, or which buffered
//! writer to use.

const std = @import("std");

pub fn out(data: []const u8) void {
    _ = std.fs.File.stdout().write(data) catch {};
}

pub fn err(data: []const u8) void {
    _ = std.fs.File.stderr().write(data) catch {};
}

pub fn outPrint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    out(s);
}

pub fn errPrint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    err(s);
}
