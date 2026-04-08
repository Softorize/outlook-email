//! Minimal structured logging used only when --verbose is passed. Writes to
//! stderr. Off by default so normal invocations stay quiet.

const std = @import("std");
const io = @import("io.zig");

var verbose_enabled: bool = false;

pub fn setVerbose(on: bool) void {
    verbose_enabled = on;
}

pub fn isVerbose() bool {
    return verbose_enabled;
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    if (!verbose_enabled) return;
    io.errPrint(fmt ++ "\n", args);
}
