//! `outlook use <account>`

const std = @import("std");
const cli = @import("../cli.zig");
const config = @import("../../config/config.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    if (args.len != 1) return error.InvalidArgument;
    try ctx.session.setCurrent(args[0]);

    var cfg_copy = ctx.cfg.*;
    cfg_copy.current_account = args[0];
    config.save(ctx.gpa, &cfg_copy) catch {};

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "now using {s}", .{args[0]}) catch "switched";
    ctx.writeOk(msg);
}
