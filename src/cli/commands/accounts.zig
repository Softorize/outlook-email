//! `outlook accounts`

const std = @import("std");
const cli = @import("../cli.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    _ = args;
    const list = try ctx.session.listAccounts(ctx.gpa);
    defer {
        for (list) |a| ctx.gpa.free(a);
        ctx.gpa.free(list);
    }
    try ctx.output.writeAccounts(ctx.gpa, list, ctx.cfg.current_account);
}
