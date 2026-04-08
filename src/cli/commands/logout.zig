//! `outlook logout [account]`

const std = @import("std");
const cli = @import("../cli.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    const account = if (args.len > 0)
        args[0]
    else
        (ctx.cfg.current_account orelse return error.NoCurrentAccount);
    try ctx.session.logout(account);
    ctx.writeOk("signed out");
}
