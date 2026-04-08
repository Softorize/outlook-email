//! `outlook login` -- start OAuth 2.0 device code flow.

const std = @import("std");
const cli = @import("../cli.zig");
const config = @import("../../config/config.zig");
const io = @import("../../util/io.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    _ = args;
    try config.ensureClientId(ctx.cfg);

    const acct = try ctx.session.loginDeviceFlow(displayPrompt);
    defer freeAccount(ctx.gpa, acct);

    var cfg_copy = ctx.cfg.*;
    cfg_copy.current_account = acct.upn;
    config.save(ctx.gpa, &cfg_copy) catch {};

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "Signed in as {s}", .{acct.upn}) catch "signed in";
    ctx.writeOk(msg);
}

fn displayPrompt(verification_uri: []const u8, user_code: []const u8, message: ?[]const u8) void {
    if (message) |m| {
        io.errPrint("{s}\n", .{m});
    } else {
        io.errPrint(
            "To sign in, open {s} in a browser and enter the code:\n\n    {s}\n\n",
            .{ verification_uri, user_code },
        );
    }
    io.err("Waiting for you to finish signing in...\n");
}

fn freeAccount(gpa: std.mem.Allocator, a: @import("../../auth/token.zig").Account) void {
    gpa.free(a.upn);
    gpa.free(a.display_name);
    gpa.free(a.home_tenant_id);
    gpa.free(a.object_id);
}
