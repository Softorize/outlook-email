//! `ocli login` -- sign in to Microsoft 365.
//!
//! Two flavours:
//!   * Default: OAuth 2.0 device code flow (short user-code typed into
//!     microsoft.com/devicelogin).
//!   * `--browser` / `--paste`: OAuth 2.0 authorization code flow with PKCE,
//!     dbxcli-style. The CLI prints a URL, the user opens it in their own
//!     browser (Chrome, Firefox, anything), signs in, and pastes the
//!     resulting redirect URL back into the terminal.

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const config = @import("../../config/config.zig");
const io = @import("../../util/io.zig");
const compose_input = @import("../compose_input.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    try config.ensureClientId(ctx.cfg);

    var use_browser: bool = false;
    const specs = [_]args_mod.CmdSpec{
        .{ .name = "--browser", .flag = .{ .bool_flag = &use_browser } },
        .{ .name = "--paste", .flag = .{ .bool_flag = &use_browser } },
    };
    const parsed = try args_mod.parseCommand(ctx.gpa, args, &specs);
    defer ctx.gpa.free(parsed.positionals);

    const acct = if (use_browser)
        try ctx.session.loginAuthCode(browserPrompt)
    else
        try ctx.session.loginDeviceFlow(deviceDisplayPrompt);
    defer freeAccount(ctx.gpa, acct);

    var cfg_copy = ctx.cfg.*;
    cfg_copy.current_account = acct.upn;
    config.save(ctx.gpa, &cfg_copy) catch {};

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "Signed in as {s}", .{acct.upn}) catch "signed in";
    ctx.writeOk(msg);
}

fn deviceDisplayPrompt(verification_uri: []const u8, user_code: []const u8, message: ?[]const u8) void {
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

fn browserPrompt(gpa: std.mem.Allocator, authorize_url: []const u8) anyerror![]u8 {
    io.errPrint(
        \\Open this URL in your browser and sign in:
        \\
        \\    {s}
        \\
        \\After sign-in, the browser will land on a blank Microsoft page whose
        \\URL ends with '?code=...'. Copy that URL from the address bar and
        \\paste it here (or paste just the code), then press Enter.
        \\
        \\
    , .{authorize_url});
    return compose_input.promptLine(gpa, "> ");
}

fn freeAccount(gpa: std.mem.Allocator, a: @import("../../auth/token.zig").Account) void {
    gpa.free(a.upn);
    gpa.free(a.display_name);
    gpa.free(a.home_tenant_id);
    gpa.free(a.object_id);
}
