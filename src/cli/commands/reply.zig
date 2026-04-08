//! `outlook reply <id> [--all]`
//!
//! Reads the reply body from stdin (multi-line, EOF or `.`-line to finish).
//! Attachments on reply are not yet implemented in v1 -- Graph's /reply
//! endpoint takes a plain-text comment, and attachment-bearing replies
//! require the "create reply draft -> attach -> send" flow. Forward already
//! supports that path; if we need attachments on reply too we can reuse
//! attachments.zig.

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const compose_input = @import("../compose_input.zig");
const graph = @import("../../graph/graph.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var all: bool = false;
    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--all", .flag = .{ .bool_flag = &all } },
    });
    defer ctx.gpa.free(parsed.positionals);
    if (parsed.positionals.len != 1) return error.InvalidArgument;

    const body = try compose_input.readBody(ctx.gpa);
    defer ctx.gpa.free(body);

    try graph.replyMessage(ctx.graph_ctx, parsed.positionals[0], body, all);
    ctx.writeOk("reply sent");
}
