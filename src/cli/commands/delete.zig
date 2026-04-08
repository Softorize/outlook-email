//! `outlook delete <id>`

const std = @import("std");
const cli = @import("../cli.zig");
const graph = @import("../../graph/graph.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    if (args.len != 1) return error.InvalidArgument;
    try graph.deleteMessage(ctx.graph_ctx, args[0]);
    ctx.writeOk("deleted");
}
