//! `outlook folders`

const std = @import("std");
const cli = @import("../cli.zig");
const graph = @import("../../graph/graph.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    _ = args;
    var page = try graph.listFolders(ctx.graph_ctx, ctx.gpa);
    defer page.deinit();
    try ctx.output.writeFolderList(ctx.gpa, page.items);
}
