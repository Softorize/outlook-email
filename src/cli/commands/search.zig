//! `outlook search <query> [--top N]`

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const graph = @import("../../graph/graph.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var top_s_opt: ?[]const u8 = null;
    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--top", .flag = .{ .string_opt = &top_s_opt } },
    });
    defer ctx.gpa.free(parsed.positionals);
    if (parsed.positionals.len != 1) return error.InvalidArgument;

    const top: u32 = if (top_s_opt) |v| std.fmt.parseInt(u32, v, 10) catch 25 else 25;

    var page = try graph.searchMessages(ctx.graph_ctx, ctx.gpa, parsed.positionals[0], top);
    defer page.deinit();
    try ctx.output.writeMessageList(ctx.gpa, page.items);
}
