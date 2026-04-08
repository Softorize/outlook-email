//! `outlook list [--folder X] [--top N] [--unread]`

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const graph = @import("../../graph/graph.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var folder_opt: ?[]const u8 = null;
    var top_s_opt: ?[]const u8 = null;
    var unread_only: bool = false;

    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--folder", .flag = .{ .string_opt = &folder_opt } },
        .{ .name = "--top", .flag = .{ .string_opt = &top_s_opt } },
        .{ .name = "--unread", .flag = .{ .bool_flag = &unread_only } },
    });
    defer ctx.gpa.free(parsed.positionals);

    const top: u32 = if (top_s_opt) |v| std.fmt.parseInt(u32, v, 10) catch 25 else 25;

    if (ctx.cfg.current_account == null) return error.NoCurrentAccount;

    var page = try graph.listInbox(ctx.graph_ctx, ctx.gpa, .{
        .top = top,
        .folder = folder_opt,
        .unread_only = unread_only,
    });
    defer page.deinit();
    try ctx.output.writeMessageList(ctx.gpa, page.items);
}
