//! `outlook read <id> [--save-attachments DIR]`

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const graph = @import("../../graph/graph.zig");
const attachments = @import("../../graph/attachments.zig");
const io = @import("../../util/io.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var save_dir_opt: ?[]const u8 = null;
    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--save-attachments", .flag = .{ .string_opt = &save_dir_opt } },
    });
    defer ctx.gpa.free(parsed.positionals);

    if (parsed.positionals.len != 1) return error.InvalidArgument;
    const id = parsed.positionals[0];

    var loaded = try graph.getMessage(ctx.graph_ctx, ctx.gpa, id);
    defer loaded.deinit();

    try ctx.output.writeMessage(ctx.gpa, loaded.value);

    if (save_dir_opt) |dir| {
        for (loaded.value.attachments) |a| {
            const path = try std.fs.path.join(ctx.gpa, &.{ dir, a.name });
            defer ctx.gpa.free(path);
            try attachments.downloadAttachment(ctx.graph_ctx, id, a.id, path);
            io.errPrint("saved {s}\n", .{path});
        }
    }
}
