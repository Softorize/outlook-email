//! `outlook forward <id> --to a,b [--attach file]...`

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const compose_input = @import("../compose_input.zig");
const graph = @import("../../graph/graph.zig");
const types = @import("../../graph/types.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var to_opt: ?[]const u8 = null;
    var attach_list: std.ArrayList([]const u8) = .empty;
    defer attach_list.deinit(ctx.gpa);

    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--to", .flag = .{ .string_opt = &to_opt } },
        .{ .name = "--attach", .flag = .{ .string_list = &attach_list } },
    });
    defer ctx.gpa.free(parsed.positionals);
    if (parsed.positionals.len != 1) return error.InvalidArgument;
    const id = parsed.positionals[0];

    const to_line = if (to_opt) |v| try ctx.gpa.dupe(u8, v) else try compose_input.promptLine(ctx.gpa, "Forward to: ");
    defer ctx.gpa.free(to_line);

    const body = try compose_input.readBody(ctx.gpa);
    defer ctx.gpa.free(body);

    const parsed_rs = try compose_input.parseRecipientList(ctx.gpa, to_line);
    defer {
        for (parsed_rs) |r| {
            ctx.gpa.free(r.address);
            if (r.name) |n| ctx.gpa.free(n);
        }
        ctx.gpa.free(parsed_rs);
    }
    const to_slice = try ctx.gpa.alloc(types.Recipient, parsed_rs.len);
    defer ctx.gpa.free(to_slice);
    for (parsed_rs, 0..) |r, i| to_slice[i] = .{ .address = r.address, .name = r.name };

    // Attachments on forward aren't supported through the Graph /forward
    // endpoint either. If the user passed --attach, tell them up front.
    if (attach_list.items.len > 0) {
        @import("../../util/io.zig").err(
            "ocli: --attach on forward is not supported in v1.\n" ++
                "         Use 'ocli send' with --attach instead.\n",
        );
        return error.InvalidArgument;
    }

    try graph.forwardMessage(ctx.graph_ctx, id, to_slice, body);
    ctx.writeOk("forwarded");
}
