//! `outlook send --to a,b [--cc ...] [--bcc ...] --subject S [--attach file]...`

const std = @import("std");
const cli = @import("../cli.zig");
const args_mod = @import("../args.zig");
const compose_input = @import("../compose_input.zig");
const types = @import("../../graph/types.zig");
const send_mod = @import("../../graph/send.zig");

pub fn run(ctx: *cli.Context, args: []const []const u8) !void {
    var to_opt: ?[]const u8 = null;
    var cc_opt: ?[]const u8 = null;
    var bcc_opt: ?[]const u8 = null;
    var subject_opt: ?[]const u8 = null;
    var attach_list: std.ArrayList([]const u8) = .empty;
    defer attach_list.deinit(ctx.gpa);

    const parsed = try args_mod.parseCommand(ctx.gpa, args, &.{
        .{ .name = "--to", .flag = .{ .string_opt = &to_opt } },
        .{ .name = "--cc", .flag = .{ .string_opt = &cc_opt } },
        .{ .name = "--bcc", .flag = .{ .string_opt = &bcc_opt } },
        .{ .name = "--subject", .flag = .{ .string_opt = &subject_opt } },
        .{ .name = "--attach", .flag = .{ .string_list = &attach_list } },
    });
    defer ctx.gpa.free(parsed.positionals);

    const to_line = if (to_opt) |v| try ctx.gpa.dupe(u8, v) else try compose_input.promptLine(ctx.gpa, "To: ");
    defer ctx.gpa.free(to_line);

    const subject_line = if (subject_opt) |v| try ctx.gpa.dupe(u8, v) else try compose_input.promptLine(ctx.gpa, "Subject: ");
    defer ctx.gpa.free(subject_line);

    const body = try compose_input.readBody(ctx.gpa);
    defer ctx.gpa.free(body);

    const to_parsed = try compose_input.parseRecipientList(ctx.gpa, to_line);
    defer freeRecipientList(ctx.gpa, to_parsed);
    const to_slice = try toGraphRecipients(ctx.gpa, to_parsed);
    defer ctx.gpa.free(to_slice);

    var cc_slice: []types.Recipient = &.{};
    defer ctx.gpa.free(cc_slice);
    if (cc_opt) |v| {
        const pr = try compose_input.parseRecipientList(ctx.gpa, v);
        defer freeRecipientList(ctx.gpa, pr);
        cc_slice = try toGraphRecipients(ctx.gpa, pr);
    }

    var bcc_slice: []types.Recipient = &.{};
    defer ctx.gpa.free(bcc_slice);
    if (bcc_opt) |v| {
        const pr = try compose_input.parseRecipientList(ctx.gpa, v);
        defer freeRecipientList(ctx.gpa, pr);
        bcc_slice = try toGraphRecipients(ctx.gpa, pr);
    }

    const att_slice = try ctx.gpa.alloc(types.AttachmentInput, attach_list.items.len);
    defer ctx.gpa.free(att_slice);
    for (attach_list.items, 0..) |p, i| att_slice[i] = .{ .path = p, .name = null };

    const draft: types.Draft = .{
        .to = to_slice,
        .cc = cc_slice,
        .bcc = bcc_slice,
        .subject = subject_line,
        .body = .{ .content_type = .text, .content = body },
        .attachments = att_slice,
        .save_to_sent = true,
    };

    try send_mod.sendMail(ctx.graph_ctx, draft);
    ctx.writeOk("sent");
}

fn toGraphRecipients(gpa: std.mem.Allocator, list: []const compose_input.ParsedRecipient) ![]types.Recipient {
    const out = try gpa.alloc(types.Recipient, list.len);
    for (list, 0..) |r, i| out[i] = .{ .address = r.address, .name = r.name };
    return out;
}

fn freeRecipientList(gpa: std.mem.Allocator, list: []const compose_input.ParsedRecipient) void {
    for (list) |r| {
        gpa.free(r.address);
        if (r.name) |n| gpa.free(n);
    }
    gpa.free(list);
}
