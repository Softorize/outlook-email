//! Send-mail flows.
//!
//! Without attachments: POST /me/sendMail with the whole message inline.
//! With attachments:    create a draft, attach each file (small or large),
//!                      then POST /me/messages/{id}/send.

const std = @import("std");
const errors = @import("../errors.zig");
const graph = @import("graph.zig");
const http = @import("http.zig");
const types = @import("types.zig");
const attachments = @import("attachments.zig");

pub const Error = errors.Error;

pub fn sendMail(ctx: *graph.Ctx, draft: types.Draft) !void {
    if (draft.attachments.len == 0) {
        return sendInline(ctx, draft);
    }
    return sendWithAttachments(ctx, draft);
}

fn sendInline(ctx: *graph.Ctx, draft: types.Draft) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try buf.appendSlice(ctx.gpa, "{\"message\":");
    try attachments.writeDraftJson(&buf, ctx.gpa, draft);
    try buf.appendSlice(ctx.gpa, ",\"saveToSentItems\":");
    try buf.appendSlice(ctx.gpa, if (draft.save_to_sent) "true" else "false");
    try buf.append(ctx.gpa, '}');

    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/sendMail", .{ctx.base_url});
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 202) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

fn sendWithAttachments(ctx: *graph.Ctx, draft: types.Draft) !void {
    const draft_id = try attachments.createDraft(ctx, draft);
    defer ctx.gpa.free(draft_id);

    for (draft.attachments) |a| {
        try attachments.attachFile(ctx, draft_id, a.path, a.name);
    }

    try attachments.sendDraft(ctx, draft_id);
}
