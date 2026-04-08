//! High-level Graph API used by CLI commands.
//!
//! Exposes strongly-typed operations that internally call `graph/http.zig`
//! and parse Graph JSON responses into the Zig types in `graph/types.zig`.
//! Every function that returns collections or a full message returns a
//! `Page(T)` or a `Loaded(T)` that owns an arena; callers deinit once.

const std = @import("std");
const errors = @import("../errors.zig");
const http = @import("http.zig");
const auth = @import("../auth/auth.zig");
const types = @import("types.zig");
const http_util = @import("../util/http_util.zig");

pub const Error = errors.Error;

pub const Ctx = struct {
    gpa: std.mem.Allocator,
    http_client: *http.Client,
    session: *auth.Session,
    base_url: []const u8 = "https://graph.microsoft.com/v1.0",
};

pub fn Page(comptime T: type) type {
    return struct {
        items: []T,
        next_link: ?[]const u8,
        arena: std.heap.ArenaAllocator,

        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
    };
}

pub fn Loaded(comptime T: type) type {
    return struct {
        value: T,
        arena: std.heap.ArenaAllocator,

        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
    };
}

pub const ListOpts = struct {
    top: u32 = 25,
    folder: ?[]const u8 = null, // folder id or well-known name
    unread_only: bool = false,
};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub fn listInbox(ctx: *Ctx, gpa: std.mem.Allocator, opts: ListOpts) !Page(types.MessageSummary) {
    const folder = opts.folder orelse "inbox";
    return listFolderImpl(ctx, gpa, folder, opts);
}

fn listFolderImpl(
    ctx: *Ctx,
    gpa: std.mem.Allocator,
    folder: []const u8,
    opts: ListOpts,
) !Page(types.MessageSummary) {
    var query: std.ArrayList(u8) = .empty;
    defer query.deinit(ctx.gpa);
    try query.writer(ctx.gpa).print(
        "$top={d}&$select=id,subject,from,sender,receivedDateTime,isRead,hasAttachments,bodyPreview,importance&$orderby=receivedDateTime%20desc",
        .{opts.top},
    );
    if (opts.unread_only) try query.appendSlice(ctx.gpa, "&$filter=isRead%20eq%20false");

    const url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/mailFolders/{s}/messages?{s}",
        .{ ctx.base_url, folder, query.items },
    );
    defer ctx.gpa.free(url);

    return fetchMessageList(ctx, gpa, url);
}

fn fetchMessageList(ctx: *Ctx, gpa: std.mem.Allocator, url: []const u8) !Page(types.MessageSummary) {
    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .GET,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 200) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const Env = types.ListEnvelope(types.RawMessageSummary);
    const parsed = std.json.parseFromSliceLeaky(Env, a, resp.body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.GraphMalformedJson;

    const items = try a.alloc(types.MessageSummary, parsed.value.len);
    for (parsed.value, 0..) |raw, i| {
        const from_raw = raw.from orelse raw.sender;
        items[i] = .{
            .id = raw.id,
            .subject = raw.subject orelse "(no subject)",
            .from = if (from_raw) |f| types.convertRecipient(f) else .{ .address = "", .name = null },
            .received_at = raw.receivedDateTime,
            .is_read = raw.isRead,
            .has_attachments = raw.hasAttachments,
            .preview = raw.bodyPreview,
            .importance = types.parseImportance(raw.importance),
        };
    }

    return .{
        .items = items,
        .next_link = parsed.@"@odata.nextLink",
        .arena = arena,
    };
}

pub fn getMessage(ctx: *Ctx, gpa: std.mem.Allocator, id: []const u8) !Loaded(types.Message) {
    const url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/messages/{s}?$expand=attachments($select=id,name,contentType,size,isInline)",
        .{ ctx.base_url, id },
    );
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .GET,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 200) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const raw = std.json.parseFromSliceLeaky(types.RawMessageFull, a, resp.body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.GraphMalformedJson;

    const to_slice = try a.alloc(types.Recipient, raw.toRecipients.len);
    types.convertRecipients(raw.toRecipients, to_slice);
    const cc_slice = try a.alloc(types.Recipient, raw.ccRecipients.len);
    types.convertRecipients(raw.ccRecipients, cc_slice);
    const bcc_slice = try a.alloc(types.Recipient, raw.bccRecipients.len);
    types.convertRecipients(raw.bccRecipients, bcc_slice);

    var atts: []types.AttachmentMeta = &.{};
    if (raw.attachments) |src| {
        const out = try a.alloc(types.AttachmentMeta, src.len);
        for (src, 0..) |r, i| out[i] = .{
            .id = r.id,
            .name = r.name,
            .content_type = r.contentType,
            .size = r.size,
            .is_inline = r.isInline,
        };
        atts = out;
    }

    const body = raw.body orelse types.RawBody{};
    const from_raw = raw.from orelse raw.sender;

    return .{
        .value = .{
            .id = raw.id,
            .conversation_id = raw.conversationId orelse "",
            .subject = raw.subject orelse "(no subject)",
            .from = if (from_raw) |f| types.convertRecipient(f) else .{ .address = "", .name = null },
            .to = to_slice,
            .cc = cc_slice,
            .bcc = bcc_slice,
            .received_at = raw.receivedDateTime,
            .sent_at = raw.sentDateTime,
            .body = .{
                .content_type = types.parseBodyType(body.contentType),
                .content = body.content,
            },
            .is_read = raw.isRead,
            .has_attachments = raw.hasAttachments,
            .importance = types.parseImportance(raw.importance),
            .web_link = raw.webLink,
            .attachments = atts,
        },
        .arena = arena,
    };
}

pub fn deleteMessage(ctx: *Ctx, id: []const u8) !void {
    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}", .{ ctx.base_url, id });
    defer ctx.gpa.free(url);
    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .DELETE,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 204 and resp.status != 200) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

pub fn moveMessage(ctx: *Ctx, id: []const u8, destination_folder_id: []const u8) !void {
    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}/move", .{ ctx.base_url, id });
    defer ctx.gpa.free(url);
    const body = try std.fmt.allocPrint(ctx.gpa, "{{\"destinationId\":\"{s}\"}}", .{destination_folder_id});
    defer ctx.gpa.free(body);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = body,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 201 and resp.status != 200) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

pub fn archiveMessage(ctx: *Ctx, id: []const u8) !void {
    return moveMessage(ctx, id, "archive");
}

pub fn replyMessage(
    ctx: *Ctx,
    id: []const u8,
    body_text: []const u8,
    reply_all: bool,
) !void {
    const suffix = if (reply_all) "replyAll" else "reply";
    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}/{s}", .{ ctx.base_url, id, suffix });
    defer ctx.gpa.free(url);

    var body_buf: std.ArrayList(u8) = .empty;
    defer body_buf.deinit(ctx.gpa);
    try body_buf.appendSlice(ctx.gpa, "{\"comment\":\"");
    try writeJsonEscaped(&body_buf, ctx.gpa, body_text);
    try body_buf.appendSlice(ctx.gpa, "\"}");

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = body_buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
        .expects_response_body = false,
    });
    defer resp.deinit();
    if (resp.status != 202) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

pub fn forwardMessage(
    ctx: *Ctx,
    id: []const u8,
    to: []const types.Recipient,
    body_text: []const u8,
) !void {
    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}/forward", .{ ctx.base_url, id });
    defer ctx.gpa.free(url);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try buf.appendSlice(ctx.gpa, "{\"comment\":\"");
    try writeJsonEscaped(&buf, ctx.gpa, body_text);
    try buf.appendSlice(ctx.gpa, "\",\"toRecipients\":");
    try @import("attachments.zig").writeRecipientsJson(&buf, ctx.gpa, to);
    try buf.append(ctx.gpa, '}');

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
        .expects_response_body = false,
    });
    defer resp.deinit();
    if (resp.status != 202) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

pub fn searchMessages(ctx: *Ctx, gpa: std.mem.Allocator, query: []const u8, top: u32) !Page(types.MessageSummary) {
    const encoded = try http_util.urlEncodeAlloc(ctx.gpa, query);
    defer ctx.gpa.free(encoded);
    const url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/messages?$search=%22{s}%22&$top={d}&$select=id,subject,from,receivedDateTime,isRead,hasAttachments,bodyPreview,importance",
        .{ ctx.base_url, encoded, top },
    );
    defer ctx.gpa.free(url);

    return fetchMessageList(ctx, gpa, url);
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

pub fn listFolders(ctx: *Ctx, gpa: std.mem.Allocator) !Page(types.Folder) {
    const url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/mailFolders?$top=200",
        .{ctx.base_url},
    );
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .GET,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 200) {
        reportGraphError(resp.status, resp.body);
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const Env = types.ListEnvelope(types.RawFolder);
    const parsed = std.json.parseFromSliceLeaky(Env, a, resp.body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch return error.GraphMalformedJson;

    const items = try a.alloc(types.Folder, parsed.value.len);
    for (parsed.value, 0..) |raw, i| items[i] = .{
        .id = raw.id,
        .display_name = raw.displayName,
        .parent_folder_id = raw.parentFolderId,
        .total_item_count = raw.totalItemCount,
        .unread_item_count = raw.unreadItemCount,
        .well_known_name = if (raw.wellKnownName) |n| types.wellKnownFromName(n) else .unknown,
    };

    return .{
        .items = items,
        .next_link = parsed.@"@odata.nextLink",
        .arena = arena,
    };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn writeJsonEscaped(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    for (s) |ch| switch (ch) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\r' => try out.appendSlice(gpa, "\\r"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
            var buf: [6]u8 = undefined;
            const hex = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{ch}) catch unreachable;
            try out.appendSlice(gpa, hex);
        },
        else => try out.append(gpa, ch),
    };
}

fn reportGraphError(status: u16, body: []const u8) void {
    @import("../util/io.zig").errPrint("ocli: Graph returned HTTP {d}: {s}\n", .{ status, body });
}
