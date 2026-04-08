//! Attachment upload and download for Microsoft Graph.
//!
//! Small files (< 3 MB after base64 encoding) go inline in the `sendMail`
//! JSON payload. Larger files go through a draft + createUploadSession +
//! chunked PUT workflow:
//!
//!   1. POST /me/messages            -> create draft, get draft id
//!   2. POST /me/messages/{id}/attachments (for every small attachment)
//!      or
//!      POST /me/messages/{id}/attachments/createUploadSession -> uploadUrl
//!      PUT  <uploadUrl> with Content-Range: bytes a-b/N  (chunks of <= 4 MB)
//!   3. POST /me/messages/{id}/send  -> sends the draft
//!
//! Download is the simple case:
//!   GET /me/messages/{id}/attachments/{aid}/$value -> raw bytes

const std = @import("std");
const errors = @import("../errors.zig");
const http = @import("http.zig");
const graph = @import("graph.zig");
const types = @import("types.zig");
const mime = @import("../util/mime.zig");

pub const Error = errors.Error;

pub const small_file_limit: usize = 3 * 1024 * 1024;
pub const upload_chunk_size: usize = 4 * 1024 * 1024 - 1; // just under 4 MiB

/// Create a draft message. Returns the draft id; caller frees.
pub fn createDraft(ctx: *graph.Ctx, draft: types.Draft) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try writeDraftJson(&buf, ctx.gpa, draft);

    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages", .{ctx.base_url});
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 201) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }

    const Resp = struct { id: []const u8 };
    var p = std.json.parseFromSlice(Resp, ctx.gpa, resp.body, .{ .ignore_unknown_fields = true }) catch return error.GraphMalformedJson;
    defer p.deinit();
    return ctx.gpa.dupe(u8, p.value.id);
}

/// Attach a file by path. Stats once and dispatches to the small-file
/// (inline base64) or large-file (createUploadSession) path.
pub fn attachFile(ctx: *graph.Ctx, draft_id: []const u8, path: []const u8, name_override: ?[]const u8) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.size < small_file_limit) {
        try attachSmallFromOpen(ctx, draft_id, file, stat.size, path, name_override);
    } else {
        try attachLargeFromOpen(ctx, draft_id, file, stat.size, path, name_override);
    }
}

/// Attach a small file using a pre-opened handle and known size. Used by
/// attachFile after a single stat.
fn attachSmallFromOpen(
    ctx: *graph.Ctx,
    draft_id: []const u8,
    file: std.fs.File,
    size: u64,
    path: []const u8,
    name_override: ?[]const u8,
) !void {
    if (size >= small_file_limit) return error.GraphBadRequest;
    const bytes = try ctx.gpa.alloc(u8, @intCast(size));
    defer ctx.gpa.free(bytes);
    const n = try file.readAll(bytes);
    if (n != bytes.len) return error.Io;

    const name = name_override orelse std.fs.path.basename(path);
    const content_type = mime.guessFromFilename(name);

    const b64_len = std.base64.standard.Encoder.calcSize(bytes.len);
    const b64 = try ctx.gpa.alloc(u8, b64_len);
    defer ctx.gpa.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, bytes);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try buf.appendSlice(ctx.gpa, "{\"@odata.type\":\"#microsoft.graph.fileAttachment\",\"name\":\"");
    try graph.writeJsonEscaped(&buf, ctx.gpa, name);
    try buf.appendSlice(ctx.gpa, "\",\"contentType\":\"");
    try graph.writeJsonEscaped(&buf, ctx.gpa, content_type);
    try buf.appendSlice(ctx.gpa, "\",\"contentBytes\":\"");
    try buf.appendSlice(ctx.gpa, b64);
    try buf.appendSlice(ctx.gpa, "\"}");

    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}/attachments", .{ ctx.base_url, draft_id });
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .body = buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 201 and resp.status != 200) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

/// Attach a large file using a pre-opened handle and known size.
fn attachLargeFromOpen(
    ctx: *graph.Ctx,
    draft_id: []const u8,
    file: std.fs.File,
    size: u64,
    path: []const u8,
    name_override: ?[]const u8,
) !void {
    const total: u64 = size;

    const name = name_override orelse std.fs.path.basename(path);
    const content_type = mime.guessFromFilename(name);

    // Microsoft Graph requires a draft + createUploadSession + chunked PUT
    // for attachments >= 3 MB. The session URL we get back is a sas-style
    // URL valid for the duration of the upload.
    var init_buf: std.ArrayList(u8) = .empty;
    defer init_buf.deinit(ctx.gpa);
    try init_buf.appendSlice(ctx.gpa, "{\"AttachmentItem\":{\"attachmentType\":\"file\",\"name\":\"");
    try graph.writeJsonEscaped(&init_buf, ctx.gpa, name);
    try init_buf.appendSlice(ctx.gpa, "\",\"size\":");
    var num_buf: [32]u8 = undefined;
    const size_str = try std.fmt.bufPrint(&num_buf, "{d}", .{total});
    try init_buf.appendSlice(ctx.gpa, size_str);
    try init_buf.appendSlice(ctx.gpa, ",\"contentType\":\"");
    try graph.writeJsonEscaped(&init_buf, ctx.gpa, content_type);
    try init_buf.appendSlice(ctx.gpa, "\"}}");

    const session_url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/messages/{s}/attachments/createUploadSession",
        .{ ctx.base_url, draft_id },
    );
    defer ctx.gpa.free(session_url);

    var s_resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = session_url,
        .body = init_buf.items,
        .content_type = "application/json",
        .bearer = ctx.session.bearerProvider(),
    });
    defer s_resp.deinit();
    if (s_resp.status != 201 and s_resp.status != 200) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(s_resp.status, &diag);
    }

    const SessResp = struct { uploadUrl: []const u8 };
    var sp = std.json.parseFromSlice(SessResp, ctx.gpa, s_resp.body, .{ .ignore_unknown_fields = true }) catch return error.GraphMalformedJson;
    defer sp.deinit();
    const upload_url = try ctx.gpa.dupe(u8, sp.value.uploadUrl);
    defer ctx.gpa.free(upload_url);

    const chunk_buf = try ctx.gpa.alloc(u8, upload_chunk_size);
    defer ctx.gpa.free(chunk_buf);

    var offset: u64 = 0;
    while (offset < total) {
        const remaining = total - offset;
        const this_size: usize = @intCast(@min(@as(u64, upload_chunk_size), remaining));
        const n = try file.readAll(chunk_buf[0..this_size]);
        if (n != this_size) return error.Io;

        var range_buf: [64]u8 = undefined;
        const range_val = try std.fmt.bufPrint(
            &range_buf,
            "bytes {d}-{d}/{d}",
            .{ offset, offset + this_size - 1, total },
        );

        var chunk_resp = try http.do(ctx.http_client, ctx.gpa, .{
            .method = .PUT,
            .url = upload_url,
            .body = chunk_buf[0..this_size],
            .content_type = "application/octet-stream",
            .extra_headers = &.{
                .{ .name = "Content-Range", .value = range_val },
            },
        });
        defer chunk_resp.deinit();
        // 202 -> more chunks expected; 201/200 -> final chunk accepted.
        if (chunk_resp.status != 202 and chunk_resp.status != 201 and chunk_resp.status != 200) {
            var diag = errors.Diagnostic.simple(error.HttpStatus);
            return http.classifyStatus(chunk_resp.status, &diag);
        }

        offset += this_size;
    }
}

/// Send a previously-created draft.
pub fn sendDraft(ctx: *graph.Ctx, draft_id: []const u8) !void {
    const url = try std.fmt.allocPrint(ctx.gpa, "{s}/me/messages/{s}/send", .{ ctx.base_url, draft_id });
    defer ctx.gpa.free(url);
    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .POST,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
    });
    defer resp.deinit();
    if (resp.status != 202 and resp.status != 200) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }
}

/// Download an attachment's raw bytes to a file on disk. Streams via a
/// buffered memory copy (Graph attachments are capped at 150 MB per item).
pub fn downloadAttachment(
    ctx: *graph.Ctx,
    message_id: []const u8,
    attachment_id: []const u8,
    dest_path: []const u8,
) !void {
    const url = try std.fmt.allocPrint(
        ctx.gpa,
        "{s}/me/messages/{s}/attachments/{s}/$value",
        .{ ctx.base_url, message_id, attachment_id },
    );
    defer ctx.gpa.free(url);

    var resp = try http.do(ctx.http_client, ctx.gpa, .{
        .method = .GET,
        .url = url,
        .bearer = ctx.session.bearerProvider(),
        .max_response_bytes = 200 * 1024 * 1024,
    });
    defer resp.deinit();
    if (resp.status != 200) {
        var diag = errors.Diagnostic.simple(error.HttpStatus);
        return http.classifyStatus(resp.status, &diag);
    }

    if (std.fs.path.dirname(dest_path)) |dir| {
        std.fs.cwd().makePath(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
    const file = try std.fs.cwd().createFile(dest_path, .{ .truncate = true });
    defer file.close();
    _ = try file.write(resp.body);
}

// -- JSON body builders ------------------------------------------------------

pub fn writeDraftJson(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, d: types.Draft) !void {
    try buf.appendSlice(gpa, "{\"subject\":\"");
    try graph.writeJsonEscaped(buf, gpa, d.subject);
    try buf.appendSlice(gpa, "\",\"body\":{\"contentType\":\"");
    try buf.appendSlice(gpa, switch (d.body.content_type) {
        .text => "Text",
        .html => "HTML",
    });
    try buf.appendSlice(gpa, "\",\"content\":\"");
    try graph.writeJsonEscaped(buf, gpa, d.body.content);
    try buf.appendSlice(gpa, "\"},\"toRecipients\":");
    try writeRecipientsJson(buf, gpa, d.to);
    if (d.cc.len > 0) {
        try buf.appendSlice(gpa, ",\"ccRecipients\":");
        try writeRecipientsJson(buf, gpa, d.cc);
    }
    if (d.bcc.len > 0) {
        try buf.appendSlice(gpa, ",\"bccRecipients\":");
        try writeRecipientsJson(buf, gpa, d.bcc);
    }
    try buf.append(gpa, '}');
}

pub fn writeRecipientsJson(buf: *std.ArrayList(u8), gpa: std.mem.Allocator, rs: []const types.Recipient) !void {
    try buf.append(gpa, '[');
    for (rs, 0..) |r, i| {
        if (i != 0) try buf.append(gpa, ',');
        try buf.appendSlice(gpa, "{\"emailAddress\":{\"address\":\"");
        try graph.writeJsonEscaped(buf, gpa, r.address);
        try buf.append(gpa, '"');
        if (r.name) |n| {
            try buf.appendSlice(gpa, ",\"name\":\"");
            try graph.writeJsonEscaped(buf, gpa, n);
            try buf.append(gpa, '"');
        }
        try buf.appendSlice(gpa, "}}");
    }
    try buf.append(gpa, ']');
}
