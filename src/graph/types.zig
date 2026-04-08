//! Microsoft Graph mail schema as Zig structs.
//!
//! Parsed from Graph JSON via `std.json.parseFromSlice(T, arena, body,
//! .{ .ignore_unknown_fields = true })`. All slice fields borrow from the
//! arena that owns the `Parsed(T)` - nothing here allocates on its own.

const std = @import("std");

pub const Recipient = struct {
    address: []const u8,
    name: ?[]const u8 = null,
};

pub const BodyType = enum { text, html };

pub const Body = struct {
    content_type: BodyType,
    content: []const u8,
};

pub const Importance = enum { low, normal, high };

pub const AttachmentMeta = struct {
    id: []const u8,
    name: []const u8,
    content_type: []const u8,
    size: u64,
    is_inline: bool,
};

pub const MessageSummary = struct {
    id: []const u8,
    subject: []const u8,
    from: Recipient,
    received_at: []const u8,
    is_read: bool,
    has_attachments: bool,
    preview: []const u8,
    importance: Importance = .normal,
};

pub const Message = struct {
    id: []const u8,
    conversation_id: []const u8,
    subject: []const u8,
    from: Recipient,
    to: []const Recipient,
    cc: []const Recipient = &.{},
    bcc: []const Recipient = &.{},
    received_at: []const u8,
    sent_at: []const u8 = "",
    body: Body,
    is_read: bool,
    has_attachments: bool,
    importance: Importance = .normal,
    web_link: []const u8 = "",
    attachments: []const AttachmentMeta = &.{},
};

pub const Draft = struct {
    to: []const Recipient,
    cc: []const Recipient = &.{},
    bcc: []const Recipient = &.{},
    subject: []const u8,
    body: Body,
    attachments: []const AttachmentInput = &.{},
    save_to_sent: bool = true,
};

pub const AttachmentInput = struct {
    path: []const u8,
    name: ?[]const u8 = null,
};

pub const WellKnown = enum {
    inbox,
    sentitems,
    drafts,
    deleteditems,
    archive,
    junkemail,
    outbox,
    unknown,
};

pub fn wellKnownFromName(name: []const u8) WellKnown {
    const table = [_]struct { []const u8, WellKnown }{
        .{ "inbox", .inbox },
        .{ "sentitems", .sentitems },
        .{ "drafts", .drafts },
        .{ "deleteditems", .deleteditems },
        .{ "archive", .archive },
        .{ "junkemail", .junkemail },
        .{ "outbox", .outbox },
    };
    // Lowercase-compare.
    var buf: [32]u8 = undefined;
    if (name.len > buf.len) return .unknown;
    for (name, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    const lower = buf[0..name.len];
    for (table) |pair| {
        if (std.mem.eql(u8, lower, pair[0])) return pair[1];
    }
    return .unknown;
}

pub const Folder = struct {
    id: []const u8,
    display_name: []const u8,
    parent_folder_id: ?[]const u8 = null,
    total_item_count: u32 = 0,
    unread_item_count: u32 = 0,
    well_known_name: WellKnown = .unknown,
};

// ---------------------------------------------------------------------------
// Raw Graph JSON mirror structs -- used with parseFromSlice. Separate from
// our nice Zig types because Graph's field names are camelCase and we want
// snake_case in Zig code.
// ---------------------------------------------------------------------------

pub const RawRecipient = struct {
    emailAddress: RawEmailAddress,
};
pub const RawEmailAddress = struct {
    address: []const u8 = "",
    name: ?[]const u8 = null,
};

pub const RawBody = struct {
    contentType: []const u8 = "text",
    content: []const u8 = "",
};

pub const RawAttachment = struct {
    id: []const u8,
    name: []const u8,
    contentType: []const u8 = "application/octet-stream",
    size: u64 = 0,
    isInline: bool = false,
};

pub const RawMessageSummary = struct {
    id: []const u8,
    subject: ?[]const u8 = null,
    from: ?RawRecipient = null,
    sender: ?RawRecipient = null,
    receivedDateTime: []const u8 = "",
    isRead: bool = false,
    hasAttachments: bool = false,
    bodyPreview: []const u8 = "",
    importance: ?[]const u8 = null,
};

pub const RawMessageFull = struct {
    id: []const u8,
    conversationId: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    from: ?RawRecipient = null,
    sender: ?RawRecipient = null,
    toRecipients: []const RawRecipient = &.{},
    ccRecipients: []const RawRecipient = &.{},
    bccRecipients: []const RawRecipient = &.{},
    receivedDateTime: []const u8 = "",
    sentDateTime: []const u8 = "",
    body: ?RawBody = null,
    isRead: bool = false,
    hasAttachments: bool = false,
    importance: ?[]const u8 = null,
    webLink: []const u8 = "",
    attachments: ?[]const RawAttachment = null,
};

pub const RawFolder = struct {
    id: []const u8,
    displayName: []const u8 = "",
    parentFolderId: ?[]const u8 = null,
    totalItemCount: u32 = 0,
    unreadItemCount: u32 = 0,
    wellKnownName: ?[]const u8 = null,
};

// Envelope types for collection endpoints.
pub fn ListEnvelope(comptime T: type) type {
    return struct {
        value: []const T,
        @"@odata.nextLink": ?[]const u8 = null,
    };
}

pub fn convertRecipient(r: RawRecipient) Recipient {
    return .{ .address = r.emailAddress.address, .name = r.emailAddress.name };
}

pub fn convertRecipients(src: []const RawRecipient, dest: []Recipient) void {
    for (src, 0..) |r, i| dest[i] = convertRecipient(r);
}

pub fn parseImportance(s: ?[]const u8) Importance {
    const v = s orelse return .normal;
    if (std.mem.eql(u8, v, "low")) return .low;
    if (std.mem.eql(u8, v, "high")) return .high;
    return .normal;
}

pub fn parseBodyType(s: []const u8) BodyType {
    if (std.ascii.eqlIgnoreCase(s, "html")) return .html;
    return .text;
}

test "wellKnownFromName" {
    try std.testing.expectEqual(WellKnown.inbox, wellKnownFromName("inbox"));
    try std.testing.expectEqual(WellKnown.sentitems, wellKnownFromName("SentItems"));
    try std.testing.expectEqual(WellKnown.unknown, wellKnownFromName("custom"));
}

test "parse inbox list fixture (tolerates unknown fields + nulls)" {
    const fixture = @embedFile("../../tests/fixtures/inbox_list.json");
    const Env = ListEnvelope(RawMessageSummary);
    var parsed = try std.json.parseFromSlice(
        Env,
        std.testing.allocator,
        fixture,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.value.len);
    try std.testing.expectEqualStrings("AAMkAD0a", parsed.value.value[0].id);
    try std.testing.expect(parsed.value.value[0].subject != null);
    try std.testing.expectEqualStrings("Weekly status", parsed.value.value[0].subject.?);
    try std.testing.expect(!parsed.value.value[0].isRead);
    try std.testing.expect(parsed.value.value[0].hasAttachments);

    // Second row has a null from, populated sender, and null subject.
    try std.testing.expect(parsed.value.value[1].from == null);
    try std.testing.expect(parsed.value.value[1].sender != null);
    try std.testing.expect(parsed.value.value[1].subject == null);

    try std.testing.expect(parsed.value.@"@odata.nextLink" != null);
}

test "parse full message fixture" {
    const fixture = @embedFile("../../tests/fixtures/message_full.json");
    var parsed = try std.json.parseFromSlice(
        RawMessageFull,
        std.testing.allocator,
        fixture,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings("AAMkAD0a", parsed.value.id);
    try std.testing.expectEqualStrings("Weekly status", parsed.value.subject.?);
    try std.testing.expect(parsed.value.body != null);
    try std.testing.expectEqualStrings("text", parsed.value.body.?.contentType);
    try std.testing.expect(parsed.value.attachments != null);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.attachments.?.len);
    try std.testing.expectEqualStrings("report.pdf", parsed.value.attachments.?[0].name);
    try std.testing.expectEqual(@as(u64, 12345), parsed.value.attachments.?[0].size);
}
