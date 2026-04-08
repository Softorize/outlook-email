//! Human-formatted, coloured output for CLI subcommands.

const std = @import("std");
const types = @import("../graph/types.zig");
const color = @import("color.zig");
const time = @import("../util/time.zig");
const errors = @import("../errors.zig");
const io = @import("../util/io.zig");

const stdoutWrite = io.out;
const stdoutPrint = io.outPrint;

pub fn writeMessageList(list: []const types.MessageSummary, profile: color.Profile) !void {
    const now = std.time.timestamp();
    var date_buf: [32]u8 = undefined;
    for (list) |m| {
        const ts = time.parseIso8601Utc(m.received_at) catch now;
        const date_str = time.formatShort(&date_buf, ts, now);
        const unread_marker: []const u8 = if (m.is_read) " " else "*";
        const attach_marker: []const u8 = if (m.has_attachments) "@" else " ";
        const from_name = m.from.name orelse m.from.address;

        if (profile.enabled and !m.is_read) {
            stdoutPrint("{s}{s}{s}", .{ profile.bold(), unread_marker, profile.reset() });
        } else {
            stdoutPrint("{s}", .{unread_marker});
        }
        stdoutPrint(" {s} ", .{attach_marker});
        stdoutPrint("{s}{s:>12}{s}  ", .{ profile.dim(), date_str, profile.reset() });
        stdoutPrint("{s}{s:<28}{s}  ", .{ profile.cyan(), truncate(from_name, 28), profile.reset() });

        if (profile.enabled and !m.is_read) {
            stdoutPrint("{s}{s}{s}", .{ profile.bold(), truncate(m.subject, 60), profile.reset() });
        } else {
            stdoutPrint("{s}", .{truncate(m.subject, 60)});
        }
        stdoutPrint("\n", .{});
        if (m.preview.len > 0) {
            stdoutPrint("          {s}{s}{s}\n", .{ profile.dim(), truncate(m.preview, 80), profile.reset() });
        }
        stdoutPrint("          {s}id: {s}{s}\n\n", .{ profile.dim(), m.id, profile.reset() });
    }
}

pub fn writeMessage(m: types.Message, profile: color.Profile) !void {
    stdoutPrint("{s}From:{s}    {s}", .{ profile.bold(), profile.reset(), m.from.address });
    if (m.from.name) |n| stdoutPrint(" ({s})", .{n});
    stdoutPrint("\n", .{});

    if (m.to.len > 0) {
        stdoutPrint("{s}To:{s}      ", .{ profile.bold(), profile.reset() });
        writeRecipientList(m.to);
        stdoutPrint("\n", .{});
    }
    if (m.cc.len > 0) {
        stdoutPrint("{s}Cc:{s}      ", .{ profile.bold(), profile.reset() });
        writeRecipientList(m.cc);
        stdoutPrint("\n", .{});
    }
    stdoutPrint("{s}Date:{s}    {s}\n", .{ profile.bold(), profile.reset(), m.received_at });
    stdoutPrint("{s}Subject:{s} {s}{s}{s}\n", .{
        profile.bold(), profile.reset(),
        profile.bold(), m.subject, profile.reset(),
    });
    if (m.attachments.len > 0) {
        stdoutPrint("{s}Files:{s}   ", .{ profile.bold(), profile.reset() });
        for (m.attachments, 0..) |a, i| {
            if (i != 0) stdoutPrint(", ", .{});
            stdoutPrint("{s} ({d} bytes)", .{ a.name, a.size });
        }
        stdoutPrint("\n", .{});
    }
    stdoutPrint("\n", .{});

    // Body. For HTML we just print as-is; Graph gives clean-enough content
    // that most of the time you can read it, and if not, users pipe through
    // `html2text` themselves.
    stdoutPrint("{s}\n", .{m.body.content});
}

fn writeRecipientList(rs: []const types.Recipient) void {
    for (rs, 0..) |r, i| {
        if (i != 0) stdoutWrite(", ");
        if (r.name) |n| {
            stdoutPrint("{s} <{s}>", .{ n, r.address });
        } else {
            stdoutWrite(r.address);
        }
    }
}

pub fn writeFolderList(list: []const types.Folder, profile: color.Profile) !void {
    for (list) |f| {
        const marker: []const u8 = switch (f.well_known_name) {
            .inbox, .sentitems, .drafts, .deleteditems, .archive, .junkemail, .outbox => "*",
            .unknown => " ",
        };
        stdoutPrint("{s} {s}{s:<32}{s}  {d:>6} unread / {d:>6} total\n", .{
            marker,
            profile.bold(),
            f.display_name,
            profile.reset(),
            f.unread_item_count,
            f.total_item_count,
        });
    }
}

pub fn writeAccounts(list: []const []const u8, current: ?[]const u8) !void {
    for (list) |acct| {
        const is_current = if (current) |c| std.mem.eql(u8, c, acct) else false;
        const marker: []const u8 = if (is_current) "*" else " ";
        stdoutPrint("{s} {s}\n", .{ marker, acct });
    }
    if (list.len == 0) stdoutPrint("(no accounts; run 'ocli login')\n", .{});
}

pub fn writeError(diag: errors.Diagnostic, profile: color.Profile) !void {
    io.errPrint("{s}error:{s} {s}\n", .{
        profile.red(), profile.reset(), errors.defaultMessage(diag.err),
    });
    if (diag.server_message) |msg| io.errPrint("       {s}\n", .{msg});
    if (diag.retry_after_seconds) |s| io.errPrint("       retry after: {d}s\n", .{s});
    if (diag.hint) |h| io.errPrint("       hint: {s}\n", .{h});
}

fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    if (max < 1) return s[0..0];
    return s[0..max];
}
