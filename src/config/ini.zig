//! A pragmatic INI parser for the outlook-email user config file.
//!
//! Supports:
//!   - `[section]` headers
//!   - `key = value` lines (unquoted)
//!   - `;` or `#` comments
//!   - trailing whitespace trimmed; leading whitespace ignored
//!
//! Does not support multi-line values, quoted values with embedded newlines,
//! or nested sections. The config file we write is always in this shape, and
//! if the user hand-edits it with fancier syntax we tell them off.

const std = @import("std");

pub const Entry = struct {
    section: []const u8,
    key: []const u8,
    value: []const u8,
};

pub const Parsed = struct {
    arena: std.heap.ArenaAllocator,
    entries: []Entry,

    pub fn deinit(self: *Parsed) void {
        self.arena.deinit();
    }

    pub fn get(self: Parsed, section: []const u8, key: []const u8) ?[]const u8 {
        for (self.entries) |e| {
            if (std.mem.eql(u8, e.section, section) and std.mem.eql(u8, e.key, key)) {
                return e.value;
            }
        }
        return null;
    }
};

pub fn parse(gpa: std.mem.Allocator, source: []const u8) !Parsed {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(a);

    var current_section: []const u8 = try a.dupe(u8, "");
    var line_no: usize = 0;
    var it = std.mem.splitScalar(u8, source, '\n');
    while (it.next()) |raw| {
        line_no += 1;
        const line = trim(raw);
        if (line.len == 0) continue;
        if (line[0] == ';' or line[0] == '#') continue;
        if (line[0] == '[') {
            const close = std.mem.indexOfScalar(u8, line, ']') orelse return error.BadSectionHeader;
            current_section = try a.dupe(u8, trim(line[1..close]));
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse return error.MissingEquals;
        const key = try a.dupe(u8, trim(line[0..eq]));
        const value = try a.dupe(u8, trim(line[eq + 1 ..]));
        try entries.append(a, .{
            .section = current_section,
            .key = key,
            .value = value,
        });
    }

    return .{
        .arena = arena,
        .entries = try entries.toOwnedSlice(a),
    };
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r");
}

pub fn writeFile(path: []const u8, entries: []const Entry) !void {
    const dir = std.fs.path.dirname(path) orelse ".";
    try std.fs.cwd().makePath(dir);
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    var buf: [4096]u8 = undefined;
    var current: []const u8 = "";
    var first = true;
    for (entries) |e| {
        if (!std.mem.eql(u8, e.section, current)) {
            if (!first) {
                _ = try file.write("\n");
            }
            if (e.section.len > 0) {
                const header = try std.fmt.bufPrint(&buf, "[{s}]\n", .{e.section});
                _ = try file.write(header);
            }
            current = e.section;
            first = false;
        }
        const line = try std.fmt.bufPrint(&buf, "{s} = {s}\n", .{ e.key, e.value });
        _ = try file.write(line);
    }
}

test "parse simple ini" {
    const src =
        \\; a comment
        \\[account]
        \\current = alice@contoso.com
        \\
        \\[ui]
        \\color = auto
        \\
    ;
    var p = try parse(std.testing.allocator, src);
    defer p.deinit();
    try std.testing.expectEqualStrings("alice@contoso.com", p.get("account", "current").?);
    try std.testing.expectEqualStrings("auto", p.get("ui", "color").?);
    try std.testing.expect(p.get("ui", "missing") == null);
}

test "reject bad section" {
    const src = "[unterminated\nkey = 1\n";
    try std.testing.expectError(error.BadSectionHeader, parse(std.testing.allocator, src));
}
