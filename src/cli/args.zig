//! Hand-rolled argument parser.
//!
//! We keep it minimal: global flags are parsed first, then the command, then
//! command-specific flags. There are no abbreviated forms; flags must use
//! their full `--name` spelling. `--name=value` and `--name value` are both
//! accepted. Anything that isn't a flag is a positional.

const std = @import("std");

pub const ParsedGlobals = struct {
    json: bool = false,
    no_color: bool = false,
    verbose: bool = false,
    proxy: ?[]const u8 = null,
    ca_bundle: ?[]const u8 = null,
    account: ?[]const u8 = null,
    client_id_override: ?[]const u8 = null,
    tenant_override: ?[]const u8 = null,
};

pub const Parsed = struct {
    globals: ParsedGlobals,
    command: ?[]const u8,
    rest: []const []const u8, // everything after the command
};

pub const ParseError = error{
    UnknownGlobalFlag,
    MissingGlobalValue,
};

pub fn parseGlobals(argv: []const []const u8) ParseError!Parsed {
    var g: ParsedGlobals = .{};
    var i: usize = 1; // skip argv[0] (program name)
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (a.len == 0) continue;
        if (a[0] != '-') break; // positional / command
        if (std.mem.eql(u8, a, "--")) {
            i += 1;
            break;
        }

        // Split --key=value
        const eq = std.mem.indexOfScalar(u8, a, '=');
        const name = if (eq) |p| a[0..p] else a;
        const value_inline: ?[]const u8 = if (eq) |p| a[p + 1 ..] else null;

        // Boolean flags.
        if (eql(name, "--json") or eql(name, "-j")) {
            g.json = true;
            continue;
        }
        if (eql(name, "--no-color")) {
            g.no_color = true;
            continue;
        }
        if (eql(name, "--verbose") or eql(name, "-v")) {
            g.verbose = true;
            continue;
        }

        // Help / version behave like commands even though they start with
        // `--` -- let the dispatcher see them.
        if (eql(name, "--help") or eql(name, "-h") or eql(name, "--version") or eql(name, "-V")) break;

        // Value flags.
        const is_value_flag = eql(name, "--proxy") or eql(name, "--ca-bundle") or eql(name, "--account") or eql(name, "--client-id") or eql(name, "--tenant");
        if (!is_value_flag) return error.UnknownGlobalFlag;

        const value: []const u8 = v: {
            if (value_inline) |vi| break :v vi;
            i += 1;
            if (i >= argv.len) return error.MissingGlobalValue;
            break :v argv[i];
        };

        if (eql(name, "--proxy")) g.proxy = value;
        if (eql(name, "--ca-bundle")) g.ca_bundle = value;
        if (eql(name, "--account")) g.account = value;
        if (eql(name, "--client-id")) g.client_id_override = value;
        if (eql(name, "--tenant")) g.tenant_override = value;
    }

    const command: ?[]const u8 = if (i < argv.len) argv[i] else null;
    const rest: []const []const u8 = if (command != null) argv[i + 1 ..] else argv[i..];
    return .{ .globals = g, .command = command, .rest = rest };
}

/// Helper for command-local parsers. Supports `--name value` and
/// `--name=value`. Multi-value flags (like --attach) are collected into the
/// provided ArrayList.
pub const CmdFlag = union(enum) {
    string_opt: *?[]const u8,
    string: *[]const u8, // required later; parser just records it
    bool_flag: *bool,
    string_list: *std.ArrayList([]const u8),
};

pub const CmdSpec = struct {
    name: []const u8,
    flag: CmdFlag,
};

pub const CmdParseResult = struct {
    positionals: []const []const u8,
};

pub fn parseCommand(
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    specs: []const CmdSpec,
) !CmdParseResult {
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(gpa);

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (a.len == 0) continue;
        if (a[0] != '-' or a.len == 1) {
            try positionals.append(gpa, a);
            continue;
        }
        if (std.mem.eql(u8, a, "--")) {
            i += 1;
            while (i < argv.len) : (i += 1) try positionals.append(gpa, argv[i]);
            break;
        }

        const eq = std.mem.indexOfScalar(u8, a, '=');
        const name = if (eq) |p| a[0..p] else a;
        const value_inline: ?[]const u8 = if (eq) |p| a[p + 1 ..] else null;

        const spec = findSpec(specs, name) orelse return error.UnknownFlag;
        switch (spec.flag) {
            .bool_flag => |p| p.* = true,
            .string_opt => |p| {
                const v = try takeValue(argv, &i, value_inline);
                p.* = v;
            },
            .string => |p| {
                const v = try takeValue(argv, &i, value_inline);
                p.* = v;
            },
            .string_list => |p| {
                const v = try takeValue(argv, &i, value_inline);
                try p.append(gpa, v);
            },
        }
    }
    return .{ .positionals = try positionals.toOwnedSlice(gpa) };
}

fn takeValue(argv: []const []const u8, i: *usize, inline_val: ?[]const u8) ![]const u8 {
    if (inline_val) |v| return v;
    i.* += 1;
    if (i.* >= argv.len) return error.MissingValue;
    return argv[i.*];
}

fn findSpec(specs: []const CmdSpec, name: []const u8) ?CmdSpec {
    for (specs) |s| {
        if (std.mem.eql(u8, s.name, name)) return s;
    }
    return null;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test "parseGlobals recognises flags" {
    const argv = [_][]const u8{
        "outlook", "--json", "--proxy", "http://p:8080", "list", "--top", "50",
    };
    const p = try parseGlobals(&argv);
    try std.testing.expect(p.globals.json);
    try std.testing.expectEqualStrings("http://p:8080", p.globals.proxy.?);
    try std.testing.expectEqualStrings("list", p.command.?);
    try std.testing.expectEqual(@as(usize, 2), p.rest.len);
}

test "parseGlobals inline =" {
    const argv = [_][]const u8{ "outlook", "--proxy=http://p:8080", "list" };
    const p = try parseGlobals(&argv);
    try std.testing.expectEqualStrings("http://p:8080", p.globals.proxy.?);
}
