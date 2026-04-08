//! Windows Credential Manager backend via advapi32 / wincred APIs.
//!
//! We declare the three functions we need by hand rather than @cImport the
//! entire Windows headers (faster build, fewer surprises).

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("../errors.zig");
const keystore = @import("keystore.zig");

const Error = errors.Error;
const windows = std.os.windows;
const WCHAR = u16;
const DWORD = u32;
const BOOL = i32;
const LPVOID = ?*anyopaque;

const CRED_TYPE_GENERIC: DWORD = 1;
const CRED_PERSIST_LOCAL_MACHINE: DWORD = 2;
const ERROR_NOT_FOUND: DWORD = 1168;

const FILETIME = extern struct {
    dwLowDateTime: DWORD,
    dwHighDateTime: DWORD,
};

const CREDENTIAL_ATTRIBUTE = extern struct {
    Keyword: ?[*:0]WCHAR,
    Flags: DWORD,
    ValueSize: DWORD,
    Value: ?[*]u8,
};

const CREDENTIALW = extern struct {
    Flags: DWORD,
    Type: DWORD,
    TargetName: ?[*:0]WCHAR,
    Comment: ?[*:0]WCHAR,
    LastWritten: FILETIME,
    CredentialBlobSize: DWORD,
    CredentialBlob: ?[*]u8,
    Persist: DWORD,
    AttributeCount: DWORD,
    Attributes: ?[*]CREDENTIAL_ATTRIBUTE,
    TargetAlias: ?[*:0]WCHAR,
    UserName: ?[*:0]WCHAR,
};

extern "advapi32" fn CredWriteW(credential: *const CREDENTIALW, flags: DWORD) callconv(.winapi) BOOL;
extern "advapi32" fn CredReadW(
    target_name: [*:0]const WCHAR,
    type_: DWORD,
    flags: DWORD,
    credential: *?*CREDENTIALW,
) callconv(.winapi) BOOL;
extern "advapi32" fn CredDeleteW(
    target_name: [*:0]const WCHAR,
    type_: DWORD,
    flags: DWORD,
) callconv(.winapi) BOOL;
extern "advapi32" fn CredFree(buffer: LPVOID) callconv(.winapi) void;
extern "advapi32" fn CredEnumerateW(
    filter: ?[*:0]const WCHAR,
    flags: DWORD,
    count: *DWORD,
    credential: *?[*]?*CREDENTIALW,
) callconv(.winapi) BOOL;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;

const Ctx = struct {
    gpa: std.mem.Allocator,
    service_prefix: []u8,
};

pub fn open(gpa: std.mem.Allocator, service_name: []const u8) !keystore.Backend {
    if (builtin.os.tag != .windows) return error.KeystoreUnavailable;
    const ctx = try gpa.create(Ctx);
    ctx.* = .{
        .gpa = gpa,
        .service_prefix = try gpa.dupe(u8, service_name),
    };
    return .{
        .ctx = ctx,
        .vtable = &.{
            .set = setImpl,
            .get = getImpl,
            .delete = deleteImpl,
            .list = listImpl,
            .describe = describeImpl,
            .close = closeImpl,
        },
    };
}

fn closeImpl(ctx_ptr: *anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const gpa = ctx.gpa;
    gpa.free(ctx.service_prefix);
    gpa.destroy(ctx);
}

fn makeTarget(ctx: *Ctx, account: []const u8, label: []const u8) ![:0]WCHAR {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try buf.appendSlice(ctx.gpa, ctx.service_prefix);
    try buf.append(ctx.gpa, ':');
    try buf.appendSlice(ctx.gpa, label);
    try buf.append(ctx.gpa, '/');
    try buf.appendSlice(ctx.gpa, account);
    return std.unicode.utf8ToUtf16LeAllocZ(ctx.gpa, buf.items);
}

fn setImpl(ctx_ptr: *anyopaque, e: keystore.Entry) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const target = makeTarget(ctx, e.account, e.label) catch return error.OutOfMemory;
    defer ctx.gpa.free(target);
    const user_w = std.unicode.utf8ToUtf16LeAllocZ(ctx.gpa, e.account) catch return error.OutOfMemory;
    defer ctx.gpa.free(user_w);

    var cred: CREDENTIALW = .{
        .Flags = 0,
        .Type = CRED_TYPE_GENERIC,
        .TargetName = target.ptr,
        .Comment = null,
        .LastWritten = .{ .dwLowDateTime = 0, .dwHighDateTime = 0 },
        .CredentialBlobSize = @intCast(e.secret.len),
        .CredentialBlob = @constCast(e.secret.ptr),
        .Persist = CRED_PERSIST_LOCAL_MACHINE,
        .AttributeCount = 0,
        .Attributes = null,
        .TargetAlias = null,
        .UserName = user_w.ptr,
    };
    if (CredWriteW(&cred, 0) == 0) return error.KeystoreUnavailable;
}

fn getImpl(
    ctx_ptr: *anyopaque,
    gpa: std.mem.Allocator,
    account: []const u8,
    label: []const u8,
) Error!?[]u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const target = makeTarget(ctx, account, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(target);

    var cred_ptr: ?*CREDENTIALW = null;
    if (CredReadW(target.ptr, CRED_TYPE_GENERIC, 0, &cred_ptr) == 0) {
        if (GetLastError() == ERROR_NOT_FOUND) return null;
        return error.KeystoreUnavailable;
    }
    defer if (cred_ptr) |cp| CredFree(cp);
    const cred = cred_ptr orelse return null;
    const len: usize = @intCast(cred.CredentialBlobSize);
    if (cred.CredentialBlob) |blob| {
        const out = gpa.alloc(u8, len) catch return error.OutOfMemory;
        @memcpy(out, blob[0..len]);
        return out;
    }
    return null;
}

fn deleteImpl(
    ctx_ptr: *anyopaque,
    account: []const u8,
    label: []const u8,
) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const target = makeTarget(ctx, account, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(target);
    if (CredDeleteW(target.ptr, CRED_TYPE_GENERIC, 0) == 0) {
        if (GetLastError() == ERROR_NOT_FOUND) return error.KeystoreItemMissing;
        return error.KeystoreUnavailable;
    }
}

fn listImpl(ctx_ptr: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    // Filter to our refresh-token namespace.
    const prefix = std.fmt.allocPrint(ctx.gpa, "{s}:refresh_token/*", .{ctx.service_prefix}) catch return error.OutOfMemory;
    defer ctx.gpa.free(prefix);
    const filter_w = std.unicode.utf8ToUtf16LeAllocZ(ctx.gpa, prefix) catch return error.OutOfMemory;
    defer ctx.gpa.free(filter_w);

    var count: DWORD = 0;
    var creds: ?[*]?*CREDENTIALW = null;
    if (CredEnumerateW(filter_w.ptr, 0, &count, &creds) == 0) {
        if (GetLastError() == ERROR_NOT_FOUND) return &.{};
        return error.KeystoreUnavailable;
    }
    defer if (creds) |c_| CredFree(@ptrCast(c_));

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |s| gpa.free(s);
        out.deinit(gpa);
    }
    if (creds) |cs| {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const cred_maybe = cs[i];
            const cred = cred_maybe orelse continue;
            const user = cred.UserName orelse continue;
            const user_slice = std.mem.span(user);
            const utf8 = std.unicode.utf16LeToUtf8Alloc(gpa, user_slice) catch return error.OutOfMemory;
            out.append(gpa, utf8) catch {
                gpa.free(utf8);
                return error.OutOfMemory;
            };
        }
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn describeImpl(_: *anyopaque) []const u8 {
    return "Windows Credential Manager";
}
