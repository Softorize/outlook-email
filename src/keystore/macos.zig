//! macOS Keychain backend via Security.framework.
//!
//! Generic password items are keyed by (service, account). We encode our
//! label into the service name so a single account can have multiple
//! entries ("outlook-email:refresh_token", "outlook-email:token_meta"),
//! while kSecAttrAccount holds the user principal name for listing.

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("../errors.zig");
const keystore = @import("keystore.zig");

const Error = errors.Error;

const c = @cImport({
    @cInclude("CoreFoundation/CoreFoundation.h");
    @cInclude("Security/Security.h");
});

const Ctx = struct {
    gpa: std.mem.Allocator,
    service_prefix: []u8,
};

pub fn open(gpa: std.mem.Allocator, service_name: []const u8) !keystore.Backend {
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

fn makeService(ctx: *Ctx, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(ctx.gpa, "{s}:{s}", .{ ctx.service_prefix, label });
}

// --- CF helpers ------------------------------------------------------------

fn cfStr(bytes: []const u8) ?c.CFStringRef {
    return c.CFStringCreateWithBytes(
        null,
        bytes.ptr,
        @intCast(bytes.len),
        c.kCFStringEncodingUTF8,
        0,
    );
}

fn cfData(bytes: []const u8) ?c.CFDataRef {
    return c.CFDataCreate(null, bytes.ptr, @intCast(bytes.len));
}

fn cfRelease(obj: ?*const anyopaque) void {
    if (obj) |o| c.CFRelease(o);
}

fn cfDictionary(pairs: []const [2]?*const anyopaque) ?c.CFDictionaryRef {
    var keys: [12]?*const anyopaque = undefined;
    var values: [12]?*const anyopaque = undefined;
    std.debug.assert(pairs.len <= keys.len);
    for (pairs, 0..) |pair, i| {
        keys[i] = pair[0];
        values[i] = pair[1];
    }
    return c.CFDictionaryCreate(
        null,
        @ptrCast(&keys),
        @ptrCast(&values),
        @intCast(pairs.len),
        &c.kCFTypeDictionaryKeyCallBacks,
        &c.kCFTypeDictionaryValueCallBacks,
    );
}

// --- vtable impls ----------------------------------------------------------

fn setImpl(ctx_ptr: *anyopaque, e: keystore.Entry) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const svc = makeService(ctx, e.label) catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);

    const svc_ref = cfStr(svc) orelse return error.OutOfMemory;
    defer cfRelease(svc_ref);
    const acct_ref = cfStr(e.account) orelse return error.OutOfMemory;
    defer cfRelease(acct_ref);
    const data_ref = cfData(e.secret) orelse return error.OutOfMemory;
    defer cfRelease(data_ref);

    // SecItemUpdate fails with errSecItemNotFound if the item is new; we
    // fall through to SecItemAdd in that case rather than calling
    // SecItemCopyMatching first to check.
    const query = cfDictionary(&.{
        .{ c.kSecClass, c.kSecClassGenericPassword },
        .{ c.kSecAttrService, svc_ref },
        .{ c.kSecAttrAccount, acct_ref },
    }) orelse return error.OutOfMemory;
    defer cfRelease(query);

    const update = cfDictionary(&.{
        .{ c.kSecValueData, data_ref },
    }) orelse return error.OutOfMemory;
    defer cfRelease(update);

    const upd_status = c.SecItemUpdate(query, update);
    if (upd_status == c.errSecSuccess) return;
    if (upd_status != c.errSecItemNotFound) {
        return mapOsStatus(upd_status);
    }

    // Not present -- add a new item.
    const add = cfDictionary(&.{
        .{ c.kSecClass, c.kSecClassGenericPassword },
        .{ c.kSecAttrService, svc_ref },
        .{ c.kSecAttrAccount, acct_ref },
        .{ c.kSecValueData, data_ref },
        .{ c.kSecAttrAccessible, c.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly },
    }) orelse return error.OutOfMemory;
    defer cfRelease(add);

    const add_status = c.SecItemAdd(add, null);
    if (add_status != c.errSecSuccess) return mapOsStatus(add_status);
}

fn getImpl(
    ctx_ptr: *anyopaque,
    gpa: std.mem.Allocator,
    account: []const u8,
    label: []const u8,
) Error!?[]u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const svc = makeService(ctx, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);

    const svc_ref = cfStr(svc) orelse return error.OutOfMemory;
    defer cfRelease(svc_ref);
    const acct_ref = cfStr(account) orelse return error.OutOfMemory;
    defer cfRelease(acct_ref);

    const query = cfDictionary(&.{
        .{ c.kSecClass, c.kSecClassGenericPassword },
        .{ c.kSecAttrService, svc_ref },
        .{ c.kSecAttrAccount, acct_ref },
        .{ c.kSecReturnData, c.kCFBooleanTrue },
        .{ c.kSecMatchLimit, c.kSecMatchLimitOne },
    }) orelse return error.OutOfMemory;
    defer cfRelease(query);

    var result: c.CFTypeRef = null;
    const status = c.SecItemCopyMatching(query, &result);
    if (status == c.errSecItemNotFound) return null;
    if (status != c.errSecSuccess) return mapOsStatus(status);
    defer cfRelease(result);

    const data: c.CFDataRef = @ptrCast(result);
    const len: usize = @intCast(c.CFDataGetLength(data));
    const bytes = c.CFDataGetBytePtr(data);
    const out = gpa.alloc(u8, len) catch return error.OutOfMemory;
    @memcpy(out, bytes[0..len]);
    return out;
}

fn deleteImpl(
    ctx_ptr: *anyopaque,
    account: []const u8,
    label: []const u8,
) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const svc = makeService(ctx, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);

    const svc_ref = cfStr(svc) orelse return error.OutOfMemory;
    defer cfRelease(svc_ref);
    const acct_ref = cfStr(account) orelse return error.OutOfMemory;
    defer cfRelease(acct_ref);

    const query = cfDictionary(&.{
        .{ c.kSecClass, c.kSecClassGenericPassword },
        .{ c.kSecAttrService, svc_ref },
        .{ c.kSecAttrAccount, acct_ref },
    }) orelse return error.OutOfMemory;
    defer cfRelease(query);

    const status = c.SecItemDelete(query);
    if (status == c.errSecSuccess) return;
    if (status == c.errSecItemNotFound) return error.KeystoreItemMissing;
    return mapOsStatus(status);
}

fn listImpl(ctx_ptr: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    // We list by refresh_token entries, since every logged-in account has one.
    const svc = makeService(ctx, "refresh_token") catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);

    const svc_ref = cfStr(svc) orelse return error.OutOfMemory;
    defer cfRelease(svc_ref);

    const query = cfDictionary(&.{
        .{ c.kSecClass, c.kSecClassGenericPassword },
        .{ c.kSecAttrService, svc_ref },
        .{ c.kSecMatchLimit, c.kSecMatchLimitAll },
        .{ c.kSecReturnAttributes, c.kCFBooleanTrue },
    }) orelse return error.OutOfMemory;
    defer cfRelease(query);

    var result: c.CFTypeRef = null;
    const status = c.SecItemCopyMatching(query, &result);
    if (status == c.errSecItemNotFound) return &.{};
    if (status != c.errSecSuccess) return mapOsStatus(status);
    defer cfRelease(result);

    const arr: c.CFArrayRef = @ptrCast(result);
    const count: usize = @intCast(c.CFArrayGetCount(arr));

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |s| gpa.free(s);
        out.deinit(gpa);
    }

    const account_key = c.kSecAttrAccount;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const dict: c.CFDictionaryRef = @ptrCast(c.CFArrayGetValueAtIndex(arr, @intCast(i)));
        const val = c.CFDictionaryGetValue(dict, account_key) orelse continue;
        const cf_string: c.CFStringRef = @ptrCast(val);
        var buf: [512]u8 = undefined;
        if (c.CFStringGetCString(cf_string, &buf, buf.len, c.kCFStringEncodingUTF8) == 0) continue;
        const slice = std.mem.sliceTo(&buf, 0);
        const dup = gpa.dupe(u8, slice) catch return error.OutOfMemory;
        out.append(gpa, dup) catch {
            gpa.free(dup);
            return error.OutOfMemory;
        };
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn describeImpl(_: *anyopaque) []const u8 {
    return "macOS Keychain (Security.framework)";
}

fn mapOsStatus(status: c.OSStatus) Error {
    return switch (status) {
        c.errSecItemNotFound => error.KeystoreItemMissing,
        c.errSecAuthFailed, c.errSecUserCanceled => error.KeystoreAccessDenied,
        else => error.KeystoreUnavailable,
    };
}
