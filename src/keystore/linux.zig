//! Linux keystore backend using libsecret loaded at runtime via std.DynLib.
//!
//! Why dynamic load? Keeps the binary a single static file that still runs on
//! headless boxes without libsecret installed. If loading fails, the caller
//! falls back to the encrypted file backend.

const std = @import("std");
const errors = @import("../errors.zig");
const keystore = @import("keystore.zig");

const Error = errors.Error;

// libsecret-1 C ABI types. We only declare the bits we use.
const GError = opaque {};
const SecretSchema = extern struct {
    name: [*:0]const u8,
    flags: c_int,
    attributes: [32]Attribute,
    reserved: c_int = 0,
    reserved1: ?*anyopaque = null,
    reserved2: ?*anyopaque = null,
    reserved3: ?*anyopaque = null,
    reserved4: ?*anyopaque = null,
    reserved5: ?*anyopaque = null,
    reserved6: ?*anyopaque = null,
    reserved7: ?*anyopaque = null,

    const Attribute = extern struct {
        name: ?[*:0]const u8 = null,
        type: c_int = 0,
    };
};

const SECRET_SCHEMA_ATTRIBUTE_STRING: c_int = 0;
const SECRET_SCHEMA_NONE: c_int = 0;

const StoreFn = *const fn (
    schema: *const SecretSchema,
    collection: ?[*:0]const u8,
    label: [*:0]const u8,
    password: [*:0]const u8,
    cancellable: ?*anyopaque,
    err: ?*?*GError,
    k1: [*:0]const u8,
    v1: [*:0]const u8,
    k2: [*:0]const u8,
    v2: [*:0]const u8,
    sentinel: ?*anyopaque,
) callconv(.c) c_int;

const LookupFn = *const fn (
    schema: *const SecretSchema,
    cancellable: ?*anyopaque,
    err: ?*?*GError,
    k1: [*:0]const u8,
    v1: [*:0]const u8,
    k2: [*:0]const u8,
    v2: [*:0]const u8,
    sentinel: ?*anyopaque,
) callconv(.c) ?[*:0]u8;

const ClearFn = *const fn (
    schema: *const SecretSchema,
    cancellable: ?*anyopaque,
    err: ?*?*GError,
    k1: [*:0]const u8,
    v1: [*:0]const u8,
    k2: [*:0]const u8,
    v2: [*:0]const u8,
    sentinel: ?*anyopaque,
) callconv(.c) c_int;

const FreeFn = *const fn (password: ?[*:0]u8) callconv(.c) void;
const GErrorFreeFn = *const fn (err: ?*GError) callconv(.c) void;

const Fns = struct {
    secret_password_store_sync: StoreFn,
    secret_password_lookup_sync: LookupFn,
    secret_password_clear_sync: ClearFn,
    secret_password_free: FreeFn,
    g_error_free: GErrorFreeFn,
};

const Ctx = struct {
    gpa: std.mem.Allocator,
    service_prefix: []u8,
    lib: std.DynLib,
    glib: std.DynLib,
    fns: Fns,
    schema: SecretSchema,
};

pub fn open(gpa: std.mem.Allocator, service_name: []const u8) !keystore.Backend {
    var lib = std.DynLib.open("libsecret-1.so.0") catch {
        return error.KeystoreUnavailable;
    };
    errdefer lib.close();
    var glib = std.DynLib.open("libglib-2.0.so.0") catch {
        return error.KeystoreUnavailable;
    };
    errdefer glib.close();

    const fns: Fns = .{
        .secret_password_store_sync = lib.lookup(StoreFn, "secret_password_store_sync") orelse return error.KeystoreUnavailable,
        .secret_password_lookup_sync = lib.lookup(LookupFn, "secret_password_lookup_sync") orelse return error.KeystoreUnavailable,
        .secret_password_clear_sync = lib.lookup(ClearFn, "secret_password_clear_sync") orelse return error.KeystoreUnavailable,
        .secret_password_free = lib.lookup(FreeFn, "secret_password_free") orelse return error.KeystoreUnavailable,
        .g_error_free = glib.lookup(GErrorFreeFn, "g_error_free") orelse return error.KeystoreUnavailable,
    };

    const ctx = try gpa.create(Ctx);
    ctx.* = .{
        .gpa = gpa,
        .service_prefix = try gpa.dupe(u8, service_name),
        .lib = lib,
        .glib = glib,
        .fns = fns,
        .schema = .{
            .name = "io.outlookemail.Credential",
            .flags = SECRET_SCHEMA_NONE,
            .attributes = blk: {
                var attrs: [32]SecretSchema.Attribute = @splat(.{});
                attrs[0] = .{ .name = "service", .type = SECRET_SCHEMA_ATTRIBUTE_STRING };
                attrs[1] = .{ .name = "account", .type = SECRET_SCHEMA_ATTRIBUTE_STRING };
                break :blk attrs;
            },
        },
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
    ctx.lib.close();
    ctx.glib.close();
    gpa.destroy(ctx);
}

fn makeService(ctx: *Ctx, label: []const u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(ctx.gpa, "{s}:{s}", .{ ctx.service_prefix, label }, 0);
}

fn setImpl(ctx_ptr: *anyopaque, e: keystore.Entry) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const svc = makeService(ctx, e.label) catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);
    const acct_z = ctx.gpa.dupeZ(u8, e.account) catch return error.OutOfMemory;
    defer ctx.gpa.free(acct_z);
    const secret_z = ctx.gpa.dupeZ(u8, e.secret) catch return error.OutOfMemory;
    defer ctx.gpa.free(secret_z);

    var err: ?*GError = null;
    const ok = ctx.fns.secret_password_store_sync(
        &ctx.schema,
        null, // default collection
        "outlook-email",
        secret_z.ptr,
        null,
        &err,
        "service",
        svc.ptr,
        "account",
        acct_z.ptr,
        null,
    );
    if (ok == 0) {
        if (err) |e2| ctx.fns.g_error_free(e2);
        return error.KeystoreUnavailable;
    }
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
    const acct_z = ctx.gpa.dupeZ(u8, account) catch return error.OutOfMemory;
    defer ctx.gpa.free(acct_z);

    var err: ?*GError = null;
    const raw = ctx.fns.secret_password_lookup_sync(
        &ctx.schema,
        null,
        &err,
        "service",
        svc.ptr,
        "account",
        acct_z.ptr,
        null,
    );
    if (err) |e2| {
        ctx.fns.g_error_free(e2);
        return error.KeystoreUnavailable;
    }
    if (raw == null) return null;
    defer ctx.fns.secret_password_free(raw);
    const slice = std.mem.sliceTo(raw.?, 0);
    return gpa.dupe(u8, slice) catch return error.OutOfMemory;
}

fn deleteImpl(
    ctx_ptr: *anyopaque,
    account: []const u8,
    label: []const u8,
) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    const svc = makeService(ctx, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(svc);
    const acct_z = ctx.gpa.dupeZ(u8, account) catch return error.OutOfMemory;
    defer ctx.gpa.free(acct_z);

    var err: ?*GError = null;
    const removed = ctx.fns.secret_password_clear_sync(
        &ctx.schema,
        null,
        &err,
        "service",
        svc.ptr,
        "account",
        acct_z.ptr,
        null,
    );
    if (err) |e2| {
        ctx.fns.g_error_free(e2);
        return error.KeystoreUnavailable;
    }
    if (removed == 0) return error.KeystoreItemMissing;
}

fn listImpl(ctx_ptr: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8 {
    _ = ctx_ptr;
    _ = gpa;
    // libsecret doesn't offer a "search by service prefix and return all
    // matching account attributes" synchronously without a lot more API. For
    // v1 we shadow the account list in the INI config file. The auth layer
    // maintains a small index that drives `outlook accounts`.
    return &.{};
}

fn describeImpl(_: *anyopaque) []const u8 {
    return "Linux libsecret (Secret Service / GNOME Keyring)";
}
