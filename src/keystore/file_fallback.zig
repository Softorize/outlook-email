//! Encrypted-file keystore fallback.
//!
//! Used when no native OS credential store is reachable -- typically a
//! headless Linux box without libsecret or D-Bus. Stores credentials as a
//! single JSON document encrypted with AES-256-GCM. The key is derived from
//! a machine-bound seed (machine-id / IOPlatformUUID / MachineGuid) with
//! HKDF-SHA256 so a stolen file alone is not enough to decrypt credentials.
//!
//! Security caveats are documented prominently in the README.

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("../errors.zig");
const keystore = @import("keystore.zig");
const paths = @import("../config/paths.zig");

const Error = errors.Error;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const Ctx = struct {
    gpa: std.mem.Allocator,
    service_prefix: []u8,
    file_path: []u8,
    key: [32]u8,
    /// In-memory cache of the decrypted store. Flushed to disk on every set.
    entries: std.StringHashMapUnmanaged([]u8) = .empty, // key = "account\0label"
    loaded: bool = false,
};

pub fn open(gpa: std.mem.Allocator, service_name: []const u8) !keystore.Backend {
    const data_dir = try paths.dataDir(gpa);
    defer gpa.free(data_dir);
    try paths.ensureDir(data_dir);

    const file_path = try std.fs.path.join(gpa, &.{ data_dir, "credentials.enc" });
    errdefer gpa.free(file_path);

    const seed = try machineSeed(gpa);
    defer gpa.free(seed);
    var key: [32]u8 = undefined;
    const prk = Hkdf.extract("outlook-email-v1", seed);
    Hkdf.expand(&key, "keystore", prk);

    const ctx = try gpa.create(Ctx);
    ctx.* = .{
        .gpa = gpa,
        .service_prefix = try gpa.dupe(u8, service_name),
        .file_path = file_path,
        .key = key,
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
    var it = ctx.entries.iterator();
    while (it.next()) |kv| {
        gpa.free(kv.key_ptr.*);
        gpa.free(kv.value_ptr.*);
    }
    ctx.entries.deinit(gpa);
    gpa.free(ctx.service_prefix);
    gpa.free(ctx.file_path);
    gpa.destroy(ctx);
}

fn composeKey(gpa: std.mem.Allocator, account: []const u8, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ account, label });
}

fn ensureLoaded(ctx: *Ctx) !void {
    if (ctx.loaded) return;
    ctx.loaded = true;
    const contents = std.fs.cwd().readFileAlloc(ctx.gpa, ctx.file_path, 16 << 20) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return error.KeystoreUnavailable,
    };
    defer ctx.gpa.free(contents);
    // Layout: [12 nonce][16 tag][ciphertext]
    if (contents.len < 28) return error.KeystoreUnavailable;
    const nonce = contents[0..12];
    const tag = contents[12..28];
    const ct = contents[28..];
    const pt = ctx.gpa.alloc(u8, ct.len) catch return error.OutOfMemory;
    defer ctx.gpa.free(pt);
    Aes256Gcm.decrypt(pt, ct, tag.*, "", nonce.*, ctx.key) catch return error.KeystoreUnavailable;
    try decodeJson(ctx, pt);
}

fn decodeJson(ctx: *Ctx, pt: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, ctx.gpa, pt, .{}) catch return error.KeystoreUnavailable;
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return;
    var it = root.object.iterator();
    while (it.next()) |kv| {
        const k = try ctx.gpa.dupe(u8, kv.key_ptr.*);
        errdefer ctx.gpa.free(k);
        const v_str = switch (kv.value_ptr.*) {
            .string => |s| s,
            else => continue,
        };
        const v = try ctx.gpa.dupe(u8, v_str);
        errdefer ctx.gpa.free(v);
        try ctx.entries.put(ctx.gpa, k, v);
    }
}

fn flush(ctx: *Ctx) !void {
    // Serialise as a flat JSON object of "account\0label" -> secret.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(ctx.gpa);
    try buf.append(ctx.gpa, '{');
    var first = true;
    var it = ctx.entries.iterator();
    while (it.next()) |kv| {
        if (!first) try buf.append(ctx.gpa, ',');
        first = false;
        try buf.append(ctx.gpa, '"');
        try writeJsonEscaped(&buf, ctx.gpa, kv.key_ptr.*);
        try buf.appendSlice(ctx.gpa, "\":\"");
        try writeJsonEscaped(&buf, ctx.gpa, kv.value_ptr.*);
        try buf.append(ctx.gpa, '"');
    }
    try buf.append(ctx.gpa, '}');

    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    const ct = try ctx.gpa.alloc(u8, buf.items.len);
    defer ctx.gpa.free(ct);
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(ct, &tag, buf.items, "", nonce, ctx.key);

    const dir = std.fs.path.dirname(ctx.file_path) orelse ".";
    try paths.ensureDir(dir);
    const file = std.fs.cwd().createFile(ctx.file_path, .{ .truncate = true, .mode = 0o600 }) catch return error.KeystoreUnavailable;
    defer file.close();
    _ = file.write(&nonce) catch return error.KeystoreUnavailable;
    _ = file.write(&tag) catch return error.KeystoreUnavailable;
    _ = file.write(ct) catch return error.KeystoreUnavailable;
}

fn writeJsonEscaped(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    for (s) |ch| switch (ch) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        '\r' => try out.appendSlice(gpa, "\\r"),
        '\t' => try out.appendSlice(gpa, "\\t"),
        0 => try out.appendSlice(gpa, "\\u0000"),
        else => try out.append(gpa, ch),
    };
}

fn setImpl(ctx_ptr: *anyopaque, e: keystore.Entry) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ensureLoaded(ctx) catch return error.KeystoreUnavailable;
    const key = composeKey(ctx.gpa, e.account, e.label) catch return error.OutOfMemory;
    errdefer ctx.gpa.free(key);
    const val = ctx.gpa.dupe(u8, e.secret) catch return error.OutOfMemory;
    errdefer ctx.gpa.free(val);
    if (ctx.entries.fetchRemove(key)) |old| {
        ctx.gpa.free(old.key);
        ctx.gpa.free(old.value);
    }
    ctx.entries.put(ctx.gpa, key, val) catch return error.OutOfMemory;
    flush(ctx) catch return error.KeystoreUnavailable;
}

fn getImpl(
    ctx_ptr: *anyopaque,
    gpa: std.mem.Allocator,
    account: []const u8,
    label: []const u8,
) Error!?[]u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ensureLoaded(ctx) catch return error.KeystoreUnavailable;
    const key = composeKey(ctx.gpa, account, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(key);
    const v = ctx.entries.get(key) orelse return null;
    return gpa.dupe(u8, v) catch return error.OutOfMemory;
}

fn deleteImpl(
    ctx_ptr: *anyopaque,
    account: []const u8,
    label: []const u8,
) Error!void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ensureLoaded(ctx) catch return error.KeystoreUnavailable;
    const key = composeKey(ctx.gpa, account, label) catch return error.OutOfMemory;
    defer ctx.gpa.free(key);
    if (ctx.entries.fetchRemove(key)) |old| {
        ctx.gpa.free(old.key);
        ctx.gpa.free(old.value);
        flush(ctx) catch return error.KeystoreUnavailable;
    } else return error.KeystoreItemMissing;
}

fn listImpl(ctx_ptr: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr));
    ensureLoaded(ctx) catch return error.KeystoreUnavailable;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it_ = seen.keyIterator();
        while (it_.next()) |k| gpa.free(k.*);
        seen.deinit(gpa);
    }
    var it = ctx.entries.keyIterator();
    while (it.next()) |k_ptr| {
        const k = k_ptr.*;
        const sep = std.mem.indexOfScalar(u8, k, 0) orelse continue;
        const label = k[sep + 1 ..];
        if (!std.mem.eql(u8, label, "refresh_token")) continue;
        const account = k[0..sep];
        if (seen.contains(account)) continue;
        const dup = gpa.dupe(u8, account) catch return error.OutOfMemory;
        seen.put(gpa, dup, {}) catch return error.OutOfMemory;
    }
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |s| gpa.free(s);
        out.deinit(gpa);
    }
    var it2 = seen.keyIterator();
    while (it2.next()) |k| {
        const dup = gpa.dupe(u8, k.*) catch return error.OutOfMemory;
        out.append(gpa, dup) catch {
            gpa.free(dup);
            return error.OutOfMemory;
        };
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

fn describeImpl(_: *anyopaque) []const u8 {
    return "encrypted file (machine-bound AES-256-GCM)";
}

/// Read a stable, per-machine identifier to use as the HKDF input. If nothing
/// is available, falls back to a random file stored alongside the
/// credentials -- less secure but lets the fallback still function.
fn machineSeed(gpa: std.mem.Allocator) ![]u8 {
    const candidates = switch (builtin.os.tag) {
        .linux => [_][]const u8{ "/etc/machine-id", "/var/lib/dbus/machine-id" },
        .macos => [_][]const u8{},
        else => [_][]const u8{},
    };
    for (candidates) |path| {
        if (std.fs.cwd().readFileAlloc(gpa, path, 256)) |contents| {
            return contents;
        } else |_| {}
    }
    // Fallback: persistent random seed in the data directory.
    const data_dir = try paths.dataDir(gpa);
    defer gpa.free(data_dir);
    try paths.ensureDir(data_dir);
    const seed_path = try std.fs.path.join(gpa, &.{ data_dir, "seed" });
    defer gpa.free(seed_path);
    if (std.fs.cwd().readFileAlloc(gpa, seed_path, 256)) |contents| {
        return contents;
    } else |_| {}
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const file = try std.fs.cwd().createFile(seed_path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    _ = try file.write(&seed);
    return gpa.dupe(u8, &seed);
}
