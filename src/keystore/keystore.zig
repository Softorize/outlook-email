//! OS credential store abstraction.
//!
//! Each supported OS has a native backend (macOS Keychain via
//! Security.framework, Windows Credential Manager via wincred). Linux tries
//! libsecret at runtime via `std.DynLib.open`; if that fails (headless box,
//! no D-Bus session, missing library), a machine-bound encrypted file backend
//! is used instead with a warning printed to stderr.
//!
//! Two orthogonal entries are stored per account:
//!   - label = "refresh_token": the long-lived refresh token
//!   - label = "token_meta":    small JSON with access_token + expires_at_unix
//!
//! This lets the auth layer refresh silently without hitting the network if
//! the cached access token is still valid.

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("../errors.zig");

const Error = errors.Error;

pub const Entry = struct {
    /// User principal name, e.g. "alice@contoso.com".
    account: []const u8,
    /// Logical label: "refresh_token" or "token_meta".
    label: []const u8,
    /// Owned by caller for set(); returned allocated by get().
    secret: []const u8,
};

pub const Backend = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        // Mutating operations use the backend's own internal allocator, so
        // they don't take one. Read operations (get, list) hand bytes back
        // to the caller and so do take a caller-chosen allocator.
        set: *const fn (ctx: *anyopaque, e: Entry) Error!void,
        get: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator, account: []const u8, label: []const u8) Error!?[]u8,
        delete: *const fn (ctx: *anyopaque, account: []const u8, label: []const u8) Error!void,
        list: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8,
        describe: *const fn (ctx: *anyopaque) []const u8,
        close: *const fn (ctx: *anyopaque) void,
    };

    pub fn set(self: Backend, e: Entry) Error!void {
        return self.vtable.set(self.ctx, e);
    }
    pub fn get(self: Backend, gpa: std.mem.Allocator, account: []const u8, label: []const u8) Error!?[]u8 {
        return self.vtable.get(self.ctx, gpa, account, label);
    }
    pub fn delete(self: Backend, account: []const u8, label: []const u8) Error!void {
        return self.vtable.delete(self.ctx, account, label);
    }
    pub fn list(self: Backend, gpa: std.mem.Allocator) Error![][]const u8 {
        return self.vtable.list(self.ctx, gpa);
    }
    pub fn describe(self: Backend) []const u8 {
        return self.vtable.describe(self.ctx);
    }
    pub fn close(self: Backend) void {
        self.vtable.close(self.ctx);
    }
};

/// Open the best available backend for this OS. Falls back to an encrypted
/// file store if the platform native store is unreachable.
pub fn open(gpa: std.mem.Allocator, service_name: []const u8) !Backend {
    return switch (builtin.os.tag) {
        .macos => @import("macos.zig").open(gpa, service_name),
        .linux, .freebsd, .openbsd, .netbsd, .dragonfly => blk: {
            if (@import("linux.zig").open(gpa, service_name)) |b| {
                break :blk b;
            } else |err| switch (err) {
                error.KeystoreUnavailable => {
                    warnFallback();
                    break :blk try @import("file_fallback.zig").open(gpa, service_name);
                },
                else => return err,
            }
        },
        .windows => @import("windows.zig").open(gpa, service_name),
        else => blk: {
            warnFallback();
            break :blk try @import("file_fallback.zig").open(gpa, service_name);
        },
    };
}

fn warnFallback() void {
    @import("../util/io.zig").err(
        "outlook: native credential store unavailable, using encrypted file fallback.\n" ++
            "         See README.md for the security trade-offs.\n",
    );
}

/// In-memory backend for tests. Not exposed through `open()`.
pub const MemoryBackend = struct {
    gpa: std.mem.Allocator,
    items: std.StringHashMapUnmanaged([]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) MemoryBackend {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *MemoryBackend) void {
        var it = self.items.iterator();
        while (it.next()) |kv| {
            self.gpa.free(kv.key_ptr.*);
            self.gpa.free(kv.value_ptr.*);
        }
        self.items.deinit(self.gpa);
    }

    pub fn backend(self: *MemoryBackend) Backend {
        return .{
            .ctx = self,
            .vtable = &.{
                .set = mbSet,
                .get = mbGet,
                .delete = mbDelete,
                .list = mbList,
                .describe = mbDescribe,
                .close = mbClose,
            },
        };
    }

    fn mbClose(_: *anyopaque) void {
        // The MemoryBackend is owned by the test; deinit is called directly.
    }

    fn composeKey(gpa: std.mem.Allocator, account: []const u8, label: []const u8) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{s}", .{ account, label });
    }

    fn mbSet(ctx: *anyopaque, e: Entry) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        const key = composeKey(self.gpa, e.account, e.label) catch return error.OutOfMemory;
        errdefer self.gpa.free(key);
        const val = self.gpa.dupe(u8, e.secret) catch return error.OutOfMemory;
        errdefer self.gpa.free(val);
        if (self.items.fetchRemove(key)) |old| {
            self.gpa.free(old.key);
            self.gpa.free(old.value);
        }
        self.items.put(self.gpa, key, val) catch return error.OutOfMemory;
    }
    fn mbGet(ctx: *anyopaque, gpa: std.mem.Allocator, account: []const u8, label: []const u8) Error!?[]u8 {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        const key = composeKey(self.gpa, account, label) catch return error.OutOfMemory;
        defer self.gpa.free(key);
        const v = self.items.get(key) orelse return null;
        return gpa.dupe(u8, v) catch return error.OutOfMemory;
    }
    fn mbDelete(ctx: *anyopaque, account: []const u8, label: []const u8) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        const key = composeKey(self.gpa, account, label) catch return error.OutOfMemory;
        defer self.gpa.free(key);
        if (self.items.fetchRemove(key)) |old| {
            self.gpa.free(old.key);
            self.gpa.free(old.value);
        } else return error.KeystoreItemMissing;
    }
    fn mbList(ctx: *anyopaque, gpa: std.mem.Allocator) Error![][]const u8 {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        var out: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (out.items) |s| gpa.free(s);
            out.deinit(gpa);
        }
        var it = self.items.keyIterator();
        outer: while (it.next()) |k_ptr| {
            const k = k_ptr.*;
            const sep = std.mem.indexOfScalar(u8, k, 0) orelse continue;
            const account = k[0..sep];
            for (out.items) |existing| {
                if (std.mem.eql(u8, existing, account)) continue :outer;
            }
            const dup = gpa.dupe(u8, account) catch return error.OutOfMemory;
            out.append(gpa, dup) catch {
                gpa.free(dup);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
    }
    fn mbDescribe(_: *anyopaque) []const u8 {
        return "in-memory (test)";
    }
};

test "memory backend round-trip" {
    var mb = MemoryBackend.init(std.testing.allocator);
    defer mb.deinit();
    const b = mb.backend();
    try b.set(.{ .account = "a@x.com", .label = "refresh_token", .secret = "secret-value" });
    const got = try b.get(std.testing.allocator, "a@x.com", "refresh_token") orelse unreachable;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("secret-value", got);

    const accounts = try b.list(std.testing.allocator);
    defer {
        for (accounts) |s| std.testing.allocator.free(s);
        std.testing.allocator.free(accounts);
    }
    try std.testing.expectEqual(@as(usize, 1), accounts.len);
    try std.testing.expectEqualStrings("a@x.com", accounts[0]);

    try b.delete("a@x.com", "refresh_token");
    try std.testing.expect((try b.get(std.testing.allocator, "a@x.com", "refresh_token")) == null);
}
