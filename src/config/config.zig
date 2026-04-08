//! Runtime configuration, merged from (highest priority first):
//!   1. CLI flags (applied by cli.dispatch after calling Config.load)
//!   2. Environment variables
//!   3. User config file (config.ini under the OS config dir)
//!   4. Build-time constants (`@import("build_options")`)
//!   5. Hardcoded defaults
//!
//! The config struct owns an arena that backs every string field, so the
//! caller only needs to call `deinit` once.

const std = @import("std");
const build_options = @import("build_options");
const paths = @import("paths.zig");
const ini = @import("ini.zig");
const errors = @import("../errors.zig");

pub const ColorMode = enum { auto, always, never };

pub const Config = struct {
    arena: std.heap.ArenaAllocator,

    client_id: []const u8,
    tenant: []const u8,
    redirect_uri: []const u8,
    scopes: []const []const u8,

    current_account: ?[]const u8,
    proxy: ?[]const u8,
    ca_bundle: ?[]const u8,
    color: ColorMode,

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Config) std.mem.Allocator {
        return self.arena.allocator();
    }
};

pub const default_scopes = [_][]const u8{
    "offline_access",
    "User.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.Read",
};

/// Load config from build options + env + file. CLI flags are applied by the
/// dispatcher after this returns.
pub fn load(gpa: std.mem.Allocator) !Config {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Start from build-time defaults.
    var cfg: Config = .{
        .arena = arena,
        .client_id = try a.dupe(u8, build_options.azure_client_id),
        .tenant = try a.dupe(u8, build_options.azure_tenant),
        .redirect_uri = try a.dupe(u8, "https://login.microsoftonline.com/common/oauth2/nativeclient"),
        .scopes = try dupeScopes(a, &default_scopes),
        .current_account = null,
        .proxy = null,
        .ca_bundle = null,
        .color = .auto,
    };

    if (paths.configFile(a)) |cfg_path| {
        if (std.fs.cwd().readFileAlloc(a, cfg_path, 1 << 20)) |contents| {
            var parsed = ini.parse(a, contents) catch |err| switch (err) {
                error.BadSectionHeader, error.MissingEquals => return error.BadConfigFile,
                else => |e| return e,
            };
            defer parsed.deinit();
            if (parsed.get("account", "current")) |v| cfg.current_account = try a.dupe(u8, v);
            if (parsed.get("network", "proxy")) |v| cfg.proxy = try a.dupe(u8, v);
            if (parsed.get("network", "ca_bundle")) |v| cfg.ca_bundle = try a.dupe(u8, v);
            if (parsed.get("ui", "color")) |v| cfg.color = parseColor(v);
            if (parsed.get("auth", "client_id")) |v| cfg.client_id = try a.dupe(u8, v);
            if (parsed.get("auth", "tenant")) |v| cfg.tenant = try a.dupe(u8, v);
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
    } else |_| {}

    try overrideFromEnv(a, &cfg, "OUTLOOK_CLIENT_ID", &cfg.client_id);
    try overrideFromEnv(a, &cfg, "OUTLOOK_TENANT", &cfg.tenant);
    try overrideFromEnvOpt(a, &cfg, "HTTPS_PROXY", &cfg.proxy);
    try overrideFromEnvOpt(a, &cfg, "OUTLOOK_CA_BUNDLE", &cfg.ca_bundle);
    if (std.process.getEnvVarOwned(a, "NO_COLOR")) |v| {
        _ = v; // presence alone disables colour per https://no-color.org/
        cfg.color = .never;
    } else |_| {}

    cfg.arena = arena;
    return cfg;
}

/// Save the subset of config that lives in the user file. Build-time values
/// and env-only overrides are not persisted.
pub fn save(gpa: std.mem.Allocator, cfg: *const Config) !void {
    const path = try paths.configFile(gpa);
    defer gpa.free(path);

    var entries: std.ArrayList(ini.Entry) = .empty;
    defer entries.deinit(gpa);

    if (cfg.current_account) |v| try entries.append(gpa, .{
        .section = "account",
        .key = "current",
        .value = v,
    });
    try entries.append(gpa, .{
        .section = "ui",
        .key = "color",
        .value = switch (cfg.color) {
            .auto => "auto",
            .always => "always",
            .never => "never",
        },
    });
    if (cfg.proxy) |v| try entries.append(gpa, .{
        .section = "network",
        .key = "proxy",
        .value = v,
    });
    if (cfg.ca_bundle) |v| try entries.append(gpa, .{
        .section = "network",
        .key = "ca_bundle",
        .value = v,
    });

    try ini.writeFile(path, entries.items);
}

fn overrideFromEnv(
    a: std.mem.Allocator,
    _: *Config,
    env_var: []const u8,
    target: *[]const u8,
) !void {
    if (std.process.getEnvVarOwned(a, env_var)) |v| {
        if (v.len > 0) target.* = v;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }
}

fn overrideFromEnvOpt(
    a: std.mem.Allocator,
    _: *Config,
    env_var: []const u8,
    target: *?[]const u8,
) !void {
    if (std.process.getEnvVarOwned(a, env_var)) |v| {
        if (v.len > 0) target.* = v;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }
}

fn parseColor(v: []const u8) ColorMode {
    if (std.mem.eql(u8, v, "always")) return .always;
    if (std.mem.eql(u8, v, "never")) return .never;
    return .auto;
}

fn dupeScopes(a: std.mem.Allocator, src: []const []const u8) ![][]const u8 {
    const out = try a.alloc([]const u8, src.len);
    for (src, 0..) |s, i| out[i] = try a.dupe(u8, s);
    return out;
}

pub fn ensureClientId(cfg: *const Config) errors.Error!void {
    if (cfg.client_id.len == 0) return error.MissingClientId;
}
