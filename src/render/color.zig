//! ANSI colour gating.
//!
//! Precedence (highest first):
//!   1. NO_COLOR env var present  -> never
//!   2. CLICOLOR_FORCE=1          -> always
//!   3. explicit --no-color or --color=... from the CLI
//!   4. stdout is a TTY           -> auto enables colour
//!   5. otherwise                 -> never

const std = @import("std");
const config = @import("../config/config.zig");

pub const Profile = struct {
    enabled: bool,

    pub fn reset(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[0m" else "";
    }
    pub fn bold(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[1m" else "";
    }
    pub fn dim(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[2m" else "";
    }
    pub fn red(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[31m" else "";
    }
    pub fn green(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[32m" else "";
    }
    pub fn yellow(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[33m" else "";
    }
    pub fn blue(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[34m" else "";
    }
    pub fn cyan(self: Profile) []const u8 {
        return if (self.enabled) "\x1b[36m" else "";
    }
};

pub fn decide(cfg_color: config.ColorMode, env: *std.process.EnvMap, json_mode: bool) Profile {
    if (json_mode) return .{ .enabled = false };
    if (env.get("NO_COLOR") != null) return .{ .enabled = false };
    if (env.get("CLICOLOR_FORCE")) |v| {
        if (v.len > 0 and v[0] != '0') return .{ .enabled = true };
    }
    return switch (cfg_color) {
        .always => .{ .enabled = true },
        .never => .{ .enabled = false },
        .auto => .{ .enabled = stdoutIsTty() },
    };
}

fn stdoutIsTty() bool {
    const f = std.fs.File.stdout();
    return f.isTty();
}
