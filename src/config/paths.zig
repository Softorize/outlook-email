//! OS-aware config, data, and cache directory resolution.
//!
//! Follows the XDG Base Directory Specification on Linux/BSD, Apple's
//! Application Support conventions on macOS, and the usual %APPDATA% /
//! %LOCALAPPDATA% layout on Windows. Paths are returned as owned slices;
//! callers free with the same allocator.

const std = @import("std");
const builtin = @import("builtin");

pub const app_name = "outlook-email";

/// Directory for user-editable config (`config.ini`, etc.).
///   Linux/BSD: $XDG_CONFIG_HOME/outlook-email  (fallback: ~/.config/outlook-email)
///   macOS:     ~/Library/Application Support/outlook-email
///   Windows:   %APPDATA%\outlook-email
pub fn configDir(gpa: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => joinHome(gpa, &.{ "Library", "Application Support", app_name }),
        .windows => fromEnv(gpa, "APPDATA", app_name) orelse
            try joinHome(gpa, &.{ "AppData", "Roaming", app_name }),
        else => fromEnv(gpa, "XDG_CONFIG_HOME", app_name) orelse
            try joinHome(gpa, &.{ ".config", app_name }),
    };
}

/// Directory for persistent data that isn't part of the config file
/// (encrypted credential file fallback, cached attachments, ...).
pub fn dataDir(gpa: std.mem.Allocator) ![]u8 {
    return std.fs.getAppDataDir(gpa, app_name);
}

/// Path to the main user config file.
pub fn configFile(gpa: std.mem.Allocator) ![]u8 {
    const dir = try configDir(gpa);
    defer gpa.free(dir);
    return std.fs.path.join(gpa, &.{ dir, "config.ini" });
}

/// Ensure a directory exists, creating parents as needed.
pub fn ensureDir(path: []const u8) !void {
    std.fs.cwd().makePath(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

fn joinHome(gpa: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    const home_env = if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = std.process.getEnvVarOwned(gpa, home_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.HomeNotSet,
        else => return err,
    };
    defer gpa.free(home);

    var all_parts: std.ArrayList([]const u8) = .empty;
    defer all_parts.deinit(gpa);
    try all_parts.append(gpa, home);
    try all_parts.appendSlice(gpa, parts);
    return std.fs.path.join(gpa, all_parts.items);
}

fn fromEnv(gpa: std.mem.Allocator, var_name: []const u8, leaf: []const u8) ?[]u8 {
    const base = std.process.getEnvVarOwned(gpa, var_name) catch return null;
    defer gpa.free(base);
    if (base.len == 0) return null;
    return std.fs.path.join(gpa, &.{ base, leaf }) catch null;
}
