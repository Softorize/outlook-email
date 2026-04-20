//! Azure AD v2 endpoint URL builders.

const std = @import("std");

/// Returns an allocated URL like
/// "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode".
pub fn deviceCodeUrl(gpa: std.mem.Allocator, tenant: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "https://login.microsoftonline.com/{s}/oauth2/v2.0/devicecode",
        .{tenant},
    );
}

pub fn tokenUrl(gpa: std.mem.Allocator, tenant: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "https://login.microsoftonline.com/{s}/oauth2/v2.0/token",
        .{tenant},
    );
}

pub fn authorizeUrl(gpa: std.mem.Allocator, tenant: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "https://login.microsoftonline.com/{s}/oauth2/v2.0/authorize",
        .{tenant},
    );
}
