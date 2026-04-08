//! Build script for the outlook-email CLI.
//!
//! The company distributing this binary bakes in their Azure client ID at
//! build time: `zig build -Dclient-id=<GUID>`. End users never see an app
//! registration step.
//!
//! Cross-compile with `-Dtarget=x86_64-linux-musl` etc. Platform-specific
//! system libraries are linked conditionally.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ------------------------------------------------------------------
    // Build-time options (baked into the binary by IT / the distributor).
    // ------------------------------------------------------------------
    const client_id = b.option(
        []const u8,
        "client-id",
        "Azure AD application (client) ID to bake into the binary",
    ) orelse "";

    const tenant = b.option(
        []const u8,
        "tenant",
        "Azure AD tenant (default: 'common' for multi-tenant + MSA)",
    ) orelse "common";

    const app_version = b.option(
        []const u8,
        "app-version",
        "Version string embedded in --version output",
    ) orelse "0.1.0";

    const opts = b.addOptions();
    opts.addOption([]const u8, "azure_client_id", client_id);
    opts.addOption([]const u8, "azure_tenant", tenant);
    opts.addOption([]const u8, "app_name", "outlook-email");
    opts.addOption([]const u8, "app_version", app_version);

    // ------------------------------------------------------------------
    // Executable.
    // ------------------------------------------------------------------
    const exe = b.addExecutable(.{
        .name = "outlook",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addOptions("build_options", opts);

    // Platform-specific linking. macOS keychain needs Security + CoreFoundation;
    // Windows Credential Manager lives in advapi32. Linux uses std.DynLib at
    // runtime to load libsecret, so nothing is linked at build time -- the
    // binary stays usable on headless boxes without libsecret installed.
    const os_tag = target.result.os.tag;
    switch (os_tag) {
        .macos => {
            exe.root_module.linkFramework("Security", .{});
            exe.root_module.linkFramework("CoreFoundation", .{});
        },
        .windows => {
            exe.root_module.linkSystemLibrary("advapi32", .{});
        },
        else => {},
    }

    b.installArtifact(exe);

    // ------------------------------------------------------------------
    // `zig build run -- <args>`
    // ------------------------------------------------------------------
    const run_step = b.step("run", "Run the outlook CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // ------------------------------------------------------------------
    // `zig build test` -- unit tests only, offline, hermetic.
    // Integration tests live in tests/integration and are gated by env var.
    // ------------------------------------------------------------------
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);
}
