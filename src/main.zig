//! Entry point for the outlook CLI.
//!
//! Main's only job is to acquire a GPA, gather argv + env, and hand off to
//! cli.dispatch. All real logic lives in modules.

const std = @import("std");
const build_options = @import("build_options");

const cli = @import("cli/cli.zig");

pub fn main() !u8 {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    var env = try std.process.getEnvMap(gpa);
    defer env.deinit();

    return cli.dispatch(gpa, argv, &env) catch |err| {
        // Last-resort handler: cli.dispatch is supposed to catch all
        // recoverable errors itself and return an exit code. If one escapes
        // it's a bug; print what we can and exit non-zero.
        std.debug.print("ocli: unexpected error: {s}\n", .{@errorName(err)});
        return 1;
    };
}

comptime {
    // Embed build metadata so --version has something to print even before
    // the CLI layer wires it up.
    _ = build_options.azure_client_id;
    _ = build_options.app_version;
}
