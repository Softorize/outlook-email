//! CLI dispatch: parse argv, initialise shared context, look up the
//! subcommand, run it, return an exit code.
//!
//! `Context` bundles the long-lived objects that every subcommand needs
//! (config, HTTP client, keystore, auth session, graph context, output
//! renderer). Subcommands receive a mutable `*Context` plus their remaining
//! args and return either void on success or an error which dispatch maps
//! to an exit code.

const std = @import("std");
const build_options = @import("build_options");

const errors = @import("../errors.zig");
const io = @import("../util/io.zig");
const config = @import("../config/config.zig");
const keystore = @import("../keystore/keystore.zig");
const http = @import("../graph/http.zig");
const graph = @import("../graph/graph.zig");
const auth = @import("../auth/auth.zig");
const render = @import("../render/render.zig");
const color_mod = @import("../render/color.zig");
const log = @import("../util/log.zig");

const args_mod = @import("args.zig");

const cmd_login = @import("commands/login.zig");
const cmd_logout = @import("commands/logout.zig");
const cmd_accounts = @import("commands/accounts.zig");
const cmd_use = @import("commands/use.zig");
const cmd_list = @import("commands/list.zig");
const cmd_read = @import("commands/read.zig");
const cmd_send = @import("commands/send.zig");
const cmd_reply = @import("commands/reply.zig");
const cmd_forward = @import("commands/forward.zig");
const cmd_delete = @import("commands/delete.zig");
const cmd_archive = @import("commands/archive.zig");
const cmd_search = @import("commands/search.zig");
const cmd_folders = @import("commands/folders.zig");

pub const Context = struct {
    gpa: std.mem.Allocator,
    cfg: *config.Config,
    keystore_backend: keystore.Backend,
    http_client: *http.Client,
    session: *auth.Session,
    graph_ctx: *graph.Ctx,
    output: render.Output,
    env: *std.process.EnvMap,

    pub fn diagnose(self: *Context, diag: errors.Diagnostic) void {
        self.output.writeError(self.gpa, diag) catch {};
    }

    pub fn writeOk(self: *Context, msg: []const u8) void {
        self.output.writeOkMessage(self.gpa, msg) catch {};
    }
};

pub fn dispatch(
    gpa: std.mem.Allocator,
    argv: []const []const u8,
    env: *std.process.EnvMap,
) !u8 {
    var parsed = args_mod.parseGlobals(argv) catch |err| {
        switch (err) {
            error.UnknownGlobalFlag => io.err("ocli: unknown global flag\n"),
            error.MissingGlobalValue => io.err("ocli: global flag missing value\n"),
        }
        return 2;
    };

    // Allow the global boolean flags (--json, --no-color, --verbose) after
    // the command name too, e.g. `ocli accounts --json`. Anything else in
    // the post-command tail belongs to the command's own parser.
    const cleaned_rest = try args_mod.stripPostCommandGlobals(gpa, parsed.rest, &parsed.globals);
    defer gpa.free(cleaned_rest);
    parsed.rest = cleaned_rest;

    if (parsed.globals.verbose) log.setVerbose(true);

    const cmd_name = parsed.command orelse {
        try printUsage();
        return 0;
    };

    // --help / --version / help always work without auth / config.
    if (std.mem.eql(u8, cmd_name, "--help") or std.mem.eql(u8, cmd_name, "-h") or std.mem.eql(u8, cmd_name, "help")) {
        try printUsage();
        return 0;
    }
    if (std.mem.eql(u8, cmd_name, "--version") or std.mem.eql(u8, cmd_name, "-V") or std.mem.eql(u8, cmd_name, "version")) {
        try printVersion();
        return 0;
    }

    var cfg = config.load(gpa) catch |err| switch (err) {
        error.BadConfigFile => {
            io.err("ocli: invalid config file\n");
            return 3;
        },
        else => return err,
    };
    defer cfg.deinit();

    if (parsed.globals.client_id_override) |v| cfg.client_id = try cfg.allocator().dupe(u8, v);
    if (parsed.globals.tenant_override) |v| cfg.tenant = try cfg.allocator().dupe(u8, v);
    if (parsed.globals.proxy) |v| cfg.proxy = try cfg.allocator().dupe(u8, v);
    if (parsed.globals.ca_bundle) |v| cfg.ca_bundle = try cfg.allocator().dupe(u8, v);
    if (parsed.globals.no_color) cfg.color = .never;
    if (parsed.globals.account) |v| cfg.current_account = try cfg.allocator().dupe(u8, v);

    const mode: render.Mode = if (parsed.globals.json) .json else .human;
    const profile = color_mod.decide(cfg.color, env, parsed.globals.json);

    var ks_backend = keystore.open(gpa, "outlook-email") catch |err| {
        var diag = errors.Diagnostic.simple(classifyAnyError(err));
        diag.hint = "Check that your OS credential store is reachable.";
        render.human.writeError(diag, profile) catch {};
        return 4;
    };
    defer ks_backend.close();

    var http_client = http.Client.init(gpa, "outlook-email/" ++ build_options.app_version) catch {
        const diag = errors.Diagnostic.simple(error.NetworkUnreachable);
        render.human.writeError(diag, profile) catch {};
        return 5;
    };
    defer http_client.deinit();
    // Only commands that actually hit the network pay the cost of scanning
    // env vars and parsing proxy URLs.
    if (!isOfflineCommand(cmd_name)) {
        http_client.enableEnvProxies() catch {};
    }

    var session = auth.Session.init(gpa, &cfg, ks_backend, &http_client);
    defer session.deinit();

    var graph_ctx: graph.Ctx = .{
        .gpa = gpa,
        .http_client = &http_client,
        .session = &session,
    };

    var ctx: Context = .{
        .gpa = gpa,
        .cfg = &cfg,
        .keystore_backend = ks_backend,
        .http_client = &http_client,
        .session = &session,
        .graph_ctx = &graph_ctx,
        .output = .{ .mode = mode, .profile = profile },
        .env = env,
    };

    runCommand(&ctx, cmd_name, parsed.rest) catch |err| {
        const canonical = classifyAnyError(err);
        const diag = errors.Diagnostic.simple(canonical);
        ctx.diagnose(diag);
        return exitCodeFor(canonical);
    };
    return 0;
}

fn isOfflineCommand(name: []const u8) bool {
    return std.mem.eql(u8, name, "accounts") or
        std.mem.eql(u8, name, "logout") or
        std.mem.eql(u8, name, "use");
}

fn classifyAnyError(err: anyerror) errors.Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.UserAborted => error.UserAborted,
        error.InvalidArgument => error.InvalidArgument,
        error.MissingClientId => error.MissingClientId,
        error.NotSignedIn => error.NotSignedIn,
        error.NoCurrentAccount => error.NoCurrentAccount,
        error.AccountNotFound => error.AccountNotFound,
        error.Unauthorized => error.Unauthorized,
        error.TokenExpiredNoRefresh => error.TokenExpiredNoRefresh,
        error.DeviceFlowDenied => error.DeviceFlowDenied,
        error.DeviceFlowExpired => error.DeviceFlowExpired,
        error.DeviceFlowPollFailed => error.DeviceFlowPollFailed,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.TlsHandshakeFailed => error.TlsHandshakeFailed,
        error.ProxyAuthRequired => error.ProxyAuthRequired,
        error.RateLimited => error.RateLimited,
        error.HttpStatus => error.HttpStatus,
        error.GraphMalformedJson => error.GraphMalformedJson,
        error.GraphUnknownSchema => error.GraphUnknownSchema,
        error.GraphBadRequest => error.GraphBadRequest,
        error.KeystoreUnavailable => error.KeystoreUnavailable,
        error.KeystoreItemMissing => error.KeystoreItemMissing,
        error.KeystoreAccessDenied => error.KeystoreAccessDenied,
        error.BadConfigFile => error.BadConfigFile,
        error.UnknownFlag, error.MissingValue, error.InvalidRecipient => error.InvalidArgument,
        error.FileNotFound, error.AccessDenied, error.PermissionDenied, error.IsDir, error.NotDir, error.BadPathName => error.Io,
        else => error.Io,
    };
}

fn runCommand(ctx: *Context, cmd_name: []const u8, rest: []const []const u8) !void {
    if (std.mem.eql(u8, cmd_name, "login")) return cmd_login.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "logout")) return cmd_logout.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "accounts")) return cmd_accounts.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "use")) return cmd_use.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "list")) return cmd_list.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "read")) return cmd_read.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "send")) return cmd_send.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "reply")) return cmd_reply.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "forward")) return cmd_forward.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "delete")) return cmd_delete.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "archive")) return cmd_archive.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "search")) return cmd_search.run(ctx, rest);
    if (std.mem.eql(u8, cmd_name, "folders")) return cmd_folders.run(ctx, rest);
    io.err("ocli: unknown command\n");
    return error.InvalidArgument;
}

fn exitCodeFor(err: anyerror) u8 {
    return switch (err) {
        error.UserAborted => 130,
        error.InvalidArgument => 2,
        error.MissingClientId, error.NotSignedIn, error.NoCurrentAccount, error.AccountNotFound => 3,
        error.Unauthorized, error.TokenExpiredNoRefresh => 4,
        error.RateLimited => 5,
        error.NetworkUnreachable, error.TlsHandshakeFailed => 6,
        else => 1,
    };
}

fn printVersion() !void {
    io.outPrint("ocli {s}\n", .{build_options.app_version});
}

fn printUsage() !void {
    const usage =
        \\ocli -- Microsoft 365 email from the terminal
        \\
        \\Usage: ocli <command> [options]
        \\
        \\Commands:
        \\  login              Sign in with a Microsoft work or personal account
        \\  logout [account]   Remove a saved session
        \\  accounts           List saved accounts
        \\  use <account>      Switch the active account
        \\
        \\  list               List messages in a folder (default: inbox)
        \\  read <id>          Show a full message
        \\  search <query>     Search messages across subject/sender/body
        \\  folders            List mail folders
        \\
        \\  send               Compose and send a new message (body from stdin)
        \\  reply <id>         Reply to a message (body from stdin)
        \\  forward <id>       Forward a message (body from stdin)
        \\  delete <id>        Delete a message
        \\  archive <id>       Move a message to Archive
        \\
        \\Global flags:
        \\  --json             Machine-readable output
        \\  --no-color         Disable ANSI colours
        \\  --verbose          Log HTTP activity to stderr
        \\  --proxy URL        HTTPS proxy (overrides HTTPS_PROXY)
        \\  --ca-bundle PATH   PEM file of root CAs for corporate TLS proxies
        \\  --account EMAIL    Use this account for this command
        \\  --client-id ID     Override the built-in Azure client ID
        \\  --tenant T         Override the Azure tenant (default: common)
        \\
        \\See README.md for Azure app registration and first-run instructions.
        \\
    ;
    io.out(usage);
}
