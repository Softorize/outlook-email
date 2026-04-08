//! High-level auth session: device code login, silent refresh, logout,
//! account switching. Owns the interaction with the keystore for token
//! persistence and exposes a BearerProvider so the graph HTTP layer can
//! fetch a valid access token on demand.

const std = @import("std");
const errors = @import("../errors.zig");
const http = @import("../graph/http.zig");
const http_util = @import("../util/http_util.zig");
const config = @import("../config/config.zig");
const keystore = @import("../keystore/keystore.zig");
const device_flow = @import("device_flow.zig");
const endpoints = @import("endpoints.zig");
const token_mod = @import("token.zig");
const log = @import("../util/log.zig");

const Error = errors.Error;

pub const Session = struct {
    gpa: std.mem.Allocator,
    cfg: *const config.Config,
    ks: keystore.Backend,
    http_client: *http.Client,

    /// Currently-selected account UPN. When null, no commands requiring auth
    /// can run.
    account: ?[]const u8 = null,

    pub fn init(
        gpa: std.mem.Allocator,
        cfg: *const config.Config,
        ks: keystore.Backend,
        http_client: *http.Client,
    ) Session {
        const initial: ?[]const u8 = if (cfg.current_account) |a|
            (gpa.dupe(u8, a) catch null)
        else
            null;
        return .{
            .gpa = gpa,
            .cfg = cfg,
            .ks = ks,
            .http_client = http_client,
            .account = initial,
        };
    }

    pub fn deinit(self: *Session) void {
        if (self.account) |a| self.gpa.free(a);
        self.account = null;
    }

    fn setAccount(self: *Session, new_account: []const u8) !void {
        const dup = try self.gpa.dupe(u8, new_account);
        if (self.account) |old| self.gpa.free(old);
        self.account = dup;
    }

    pub fn bearerProvider(self: *Session) http.BearerProvider {
        return .{ .ctx = self, .getFn = bearerGetFn };
    }

    fn bearerGetFn(ctx: *anyopaque, gpa: std.mem.Allocator) Error![]const u8 {
        const self: *Session = @ptrCast(@alignCast(ctx));
        return self.currentAccessToken(gpa);
    }

    /// Returns a valid access token for `self.account`. If the persisted
    /// access token is within 60 seconds of expiry it is silently refreshed
    /// using the saved refresh token. Caller owns the returned bytes.
    pub fn currentAccessToken(self: *Session, gpa: std.mem.Allocator) Error![]const u8 {
        const account = self.account orelse return error.NotSignedIn;
        const now = std.time.timestamp();

        if (try self.ks.get(self.gpa, account, "token_meta")) |meta_raw| {
            defer self.gpa.free(meta_raw);
            if (token_mod.parseMeta(self.gpa, meta_raw)) |meta| {
                defer self.gpa.free(meta.access_token);
                if (now + 60 < meta.expires_at_unix) {
                    return gpa.dupe(u8, meta.access_token) catch return error.OutOfMemory;
                }
            } else |_| {}
        }

        const refresh = (try self.ks.get(self.gpa, account, "refresh_token")) orelse return error.TokenExpiredNoRefresh;
        defer self.gpa.free(refresh);
        const new_access = try self.refreshWith(refresh, account);
        defer self.gpa.free(new_access);
        return gpa.dupe(u8, new_access) catch return error.OutOfMemory;
    }

    /// POSTs the refresh_token grant and persists the new access/refresh
    /// pair. Returns an owned copy of the fresh access token; caller frees.
    fn refreshWith(self: *Session, refresh_token: []const u8, account: []const u8) Error![]u8 {
        log.debug("ocli: refreshing access token for {s}", .{account});
        const url = endpoints.tokenUrl(self.gpa, self.cfg.tenant) catch return error.OutOfMemory;
        defer self.gpa.free(url);

        const scopes_joined = joinScopes(self.gpa, self.cfg.scopes) catch return error.OutOfMemory;
        defer self.gpa.free(scopes_joined);

        const body = http_util.formEncodeAlloc(self.gpa, &.{
            .{ "client_id", self.cfg.client_id },
            .{ "grant_type", "refresh_token" },
            .{ "refresh_token", refresh_token },
            .{ "scope", scopes_joined },
        }) catch return error.OutOfMemory;
        defer self.gpa.free(body);

        var resp = try http.do(self.http_client, self.gpa, .{
            .method = .POST,
            .url = url,
            .body = body,
            .content_type = "application/x-www-form-urlencoded",
        });
        defer resp.deinit();

        if (resp.status != 200) {
            // invalid_grant -> nuke saved state so the next call surfaces a
            // clean "please run outlook login" instead of looping.
            _ = self.ks.delete(account, "refresh_token") catch {};
            _ = self.ks.delete(account, "token_meta") catch {};
            return error.TokenExpiredNoRefresh;
        }

        const Parsed = struct {
            access_token: []const u8,
            refresh_token: ?[]const u8 = null,
            expires_in: u32,
        };
        var p = std.json.parseFromSlice(Parsed, self.gpa, resp.body, .{ .ignore_unknown_fields = true }) catch return error.GraphMalformedJson;
        defer p.deinit();

        const expires_at = std.time.timestamp() + @as(i64, p.value.expires_in);

        if (p.value.refresh_token) |new_rt| {
            try self.ks.set(.{ .account = account, .label = "refresh_token", .secret = new_rt });
        }
        const meta_json = token_mod.serialiseMetaAlloc(self.gpa, .{
            .access_token = p.value.access_token,
            .expires_at_unix = expires_at,
        }) catch return error.OutOfMemory;
        defer self.gpa.free(meta_json);
        try self.ks.set(.{ .account = account, .label = "token_meta", .secret = meta_json });

        return self.gpa.dupe(u8, p.value.access_token) catch return error.OutOfMemory;
    }

    pub fn loginDeviceFlow(
        self: *Session,
        display: *const fn (verification_uri: []const u8, user_code: []const u8, message: ?[]const u8) void,
    ) !token_mod.Account {
        try config.ensureClientId(self.cfg);

        const dc_url = try endpoints.deviceCodeUrl(self.gpa, self.cfg.tenant);
        defer self.gpa.free(dc_url);
        const scopes_joined = try joinScopes(self.gpa, self.cfg.scopes);
        defer self.gpa.free(scopes_joined);

        const dc_body = try http_util.formEncodeAlloc(self.gpa, &.{
            .{ "client_id", self.cfg.client_id },
            .{ "scope", scopes_joined },
        });
        defer self.gpa.free(dc_body);

        var dc_resp = try http.do(self.http_client, self.gpa, .{
            .method = .POST,
            .url = dc_url,
            .body = dc_body,
            .content_type = "application/x-www-form-urlencoded",
        });
        defer dc_resp.deinit();
        if (dc_resp.status != 200) {
            reportAadError(self.gpa, dc_resp.status, dc_resp.body);
            return error.DeviceFlowPollFailed;
        }

        var start = try device_flow.startFromJson(self.gpa, dc_resp.body);
        defer start.deinit();
        display(start.verification_uri, start.user_code, start.message);

        const token_url_s = try endpoints.tokenUrl(self.gpa, self.cfg.tenant);
        defer self.gpa.free(token_url_s);

        const started_at = std.time.timestamp();
        var interval: u32 = start.interval;
        while (true) {
            const now = std.time.timestamp();
            if (now - started_at > @as(i64, start.expires_in)) return error.DeviceFlowExpired;
            std.Thread.sleep(@as(u64, interval) * std.time.ns_per_s);

            const poll_body = try http_util.formEncodeAlloc(self.gpa, &.{
                .{ "client_id", self.cfg.client_id },
                .{ "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                .{ "device_code", start.device_code },
            });
            defer self.gpa.free(poll_body);

            var poll_resp = try http.do(self.http_client, self.gpa, .{
                .method = .POST,
                .url = token_url_s,
                .body = poll_body,
                .content_type = "application/x-www-form-urlencoded",
            });
            defer poll_resp.deinit();

            var outcome = try device_flow.pollFromJson(self.gpa, poll_resp.status, poll_resp.body);
            switch (outcome) {
                .pending => continue,
                .slow_down => {
                    interval += 5;
                    continue;
                },
                .denied => return error.DeviceFlowDenied,
                .expired => return error.DeviceFlowExpired,
                .other => |code| {
                    defer self.gpa.free(code);
                    return error.DeviceFlowPollFailed;
                },
                .success => |*s| {
                    defer {
                        var mut = s.*;
                        mut.deinit();
                    }
                    // Look up the user identity via GET /me. Doing this with a
                    // real Graph call is more robust than parsing the access
                    // token as a JWT -- access tokens are opaque for MSA /
                    // personal accounts and the JWT shape varies between
                    // tenants.
                    const acct = try fetchMeAccount(self, s.access_token);
                    errdefer freeAccount(self.gpa, acct);

                    const expires_at = std.time.timestamp() + @as(i64, s.expires_in);

                    try self.ks.set(.{
                        .account = acct.upn,
                        .label = "refresh_token",
                        .secret = s.refresh_token,
                    });
                    const meta_json = try token_mod.serialiseMetaAlloc(self.gpa, .{
                        .access_token = s.access_token,
                        .expires_at_unix = expires_at,
                    });
                    defer self.gpa.free(meta_json);
                    try self.ks.set(.{
                        .account = acct.upn,
                        .label = "token_meta",
                        .secret = meta_json,
                    });

                    try self.setAccount(acct.upn);
                    return acct;
                },
            }
        }
    }

    pub fn logout(self: *Session, account: []const u8) !void {
        _ = self.ks.delete(account, "refresh_token") catch |err| switch (err) {
            error.KeystoreItemMissing => {},
            else => return err,
        };
        _ = self.ks.delete(account, "token_meta") catch |err| switch (err) {
            error.KeystoreItemMissing => {},
            else => return err,
        };
        if (self.account) |cur| {
            if (std.mem.eql(u8, cur, account)) {
                self.gpa.free(cur);
                self.account = null;
            }
        }
    }

    pub fn listAccounts(self: *Session, gpa: std.mem.Allocator) ![][]const u8 {
        return self.ks.list(gpa);
    }

    pub fn setCurrent(self: *Session, account: []const u8) !void {
        const rt = (try self.ks.get(self.gpa, account, "refresh_token")) orelse return error.AccountNotFound;
        self.gpa.free(rt);
        try self.setAccount(account);
    }
};

/// Fetch the signed-in user's profile via Graph /me using the freshly
/// issued access token directly (bypassing the BearerProvider, since the
/// session doesn't yet know which account is current).
fn fetchMeAccount(self: *Session, access_token: []const u8) !token_mod.Account {
    var bearer_buf: [4500]u8 = undefined;
    const bearer_val = std.fmt.bufPrint(&bearer_buf, "Bearer {s}", .{access_token}) catch return error.OutOfMemory;
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = bearer_val },
    };

    var resp = try http.do(self.http_client, self.gpa, .{
        .method = .GET,
        .url = "https://graph.microsoft.com/v1.0/me",
        .extra_headers = &headers,
    });
    defer resp.deinit();

    if (resp.status != 200) {
        @import("../util/io.zig").errPrint(
            "ocli: GET /me returned HTTP {d}: {s}\n",
            .{ resp.status, resp.body },
        );
        return error.GraphMalformedJson;
    }

    const Me = struct {
        userPrincipalName: ?[]const u8 = null,
        mail: ?[]const u8 = null,
        displayName: ?[]const u8 = null,
        id: ?[]const u8 = null,
    };
    var p = std.json.parseFromSlice(Me, self.gpa, resp.body, .{ .ignore_unknown_fields = true }) catch {
        @import("../util/io.zig").errPrint(
            "ocli: could not parse /me response: {s}\n",
            .{resp.body},
        );
        return error.GraphMalformedJson;
    };
    defer p.deinit();

    const upn = p.value.userPrincipalName orelse p.value.mail orelse p.value.id orelse "unknown";
    const display = p.value.displayName orelse upn;
    return .{
        .upn = try self.gpa.dupe(u8, upn),
        .display_name = try self.gpa.dupe(u8, display),
        .home_tenant_id = try self.gpa.dupe(u8, ""),
        .object_id = try self.gpa.dupe(u8, p.value.id orelse ""),
    };
}

/// Pull the AAD error code + description out of an Azure error response and
/// print them to stderr so the user sees the real cause (e.g.
/// `AADSTS700016: Application with identifier ... was not found`) instead of
/// a generic "sign-in poll failed" message.
fn reportAadError(gpa: std.mem.Allocator, status: u16, body: []const u8) void {
    const Aad = struct {
        @"error": []const u8 = "",
        error_description: []const u8 = "",
    };
    var p = std.json.parseFromSlice(Aad, gpa, body, .{ .ignore_unknown_fields = true }) catch {
        @import("../util/io.zig").errPrint("ocli: Microsoft returned HTTP {d}: {s}\n", .{ status, body });
        return;
    };
    defer p.deinit();
    if (p.value.@"error".len == 0 and p.value.error_description.len == 0) {
        @import("../util/io.zig").errPrint("ocli: Microsoft returned HTTP {d}\n", .{status});
        return;
    }
    @import("../util/io.zig").errPrint(
        "ocli: Microsoft rejected the sign-in request:\n  {s}\n  {s}\n",
        .{ p.value.@"error", p.value.error_description },
    );
}

pub fn freeAccount(gpa: std.mem.Allocator, a: token_mod.Account) void {
    gpa.free(a.upn);
    gpa.free(a.display_name);
    gpa.free(a.home_tenant_id);
    gpa.free(a.object_id);
}

fn joinScopes(gpa: std.mem.Allocator, scopes: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (scopes, 0..) |s, i| {
        total += s.len;
        if (i + 1 < scopes.len) total += 1;
    }
    const out = try gpa.alloc(u8, total);
    var off: usize = 0;
    for (scopes, 0..) |s, i| {
        @memcpy(out[off .. off + s.len], s);
        off += s.len;
        if (i + 1 < scopes.len) {
            out[off] = ' ';
            off += 1;
        }
    }
    return out;
}
