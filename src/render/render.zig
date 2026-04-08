//! Facade in front of human/json writers. The CLI command layer calls into
//! this file and passes an output mode; the right backend is chosen.

const std = @import("std");
pub const color = @import("color.zig");
pub const human = @import("human.zig");
pub const json = @import("json.zig");

const types = @import("../graph/types.zig");
const errors = @import("../errors.zig");

pub const Mode = enum { human, json };

pub const Output = struct {
    mode: Mode,
    profile: color.Profile,

    pub fn writeMessageList(
        self: Output,
        gpa: std.mem.Allocator,
        list: []const types.MessageSummary,
    ) !void {
        switch (self.mode) {
            .json => try json.writeMessageList(list, gpa),
            .human => try human.writeMessageList(list, self.profile),
        }
    }

    pub fn writeMessage(self: Output, gpa: std.mem.Allocator, m: types.Message) !void {
        switch (self.mode) {
            .json => try json.writeMessage(m, gpa),
            .human => try human.writeMessage(m, self.profile),
        }
    }

    pub fn writeFolderList(self: Output, gpa: std.mem.Allocator, list: []const types.Folder) !void {
        switch (self.mode) {
            .json => try json.writeFolderList(list, gpa),
            .human => try human.writeFolderList(list, self.profile),
        }
    }

    pub fn writeAccounts(
        self: Output,
        gpa: std.mem.Allocator,
        list: []const []const u8,
        current: ?[]const u8,
    ) !void {
        switch (self.mode) {
            .json => try json.writeAccounts(list, current, gpa),
            .human => try human.writeAccounts(list, current),
        }
    }

    pub fn writeError(self: Output, gpa: std.mem.Allocator, diag: errors.Diagnostic) !void {
        switch (self.mode) {
            .json => try json.writeError(diag, gpa),
            .human => try human.writeError(diag, self.profile),
        }
    }

    pub fn writeOkMessage(self: Output, gpa: std.mem.Allocator, msg: []const u8) !void {
        switch (self.mode) {
            .json => try json.writeOk(msg, gpa),
            .human => @import("../util/io.zig").outPrint("{s}\n", .{msg}),
        }
    }
};
