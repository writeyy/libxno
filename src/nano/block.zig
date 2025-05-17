const std = @import("std");
const signer = @import("signer.zig");

const PREAMBLE = "0000000000000000000000000000000000000000000000000000000000000006";

pub const NanoBlock = struct {
    @"type": []const u8 = "state",
    account: []const u8,
    previous: []const u8,
    representative: []const u8,
    balance: []const u8,
    link: []const u8,
    signature: ?[]const u8 = null,
    work: ?[]const u8 = null
};

pub fn receive(allocator: std.mem.Allocator, data: struct {
    tx_hash: []const u8,
    to_address: []const u8,
    balance_raw: u128,
    frontier: []const u8,
    representative: []const u8,
    amount_raw: u128,
    work: ?[]const u8 = null,
}, secret_key: [32]u8) []const u8 {
    const balance = try std.fmt.allocPrint(allocator, "{}", .{data.balance_raw + data.amount_raw});
    defer allocator.free(balance);

    var block = NanoBlock{
        .link = data.tx_hash,
        .account = data.to_address,
        .previous = data.frontier,
        .representative = data.representative,
        .balance = balance,
        .work = data.work
    };

    const payload: [][]const u8 = &.{
        PREAMBLE, 
        data.to_address, 
        data.frontier, 
        data.representative, 
    };

    std.debug.print("{any}\n", .{payload});

    //block.signature = try signer.sign(&.{
    //    PREAMBLE, data.
    //}, secret_key);

    return try std.json.stringifyAlloc(allocator, block, .{.emit_null_optional_fields = true });
}