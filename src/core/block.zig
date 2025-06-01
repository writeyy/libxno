const std = @import("std");
const signer = @import("signer.zig");
const address = @import("address.zig");

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
    recipient: []const u8,
    balance_raw: u128,
    frontier: []const u8,
    representative: []const u8,
    amount_raw: u128,
    work: ?[]const u8 = null,
}, secret_key: [32]u8) ![]const u8 {
    const balance = try std.fmt.allocPrint(allocator, "{}", .{data.balance_raw + data.amount_raw});
    defer allocator.free(balance);

    var block = NanoBlock{
        .link = data.tx_hash,
        .account = data.recipient,
        .previous = data.frontier,
        .representative = data.representative,
        .balance = balance,
        .work = data.work
    };

    const account = address.addressToHex(data.recipient);

    const decimal_hex = try allocator.alloc(u8, 32);
    defer allocator.free(decimal_hex);

    _ = std.fmt.formatIntBuf(decimal_hex, data.amount_raw, 16, .lower, .{});

    var list = std.ArrayList([]const u8).init(allocator);

    try list.append(PREAMBLE);
    try list.append(account);
    try list.append(data.frontier);
    try list.append(data.representative);
    try list.append(decimal_hex);
    try list.append(data.tx_hash);

    std.debug.print("{any}\n", .{list.items});
    const payload = try list.toOwnedSlice();
    defer allocator.free(payload);

    block.signature = try signer.sign(payload, secret_key);

    return try std.json.stringifyAlloc(allocator, block, .{.emit_null_optional_fields = true });
}