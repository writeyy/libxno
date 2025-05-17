const std = @import("std");
const base32 = @import("nano/address.zig");

pub fn main() !void {
    const a = "1ad2fcf316bfafb734b446985e44ebdf882fc7042d828311ecc1dd92d2d4f0fb";
    var ab: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ab, a);

    var dest: [base32.NANO_ADDRESS_SIZE]u8 = undefined;
    base32.deriveAddress(&dest, ab);

    std.debug.print("{s}\n", .{dest});
}