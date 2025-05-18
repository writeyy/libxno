const std = @import("std");
const box = @import("nano/address.zig");

pub fn main() !void {
    const pk = "d20dea091337ef5aa61a173979e2bce60d2aa7c6ac89ee076d5175325f83ec7b";
    const a = "4587d7a5198d71757517bc32765b382ddc73f24053bbceff18990f827b34ed5a";
    var ab: [32]u8 = undefined;
    var pkx: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pkx, pk);
    _ = try std.fmt.hexToBytes(&ab, a);
    
    var ad: [box.NANO_ADDRESS_SIZE]u8 = undefined;
    box.deriveAddress(&ad, ab);

    box.addressToPublicKey(&pkx, &ad);
    std.debug.print("{s}\n", .{std.fmt.bytesToHex(pkx, .lower)});

    std.debug.print("{s}\n", .{ad});

    _ = box.addressToHex(&ad);

}