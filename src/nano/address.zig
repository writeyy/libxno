const std = @import("std");
const Blake = std.crypto.hash.blake2.Blake2b(40);

const ALPHABET = "13456789abcdefghijkmnopqrstuwxyz";

const ADDRESS_ENCODE_SIZE = encodeSize(32);
const BLAKE2B_ENCODE_SIZE = encodeSize(Blake.digest_length);

pub const NANO_ADDRESS_SIZE = ADDRESS_ENCODE_SIZE + BLAKE2B_ENCODE_SIZE + 5;

pub fn deriveAddress(addr_dest: []u8, public_key: [32]u8) void {
    var checksum: [Blake.digest_length]u8 = undefined;
    var hasher = Blake.init(.{});
    hasher.update(&public_key);
    hasher.final(&checksum);
    std.mem.reverse(u8, &checksum);

    @memcpy(addr_dest[0..5], "nano_");

    encodeBase32(addr_dest[5..(ADDRESS_ENCODE_SIZE + 5)], @constCast(&public_key));
    encodeBase32(addr_dest[(ADDRESS_ENCODE_SIZE + 5)..], &checksum);
}

pub fn encodeSize(len: usize) usize {
    return ((len * 8) + 4) / 5;
}

pub fn encodeBase32(dest: []u8, input: []u8) void {
    var out_idx: usize = 0;
    var value: usize = 0;
    var bits: u8 = 0;

    const total_bits = input.len * 8;
    const leftover = total_bits % 5;
    const offset = if (leftover == 0) 0 else 5 - leftover;

    for (input) |byte| {
        value = (value << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            const shift_amt: u6 = @intCast(bits + offset - 5);
            const index: u5 = @intCast((value >> shift_amt) & 0b11111);
            dest[out_idx] = ALPHABET[index];
            out_idx += 1;
            bits -= 5;
        }
    }

    if (bits > 0) {
        const shift_amt: u6 = @intCast(5 - (bits + offset));
        const index: u5 = @intCast((value << shift_amt) & 0b11111);
        dest[out_idx] = ALPHABET[index];
    }
}
