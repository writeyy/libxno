const std = @import("std");
const Blake = std.crypto.hash.blake2.Blake2b(40);
const assert = std.debug.assert;

const ALPHABET = "13456789abcdefghijkmnopqrstuwxyz";

const ADDRESS_ENCODE_SIZE = encodeSize(32);
const BLAKE2B_ENCODE_SIZE = encodeSize(Blake.digest_length);

pub const NANO_ADDRESS_SIZE = ADDRESS_ENCODE_SIZE + BLAKE2B_ENCODE_SIZE + 5;

pub fn deriveAddress(addr_dest: []u8, public_key: [32]u8) void {
    assert(addr_dest.len == NANO_ADDRESS_SIZE);

    var checksum: [Blake.digest_length]u8 = undefined;
    var hasher = Blake.init(.{});
    hasher.update(&public_key);
    hasher.final(&checksum);
    std.mem.reverse(u8, &checksum);

    @memcpy(addr_dest[0..5], "nano_");

    encodeBase32(addr_dest[5..(ADDRESS_ENCODE_SIZE + 5)], @constCast(&public_key));
    encodeBase32(addr_dest[(ADDRESS_ENCODE_SIZE + 5)..], &checksum);
}

pub fn addressToPublicKey(pkey_dest: []u8, address: []const u8) void {
    assert(address.len == NANO_ADDRESS_SIZE);
    assert(pkey_dest.len == 32);

    std.debug.print("{}\n", .{decodeSize(NANO_ADDRESS_SIZE)});

    var temp: [decodeSize(NANO_ADDRESS_SIZE) - decodeSize(4)]u8 = undefined;
    decodeBase32(&temp, address[5..]);
    std.debug.print("{s}\n", .{std.fmt.bytesToHex(temp, .lower)});
    @memcpy(pkey_dest, temp[0..32]);
}

pub fn addressToHex(address: []const u8) []const u8 {
    assert(address.len == NANO_ADDRESS_SIZE);

    const addr = address[5..];

    var keyB: [decodeSize(52)]u8 = undefined;
    var hashB: [decodeSize(8)]u8 = undefined;

    std.debug.print("{} {} {} {}\n", .{keyB.len, hashB.len, addr[0..52].len, addr[52..].len});

    decodeBase32(&keyB, addr[0..52]);
    decodeBase32(&hashB, addr[52..60]);

    var hash: [Blake.digest_length]u8 = undefined;
    Blake.hash(&hashB, &hash, .{});
    std.mem.reverse(u8, &hash);
    
    std.debug.print("{any} {any}\n", .{hashB, hash});

    return "ok";
}

const BASE32_LOOKUP = blk: {
    var table = [_]u8{255} ** 128;
    for (ALPHABET, 0..) |ch, i| {
        table[ch] = @intCast(i);
    }
    break :blk table;
};

pub fn decodeBase32(dest: []u8, input: []const u8) void {
    std.debug.print("{}\n", .{decodeSize(input.len)});
    assert(dest.len == decodeSize(input.len));

    const length = input.len;
    const leftover = (length * 5) % 8;
    const offset: u6 = if (leftover == 0) 0 else 8 - @as(u6, @intCast(leftover));
    
    var value: u64 = 0;
    var bits: u6 = 0;
    var out_idx: usize = 0;

    for (input) |ch| {
        assert(ch < BASE32_LOOKUP.len);
        assert(BASE32_LOOKUP[ch] != 255);

        const idx = BASE32_LOOKUP[ch];
        value = (value << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            dest[out_idx] = @intCast((value >> @intCast(bits + offset - 8)) & 0xFF);
            out_idx += 1;
            bits -= 8;
        }
    }

    if (bits > 0) {
        dest[out_idx] = @intCast((value << @intCast(bits + offset - 8)) & 0xFF);
        out_idx += 1;
    }

    if (leftover != 0) {
        std.mem.copyForwards(u8, dest[0..out_idx-1], dest[1..out_idx]);
    }
}

pub fn decodeSize(len: usize) usize {
    return ((len * 5) / 8);
}

pub fn encodeSize(len: usize) usize {
    return ((len * 8) + 4) / 5;
}

pub fn encodeBase32(dest: []u8, input: []u8) void {
    assert(dest.len == encodeSize(input.len));

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