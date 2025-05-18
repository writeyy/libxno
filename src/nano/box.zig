const std = @import("std");
const Ed25519 = @import("ed25519.zig");
const Blake = std.crypto.hash.blake2.Blake2b512; 
const assert = std.debug.assert;

const Self = @This();

pub fn deriveSecret(secret_key: [32]u8) ![32]u8 {
    var az: [Blake.digest_length]u8 = undefined;
    Blake.hash(&secret_key, &az, .{});
    var sk = az[0..32].*;
    std.crypto.ecc.Curve25519.scalar.clamp(&sk);
    return sk;
}

pub fn derivePublic(public_key: [32]u8) ![32]u8 {
    const pk_ed = try std.crypto.ecc.Edwards25519.fromBytes(public_key);
    const pk = try std.crypto.ecc.Curve25519.fromEdwards25519(pk_ed);
    return pk.toBytes();
}

pub fn encryptSize(len: usize) usize {
    return len + std.crypto.nacl.Box.nonce_length + std.crypto.nacl.Box.tag_length;
}

pub fn decryptSize(len: usize) usize {
    return len - std.crypto.nacl.Box.nonce_length - std.crypto.nacl.Box.tag_length;
}

pub fn encrypt(boxed: []u8, message: []const u8, recipient_public_key: [32]u8, sender_secret_key: [32]u8) !void {
    assert(boxed.len == encryptSize(message.len));

    std.crypto.random.bytes(boxed[0..std.crypto.nacl.Box.nonce_length]);
    try std.crypto.nacl.Box.seal(
        boxed[std.crypto.nacl.Box.nonce_length..], 
        message, 
        boxed[0..std.crypto.nacl.Box.nonce_length].*, 
        recipient_public_key, 
        sender_secret_key
    );
}

pub fn decrypt(message: []u8, encrypted: []u8, recipient_secret_key: [32]u8, sender_public_key: [32]u8) !void {
    assert(message.len == decryptSize(encrypted.len));

    try std.crypto.nacl.Box.open(
        message, 
        encrypted[24..], 
        encrypted[0..24].*, 
        sender_public_key, 
        recipient_secret_key
    );
}