const std = @import("std");
const Ed25519 = @import("ed25519.zig");
const Blake = std.crypto.hash.blake2.Blake2b256;

pub fn sign(messages: [][]const u8, secret_key: [32]u8) ![64]u8 {
    var bHash: [32]u8 = undefined;
    var b2b = Blake.init(.{});
    for (messages) |msg| {
        b2b.update(msg);
    }
    b2b.final(&bHash);
    return try Ed25519.sign(&bHash, try Ed25519.KeyPair.create(secret_key), null);
}

pub fn verify(public_key: [32]u8, signature: [64]u8, messages: [][]const u8) !bool {
    var bHash: [32]u8 = undefined;
    var b2b = Blake.init(.{});
    for (messages) |msg| {
        b2b.update(msg);
    }
    b2b.final(&bHash);
    Ed25519.verify(signature, &bHash, public_key) catch {
        return false;
    };
    return true;
}