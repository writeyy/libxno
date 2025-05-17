// Modified version of std provided ED25519 implementation
// to replace the hash function with blake2.

const std = @import("std");
const Blake = std.crypto.hash.blake2.Blake2b512;

const Self = @This();

pub const Curve = std.crypto.ecc.Edwards25519;
pub const seed_length = 32;
pub const secret_length = 64;
pub const public_length = 32;
pub const signature_length = 64;
pub const noise_length = 32;

pub const KeyPair = struct {
    public_key: [public_length]u8,
    secret_key: [secret_length]u8,

    pub fn create(seed: ?[seed_length]u8) !KeyPair {
        const ss = seed orelse ss: {
            var random_seed: [seed_length]u8 = undefined;
            std.crypto.random.bytes(&random_seed);
            break :ss random_seed;
        };
        var az: [Blake.digest_length]u8 = undefined;
        var h = Blake.init(.{});
        h.update(&ss);
        h.final(&az);
        const p = try Curve.basePoint.clampedMul(az[0..32].*);
        var sk: [secret_length]u8 = undefined;
        std.mem.copyForwards(u8, &sk, &ss);
        const pk = p.toBytes();
        std.mem.copyForwards(u8, sk[seed_length..], &pk);

        return KeyPair{ .public_key = pk, .secret_key = sk };
    }
};

pub fn sign(msg: []const u8, key_pair: KeyPair, noise: ?[noise_length]u8) [signature_length]u8 {
    const seed = key_pair.secret_key[0..seed_length];
    const public_key = key_pair.secret_key[seed_length..];
    if (!std.mem.eql(u8, public_key, &key_pair.public_key)) {
        return error.KeyMismatch;
    }
    var az: [Blake.digest_length]u8 = undefined;
    var h = Blake.init(.{});
    h.update(seed);
    h.final(&az);

    h = Blake.init(.{});
    if (noise) |*z| {
        h.update(z);
    }
    h.update(az[32..]);
    h.update(msg);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    const nonce = Curve.scalar.reduce64(nonce64);
    const r = try Curve.basePoint.mul(nonce);

    var sig: [signature_length]u8 = undefined;
    std.mem.copyForwards(u8, sig[0..32], &r.toBytes());
    std.mem.copyForwards(u8, sig[32..], public_key);
    h = Blake.init(.{});
    h.update(&sig);
    h.update(msg);
    var hram64: [Blake.digest_length]u8 = undefined;
    h.final(&hram64);
    const hram = Curve.scalar.reduce64(hram64);

    const x = az[0..32];
    Curve.scalar.clamp(x);
    const s = Curve.scalar.mulAdd(hram, x.*, nonce);
    std.mem.copyForwards(u8, sig[32..], s[0..]);
    return sig;
}

pub fn verify(sig: [signature_length]u8, msg: []const u8, public_key: [public_length]u8) !void {
    const r = sig[0..32].*;
    const s = sig[32..64].*;
    try Curve.scalar.rejectNonCanonical(s);
    const a = try Curve.fromBytes(public_key);
    try a.rejectIdentity();
    try Curve.rejectNonCanonical(r);
    const expected_r = try Curve.fromBytes(r);
    try expected_r.rejectIdentity();

    var h = Blake.init(.{});
    h.update(&r);
    h.update(&public_key);
    h.update(msg);
    var hram64: [Blake.digest_length]u8 = undefined;
    h.final(&hram64);
    const hram = Curve.scalar.reduce64(hram64);

    const sb_ah = try Curve.basePoint.mulDoubleBasePublic(s, a.neg(), hram);
    if (expected_r.sub(sb_ah).rejectLowOrder()) {
        return error.SignatureVerificationFailed;
    } else |_| {}
}