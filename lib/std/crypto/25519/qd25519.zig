// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2020 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.

const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const Sha512 = std.crypto.hash.sha2.Sha512;

/// QDSA signatures over Curve25519.
pub const Qd25519 = struct {
    /// The underlying elliptic curve.
    pub const Curve = @import("curve25519.zig").Curve25519;
    /// Length (in bytes) of a seed required to create a key pair.
    pub const seed_length = 32;
    /// Length (in bytes) of a compressed key pair.
    pub const keypair_length = 64;
    /// Length (in bytes) of a compressed public key.
    pub const public_length = 32;
    /// Length (in bytes) of a compressed private key.
    pub const private_length = 32;
    /// Length (in bytes) of a signature.
    pub const signature_length = 64;
    /// Length (in bytes) of optional random bytes, for non-deterministic signatures.
    pub const noise_length = 32;

    /// Derive a key pair from a secret seed.
    pub fn createKeyPair(seed: [seed_length]u8) ![keypair_length]u8 {
        var az: [Sha512.digest_length]u8 = undefined;
        var h = Sha512.init(.{});
        h.update(&seed);
        h.final(&az);
        const p = try Curve.basePoint.clampedMul(az[0..32].*);
        var keypair: [keypair_length]u8 = undefined;
        mem.copy(u8, &keypair, &seed);
        mem.copy(u8, keypair[seed_length..], &p.toBytes());
        return keypair;
    }

    /// Return the public key for a given key pair.
    pub fn publicKey(key_pair: [keypair_length]u8) [public_length]u8 {
        var public_key: [public_length]u8 = undefined;
        mem.copy(u8, public_key[0..], key_pair[private_length..]);
        return public_key;
    }

    /// Return the private key for a given key pair.
    pub fn privateKey(key_pair: [keypair_length]u8) [private_length]u8 {
        var private_key: [private_length]u8 = undefined;
        mem.copy(u8, private_key[0..], key_pair[0..private_length]);
        return private_key;
    }

    /// Sign a message using a key pair, and optional random noise.
    /// Having noise creates non-standard, non-deterministic signatures,
    /// but has been proven to increase resilience against fault attacks.
    pub fn sign(msg: []const u8, key_pair: [keypair_length]u8, noise: ?[noise_length]u8) ![signature_length]u8 {
        const public_key = key_pair[32..];
        var az: [Sha512.digest_length]u8 = undefined;
        var h = Sha512.init(.{});
        h.update(key_pair[0..seed_length]);
        h.final(&az);

        h = Sha512.init(.{});
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
        mem.copy(u8, sig[0..32], &r.toBytes());
        mem.copy(u8, sig[32..], public_key);
        h = Sha512.init(.{});
        h.update(&sig);
        h.update(msg);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);
        const hram = Curve.scalar.reduce64(hram64);

        var x = az[0..32];
        Curve.scalar.clamp(x);
        //const s = Curve.scalar.mulAdd(hram, x.*, nonce);
        const s = Curve.scalar.mul(hram, x.*);
        mem.copy(u8, sig[32..], s[0..]);
        return sig;
    }

    fn bValues(xp: Curve.Quotient, xq: Curve.Quotient) struct { bZZ: Curve.Fe, bXZ: Curve.Fe, bXX: Curve.Fe } {
        var b0 = xp.xz.mul(xq.xz);
        var b1 = xp.z.mul(xq.z);
        const bZZ = b0.sub(b1).sq();
        b0 = b0.add(b1);

        b1 = xp.xz.mul(xq.z);
        var b2 = xq.xz.mul(xp.z);
        const bXX = b1.sub(b2).sq();

        var bXZ = b1.add(b2).mul(b0);
        b0 = b1.mul(b2);
        b0 = b0.add(b0);
        b0 = b0.add(b0);
        b1 = b0.add(b0).mul32(121666);
        b0 = b1.sub(b0);
        bXZ = bXZ.add(b0);
        bXZ = bXZ.add(bXZ);
        return .{ .bZZ = bZZ, .bXZ = bXZ, .bXX = bXX };
    }

    /// Verify an Qd25519 signature given a message and a public key.
    /// Returns error.InvalidSignature is the signature verification failed.
    pub fn verify(sig: [signature_length]u8, msg: []const u8, public_key: [public_length]u8) !void {
        const r = sig[0..32];
        const s = sig[32..64];
        try Curve.scalar.rejectNonCanonical(s.*);
        try Curve.rejectNonCanonical(public_key);
        const a = try Curve.fromBytes(public_key);
        try a.rejectIdentity();

        var h = Sha512.init(.{});
        h.update(r);
        h.update(&public_key);
        h.update(msg);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);
        const hram = Curve.scalar.reduce64(hram64);

        const ladder = a.mulQ(hram);
        const q = ladder.sp;
        const p = ladder.spp;
        const sp = try Curve.basePoint.mul(s.*);
        const bv = bValues(p, q);
        const rx = Curve.Fe.fromBytes(r.*);
        var b0 = rx.sq().mul(bv.bXX);
        const b1 = rx.mul(bv.bXZ);
        b0 = b0.sub(b1).add(bv.bZZ);
        if (!b0.isZero()) {
            return error.InvalidSignature;
        }
    }
};

test "qd25519 signature" {
    var seed: [32]u8 = undefined;
    try fmt.hexToBytes(seed[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const key_pair = try Qd25519.createKeyPair(seed);

    const sig = try Qd25519.sign("test", key_pair, null);
    var buf: [128]u8 = undefined;
    const public_key = Qd25519.publicKey(key_pair);
    try Qd25519.verify(sig, "test", public_key);
    std.testing.expectError(error.InvalidSignature, Qd25519.verify(sig, "TEST", public_key));
}
