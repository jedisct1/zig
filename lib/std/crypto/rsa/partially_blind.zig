//! RSA partially blind signatures, as specified in draft-irtf-cfrg-partially-blind-rsa-02.

const std = @import("std");
const crypto = std.crypto;
const core = @import("core.zig");
const blind = @import("blind.zig");
const Sha384 = crypto.hash.sha2.Sha384;
const HkdfSha384 = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.sha2.HmacSha384);

const ContextTooLongError = crypto.errors.ContextTooLongError;
const KeyMismatchError = crypto.errors.KeyMismatchError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;
const WeakParametersError = crypto.errors.WeakParametersError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

/// RSA partially blind signatures (draft-irtf-cfrg-partially-blind-rsa-02).
///
/// The modulus must have 2048, 4096, 8192 or 16384 bits, because the draft needs its byte length to be a power of 2.
///
/// Keys use safe primes, so generating them is slow, and d is computed modulo (p - 1) * (q - 1), as in the draft.
/// On an Apple M5 Max in ReleaseFast, a 2048-bit key took 7 seconds on average (3 to 20 seconds), and a 4096-bit key took one to five minutes.
///
/// Secret keys can't be imported yet, because nothing could check that their primes are safe.
/// To restore a key, call `KeyPair.generateDeterministic()` again with its seed.
///
/// Signatures are verified with a public key derived from the metadata, whose exponent is as large as a prime factor.
/// That makes verification about twice as slow as signing, so attacker-chosen metadata can be used for denial of service.
/// Blind signing pays for the same exponentiation in its fault check, which makes it about three times slower than with `BlindRsa`.
///
/// Signatures can only be unlinked among signatures that share the same metadata, so applications must restrict the set of possible values.
///
/// A key MUST NOT be used with another protocol or another variant.
pub fn PartiallyBlindRsa(comptime bits: u16, comptime v: blind.BlindVariant) type {
    switch (bits) {
        2048, 4096, 8192, 16384 => {},
        else => @compileError("the modulus of partially blind signatures must have 2048, 4096, 8192 or 16384 bits"),
    }
    const policy: core.Policy = .{
        .kind = .partially_blind,
        .hash = .sha384,
        .salt_length = v.saltLength(),
        .label = std.fmt.comptimePrint("PartiallyBlindRsa {d} {s}", .{ bits, @tagName(v) }),
    };
    const R = core.Rsa(bits);
    const C = blind.BlindingProtocol(bits, v);
    const lambda_length = R.modulus_length / 2;

    return struct {
        pub const modulus_bits = bits;
        pub const modulus_length = R.modulus_length;
        pub const prime_length = R.prime_length;
        pub const PublicKeyError = core.PublicKeyError;
        pub const SecretKeyError = core.SecretKeyError;
        pub const Hash = Sha384;
        pub const variant = v;
        pub const randomizer_length = C.randomizer_length;
        pub const BlindMessage = C.BlindMessage;
        pub const BlindSignature = C.BlindSignature;
        pub const BlindingSecret = C.BlindingSecret;
        pub const BlindingResult = C.BlindingResult;

        pub const PublicKey = struct {
            key: R.PublicKey,

            const F = core.PublicKeyFunctions(PublicKey, bits, policy);
            pub const Format = core.PublicKeyFormat;
            pub const Components = F.Components;
            pub const der_encoded_length_max = F.der_encoded_length_max;
            pub const pem_encoded_length_max = F.pem_encoded_length_max;
            pub const fromComponents = F.fromComponents;
            pub const toComponents = F.toComponents;
            pub const fromDer = F.fromDer;
            pub const toDer = F.toDer;
            pub const fromPem = F.fromPem;
            pub const toPem = F.toPem;

            /// Derives the public key for some metadata, which can't be longer than 2^32 - 1 bytes.
            pub fn derivePublicKey(pk: PublicKey, info: []const u8) ContextTooLongError!DerivedPublicKey {
                if (info.len > std.math.maxInt(u32)) return error.ContextTooLong;

                var n: [modulus_length]u8 = undefined;
                pk.key.n.toBytes(&n, .big) catch unreachable;
                var hkdf = HkdfSha384.extractInit(&n);
                hkdf.update("key");
                hkdf.update(info);
                hkdf.update(&.{0});
                var prk: [HkdfSha384.prk_length]u8 = undefined;
                hkdf.final(&prk);
                var expanded: [lambda_length + 16]u8 = undefined;
                HkdfSha384.expand(&expanded, "PBRSA", prk);
                expanded[0] &= 0x3f;
                expanded[lambda_length - 1] |= 1;

                var h = Sha384.init(.{});
                h.update("msg");
                h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(info.len))));
                h.update(info);
                return .{ .key = pk.key, .e_prime = expanded[0..lambda_length].*, .h = h };
            }
        };

        pub const DerivedPublicKey = struct {
            key: R.PublicKey,
            e_prime: [lambda_length]u8,
            /// The hash state after the metadata prefix.
            h: Sha384,

            /// Prepares and blinds a message, on the client.
            /// Returns `error.WeakPublicKey` if the key is broken.
            /// `io.random()` must be a cryptographically secure generator.
            pub fn blind(dpk: DerivedPublicKey, msg: []const u8, io: std.Io) WeakPublicKeyError!BlindingResult {
                return C.blind(dpk.key, &dpk.e_prime, dpk.h, msg, io);
            }

            /// Unblinds a blind signature, on the client, and verifies the result.
            pub fn finalize(dpk: DerivedPublicKey, blind_sig: BlindSignature, secret: BlindingSecret, msg: []const u8) Signature.VerifyError!Signature {
                return .{ .bytes = try C.finalize(dpk.key, &dpk.e_prime, dpk.h, blind_sig, secret, msg), .msg_randomizer = secret.msg_randomizer };
            }
        };

        pub const SecretKey = struct {
            key: R.SecretKey,

            const F = core.SecretKeyFunctions(SecretKey, PublicKey, bits, policy);
            pub const Format = core.SecretKeyFormat;
            pub const Components = F.Components;
            pub const der_encoded_length_max = F.der_encoded_length_max;
            pub const pem_encoded_length_max = F.pem_encoded_length_max;
            pub const toComponents = F.toComponents;
            pub const toDer = F.toDer;
            pub const toPem = F.toPem;
            pub const publicKey = F.publicKey;
        };

        pub const KeyPair = struct {
            public_key: PublicKey,
            secret_key: SecretKey,

            const F = core.KeyPairFunctions(KeyPair, bits, policy);
            pub const seed_length = F.seed_length;
            pub const generate = F.generate;
            pub const generateDeterministic = F.generateDeterministic;
            pub const fromSecretKey = F.fromSecretKey;

            // Returns e'^-1 mod (p - 1).
            // With p = 2p' + 1, that's whichever of x and x + p' is odd, where x = e'^-1 mod p'.
            fn deriveExponent(p: R.P, e_prime: R.HalfUint) WeakParametersError!R.HalfUint {
                var pp = p.toUint();
                pp.shiftRightPublic(1);
                defer core.wipe(&pp);
                var m = R.P.fromUintSecret(pp, R.half_bits - 1) catch unreachable;
                defer core.wipe(&m);
                var x = (m.invert(m.reduce(e_prime)) orelse return error.WeakParameters).v.cast(R.HalfUint) catch unreachable;
                defer core.wipe(&x);
                var y = x;
                _ = y.addWithOverflow(pp);
                y.cmov(x.isOdd(), x);
                return y;
            }

            /// Derives the key pair for some metadata, which can't be longer than 2^32 - 1 bytes.
            /// This is slow, so servers should cache the derived key pairs.
            /// Returns `error.WeakParameters` if the derived exponent has no inverse, which is impossible with safe primes.
            pub fn deriveKeyPair(kp: *const KeyPair, info: []const u8) (ContextTooLongError || WeakParametersError || KeyMismatchError)!DerivedKeyPair {
                try F.check(kp);
                const dpk = try kp.public_key.derivePublicKey(info);
                const e_prime = R.HalfUint.fromBytes(&dpk.e_prime, .big) catch unreachable;
                const sk = &kp.secret_key.key;
                return .{
                    .public_key = dpk,
                    .secret_key = sk.*,
                    .dp = try deriveExponent(sk.p, e_prime),
                    .dq = try deriveExponent(sk.q, e_prime),
                };
            }
        };

        pub const DerivedKeyPair = struct {
            public_key: DerivedPublicKey,
            secret_key: R.SecretKey,
            dp: R.HalfUint,
            dq: R.HalfUint,

            /// Signs a blinded message, on the server.
            /// Returns `error.NonCanonical` if the message isn't below n, and `error.KeyMismatch` if the fault check fails.
            ///
            /// With `side_channels_mitigations` set to `.none`, this function must not be exposed to anyone who can measure its timing.
            pub fn blindSign(dkp: *const DerivedKeyPair, blind_message: BlindMessage, io: std.Io) (NonCanonicalError || KeyMismatchError)!BlindSignature {
                return .{ .bytes = try dkp.secret_key.rsadpWith(dkp.dp, dkp.dq, &dkp.public_key.e_prime, &blind_message.bytes, core.IoSource{ .io = io }) };
            }
        };

        pub const Signature = struct {
            pub const VerifyError = NonCanonicalError || SignatureVerificationError;

            bytes: [modulus_length]u8,
            msg_randomizer: [randomizer_length]u8,

            pub fn fromBytes(bytes: [modulus_length]u8, msg_randomizer: [randomizer_length]u8) Signature {
                return .{ .bytes = bytes, .msg_randomizer = msg_randomizer };
            }

            /// Verifies the signature of an application message, with the key derived for its metadata.
            pub fn verify(sig: Signature, msg: []const u8, public_key: DerivedPublicKey) VerifyError!void {
                return C.verify(public_key.key, &public_key.e_prime, public_key.h, sig.bytes, &sig.msg_randomizer, msg);
            }
        };
    };
}

test "draft-irtf-cfrg-partially-blind-rsa-02 vectors" {
    const t = @import("tests.zig");
    const testing = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    const PB = PartiallyBlindRsa(2048, .sha384_pss_deterministic);
    const Vector = struct {
        n: []const u8,
        e: []const u8,
        d: []const u8,
        p: []const u8,
        q: []const u8,
        dp: []const u8,
        dq: []const u8,
        qinv: []const u8,
        msg: []const u8,
        info: []const u8,
        eprime: []const u8,
        dprime_p: []const u8,
        dprime_q: []const u8,
        inv: []const u8,
        blind_msg: []const u8,
        blind_sig: []const u8,
        sig: []const u8,
    };
    for (try t.parse(Vector, arena, "pbrsa.json")) |v| {
        var c = try t.secretComponents(PB.SecretKey.Components, v);
        const kp = PB.KeyPair.fromSecretKey(try PB.SecretKey.F.fromComponents(&c));
        const info = try t.hex(arena, v.info);
        const msg = try t.hex(arena, v.msg);
        const dkp = try kp.deriveKeyPair(info);
        try testing.expectEqualSlices(u8, &try t.hexArray(PB.modulus_length / 2, v.eprime), &dkp.public_key.e_prime);
        try testing.expect(dkp.dp.eql(try .fromBytes(&try t.hexArray(PB.prime_length, v.dprime_p), .big)));
        try testing.expect(dkp.dq.eql(try .fromBytes(&try t.hexArray(PB.prime_length, v.dprime_q), .big)));

        const blind_sig = try dkp.blindSign(.fromBytes(try t.hexArray(PB.modulus_length, v.blind_msg)), io);
        try testing.expectEqualSlices(u8, &try t.hexArray(PB.modulus_length, v.blind_sig), &blind_sig.bytes);
        const dpk = dkp.public_key;
        const sig = try dpk.finalize(blind_sig, .fromBytes(try t.hexArray(PB.modulus_length, v.inv)), msg);
        try testing.expectEqualSlices(u8, &try t.hexArray(PB.modulus_length, v.sig), &sig.bytes);
        try sig.verify(msg, dpk);
        try testing.expectError(error.SignatureVerificationFailed, sig.verify(msg, try kp.public_key.derivePublicKey("other")));

        const blinding = try dpk.blind(msg, io);
        const sig2 = try dpk.finalize(try dkp.blindSign(blinding.blind_message, io), blinding.secret, msg);
        try sig2.verify(msg, dpk);
    }
}
