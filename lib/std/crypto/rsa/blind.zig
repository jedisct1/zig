//! RSA blind signatures, as specified in RFC 9474, with the EMSA-PSS encoding fixed by erratum 9089 (emBits = modBits - 1).

const std = @import("std");
const crypto = std.crypto;
const core = @import("core.zig");
const padding = @import("padding.zig");
const Sha384 = crypto.hash.sha2.Sha384;

const KeyMismatchError = crypto.errors.KeyMismatchError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;
const WeakPublicKeyError = crypto.errors.WeakPublicKeyError;

/// The named variants of RFC 9474.
pub const BlindVariant = enum(u8) {
    /// RSABSSA-SHA384-PSS-Randomized, which the RFC recommends.
    sha384_pss_randomized,
    /// RSABSSA-SHA384-PSSZERO-Randomized.
    sha384_psszero_randomized,
    /// RSABSSA-SHA384-PSS-Deterministic.
    ///
    /// Without randomized message preparation, a malicious signer can choose its key to learn things about low-entropy messages (RFC 9474 section 7.3), and the random PSS salt doesn't help.
    /// Only use it if every message contains entropy the signer couldn't guess before choosing its key, or if the client knows that the key was honestly generated.
    sha384_pss_deterministic,
    /// RSABSSA-SHA384-PSSZERO-Deterministic.
    ///
    /// Without randomized message preparation, a malicious signer can choose its key to learn things about low-entropy messages (RFC 9474 section 7.3).
    /// Only use it if every message contains entropy the signer couldn't guess before choosing its key, or if the client knows that the key was honestly generated.
    sha384_psszero_deterministic,
    _,

    pub fn saltLength(comptime v: BlindVariant) u32 {
        return switch (v) {
            .sha384_pss_randomized, .sha384_pss_deterministic => Sha384.digest_length,
            .sha384_psszero_randomized, .sha384_psszero_deterministic => 0,
            _ => @compileError("unknown blind signature variant"),
        };
    }

    pub fn isRandomized(comptime v: BlindVariant) bool {
        return v == .sha384_pss_randomized or v == .sha384_psszero_randomized;
    }
};

/// RSA blind signatures (RFC 9474).
///
/// A key MUST NOT be used with another protocol or another variant.
///
/// In SubjectPublicKeyInfo and PKCS #8, keys are written with id-RSASSA-PSS and exactly the parameters of the variant, and nothing else is accepted.
/// PKCS #1 and components have no algorithm identifier, so they are accepted as they are, including by `fromPem()`.
/// The randomized and deterministic variants with the same salt length share these parameters, though, so keeping their keys apart is up to the protocol.
///
/// Key generation computes d modulo lcm(p - 1, q - 1), as FIPS 186-5 does.
pub fn BlindRsa(comptime bits: u16, comptime v: BlindVariant) type {
    const policy: core.Policy = .{
        .kind = .blind,
        .hash = .sha384,
        .salt_length = v.saltLength(),
        .label = std.fmt.comptimePrint("BlindRsa {d} {s}", .{ bits, @tagName(v) }),
    };
    const R = core.Rsa(bits);
    const C = BlindingProtocol(bits, v);

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

            /// Prepares and blinds a message, on the client.
            /// Returns `error.WeakPublicKey` if the key is broken.
            /// `io.random()` must be a cryptographically secure generator, as RFC 9474 requires.
            pub fn blind(pk: PublicKey, msg: []const u8, io: std.Io) WeakPublicKeyError!BlindingResult {
                var buf: [8]u8 = undefined;
                return C.blind(pk.key, core.exponentBytes(pk.key.e, &buf), Sha384.init(.{}), msg, io);
            }

            /// Unblinds a blind signature, on the client, and verifies the result.
            pub fn finalize(pk: PublicKey, blind_sig: BlindSignature, secret: BlindingSecret, msg: []const u8) Signature.VerifyError!Signature {
                var buf: [8]u8 = undefined;
                return .{ .bytes = try C.finalize(pk.key, core.exponentBytes(pk.key.e, &buf), Sha384.init(.{}), blind_sig, secret, msg), .msg_randomizer = secret.msg_randomizer };
            }
        };

        pub const SecretKey = struct {
            key: R.SecretKey,

            const F = core.SecretKeyFunctions(SecretKey, PublicKey, bits, policy);
            pub const Format = core.SecretKeyFormat;
            pub const Components = F.Components;
            pub const der_encoded_length_max = F.der_encoded_length_max;
            pub const pem_encoded_length_max = F.pem_encoded_length_max;
            pub const fromComponents = F.fromComponents;
            pub const toComponents = F.toComponents;
            pub const fromDer = F.fromDer;
            pub const toDer = F.toDer;
            pub const fromPem = F.fromPem;
            pub const toPem = F.toPem;
            pub const publicKey = F.publicKey;

            /// Signs a blinded message, on the server.
            /// Returns `error.NonCanonical` if the message isn't below n, and `error.KeyMismatch` if the fault check fails.
            ///
            /// With `side_channels_mitigations` set to `.none`, this function must not be exposed to anyone who can measure its timing.
            pub fn blindSign(sk: *const SecretKey, blind_message: BlindMessage, io: std.Io) (NonCanonicalError || KeyMismatchError)!BlindSignature {
                return .{ .bytes = try sk.key.rsadp(&blind_message.bytes, core.IoSource{ .io = io }) };
            }
        };

        pub const KeyPair = struct {
            public_key: PublicKey,
            secret_key: SecretKey,

            const F = core.KeyPairFunctions(KeyPair, bits, policy);
            pub const seed_length = F.seed_length;
            pub const generate = F.generate;
            pub const generateDeterministic = F.generateDeterministic;
            pub const fromSecretKey = F.fromSecretKey;
        };

        pub const Signature = struct {
            pub const VerifyError = NonCanonicalError || SignatureVerificationError;

            bytes: [modulus_length]u8,
            msg_randomizer: [randomizer_length]u8,

            pub fn fromBytes(bytes: [modulus_length]u8, msg_randomizer: [randomizer_length]u8) Signature {
                return .{ .bytes = bytes, .msg_randomizer = msg_randomizer };
            }

            /// Verifies the signature of an application message, without the randomizer.
            pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) VerifyError!void {
                var buf: [8]u8 = undefined;
                return C.verify(public_key.key, core.exponentBytes(public_key.key.e, &buf), Sha384.init(.{}), sig.bytes, &sig.msg_randomizer, msg);
            }
        };
    };
}

/// The message types and the client-side operations shared by the blind and partially blind schemes.
pub fn BlindingProtocol(comptime bits: u16, comptime v: BlindVariant) type {
    const R = core.Rsa(bits);
    const k = R.modulus_length;
    const salt_length = v.saltLength();

    return struct {
        pub const randomizer_length = if (v.isRandomized()) 32 else 0;

        pub const BlindMessage = struct {
            bytes: [k]u8,

            pub fn fromBytes(bytes: [k]u8) BlindMessage {
                return .{ .bytes = bytes };
            }

            pub fn toBytes(m: BlindMessage) [k]u8 {
                return m.bytes;
            }
        };

        pub const BlindSignature = struct {
            bytes: [k]u8,

            pub fn fromBytes(bytes: [k]u8) BlindSignature {
                return .{ .bytes = bytes };
            }

            pub fn toBytes(s: BlindSignature) [k]u8 {
                return s.bytes;
            }
        };

        /// Client-side secret: whoever learns it can link the final signature to the blinded message.
        pub const BlindingSecret = struct {
            inv: [k]u8,
            msg_randomizer: [randomizer_length]u8,

            pub const encoded_length = k + randomizer_length;

            /// Decodes the inverse followed by the randomizer.
            pub fn fromBytes(bytes: [encoded_length]u8) BlindingSecret {
                return .{ .inv = bytes[0..k].*, .msg_randomizer = bytes[k..].* };
            }

            /// Encodes the inverse followed by the randomizer.
            pub fn toBytes(s: BlindingSecret) [encoded_length]u8 {
                return s.inv ++ s.msg_randomizer;
            }
        };

        pub const BlindingResult = struct {
            blind_message: BlindMessage,
            secret: BlindingSecret,
        };

        fn messageHash(h_init: Sha384, msg_randomizer: []const u8, msg: []const u8) [Sha384.digest_length]u8 {
            var h = h_init;
            h.update(msg_randomizer);
            h.update(msg);
            return h.finalResult();
        }

        /// Prepare and Blind, with a hash state that may already hold a prefix.
        pub fn blind(pk: R.PublicKey, e: []const u8, h_init: Sha384, msg: []const u8, io: std.Io) WeakPublicKeyError!BlindingResult {
            const n = pk.n;
            var rnd: [randomizer_length + salt_length]u8 = undefined;
            defer crypto.secureZero(u8, &rnd);
            io.random(&rnd);
            var result: BlindingResult = undefined;
            result.secret.msg_randomizer = rnd[0..randomizer_length].*;
            var em = padding.pssEncode(Sha384, k, &messageHash(h_init, rnd[0..randomizer_length], msg), rnd[randomizer_length..]);
            defer crypto.secureZero(u8, &em);
            var m = pk.element(&em) catch unreachable;
            defer core.wipe(&m);

            // Inverting m * r both checks that m is invertible and gives r^-1, as m * (m * r)^-1.
            // The signer picks the modulus, so m may share a factor with it.
            // invertBlinded() would leak which one when it fails, so this uses the slower constant-time inversion.
            const source: core.IoSource = .{ .io = io };
            for (0..core.max_attempts) |_| {
                var r = core.uniform(n, source) orelse return error.WeakPublicKey;
                defer core.wipe(&r);
                if (n.invert(n.mul(m, r))) |mr_inv| {
                    var inv = n.mul(m, mr_inv);
                    defer core.wipe(&inv);
                    inv.toBytes(&result.secret.inv, .big) catch unreachable;
                    n.mul(m, (n.powWithEncodedPublicExponent(r, e, .big) catch unreachable)).toBytes(&result.blind_message.bytes, .big) catch unreachable;
                    return result;
                }
                // If m has no inverse, the key is broken. Otherwise, r wasn't invertible, so try again.
                if (n.invert(m) == null) return error.WeakPublicKey;
            }
            return error.WeakPublicKey;
        }

        /// Finalize, with a hash state that may already hold a prefix.
        /// Returns the signature, which goes with the randomizer of the secret.
        pub fn finalize(
            pk: R.PublicKey,
            e: []const u8,
            h_init: Sha384,
            blind_sig: BlindSignature,
            secret: BlindingSecret,
            msg: []const u8,
        ) (NonCanonicalError || SignatureVerificationError)![k]u8 {
            const z = try pk.element(&blind_sig.bytes);
            var inv = try pk.element(&secret.inv);
            defer core.wipe(&inv);
            var sig: [k]u8 = undefined;
            pk.n.mul(z, inv).toBytes(&sig, .big) catch unreachable;
            try verify(pk, e, h_init, sig, &secret.msg_randomizer, msg);
            return sig;
        }

        /// RSASSA-PSS-VERIFY of the prepared message, with a hash state that may already hold a prefix.
        pub fn verify(
            pk: R.PublicKey,
            e: []const u8,
            h_init: Sha384,
            sig: [k]u8,
            msg_randomizer: []const u8,
            msg: []const u8,
        ) (NonCanonicalError || SignatureVerificationError)!void {
            const s = try pk.element(&sig);
            var em: [k]u8 = undefined;
            (pk.n.powWithEncodedPublicExponent(s, e, .big) catch unreachable).toBytes(&em, .big) catch unreachable;
            if (!padding.pssVerify(Sha384, k, salt_length, &messageHash(h_init, msg_randomizer, msg), em)) return error.SignatureVerificationFailed;
        }
    };
}
