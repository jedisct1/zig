//! RSA signatures: RSASSA-PSS and RSASSA-PKCS1-v1_5 (RFC 8017), blind signatures (RFC 9474), and partially blind signatures (draft-irtf-cfrg-partially-blind-rsa-02).
//!
//! Each scheme type works with a single modulus size, a multiple of 8 between 2048 and 16384 bits.
//! To accept keys of several sizes, read the size with `modulusBitsFromDer()` or `modulusBitsFromPem()` first, and pick the type from it.
//!
//! Each scheme also has its own key types, so a key can't be used with another scheme by accident.
//! To move a key to another scheme on purpose, export it and import it into the other type.
//!
//! Every operation that uses a secret key takes an `io`, whose `random()` must be a cryptographically secure generator.
//!
//! Protection against side channels depends on `std.options.side_channels_mitigations`.
//! From `.basic` up, private-key operations run in constant time.
//! Key generation tries a number of candidates that depends on the seed, and importing or exporting a key in DER or PEM reveals the length of each integer.
//! `.medium`, the default, adds exponent blinding, and `.full` also blinds the base and the modulus.
//! `.none` doesn't protect against timing attacks at all, so only use it where nobody can measure timing.
//!
//! Every private-key result is checked with the public key before it is returned, because a single faulty signature is enough to recover the key.
//! If that check fails, the operation returns `error.KeyMismatch`.
//!
//! Keys can be printed with `{any}` like any struct, so be careful not to log them.
//!
//! Secrets in stack buffers are wiped, but the temporaries of `std.crypto.ff`, such as exponentiation tables, aren't.
//! Keys have no destructor: wipe them with `std.crypto.secureZero()` when you're done.

const std = @import("std");
const crypto = std.crypto;
const timing_safe = crypto.timing_safe;
const core = @import("core.zig");
const padding = @import("padding.zig");

const KeyMismatchError = crypto.errors.KeyMismatchError;
const NonCanonicalError = crypto.errors.NonCanonicalError;
const SignatureVerificationError = crypto.errors.SignatureVerificationError;

pub const PublicKeyFormat = core.PublicKeyFormat;
pub const SecretKeyFormat = core.SecretKeyFormat;
pub const PublicKeyError = core.PublicKeyError;
pub const SecretKeyError = core.SecretKeyError;
pub const modulusBitsFromDer = core.modulusBitsFromDer;
pub const modulusBitsFromPem = core.modulusBitsFromPem;

pub const BlindVariant = @import("blind.zig").BlindVariant;
pub const BlindRsa = @import("blind.zig").BlindRsa;
pub const PartiallyBlindRsa = @import("partially_blind.zig").PartiallyBlindRsa;

/// RSASSA-PSS, with MGF1 using the same hash, and a salt as long as the digest.
///
/// Keys imported with id-RSASSA-PSS keep their parameters in SubjectPublicKeyInfo and PKCS #8, and other keys are written as rsaEncryption.
/// PKCS #1 and components have no algorithm identifier, so exporting a key that way drops the restriction.
///
/// Key generation computes d modulo lcm(p - 1, q - 1), as FIPS 186-5 does.
pub fn RsaPss(comptime bits: u16, comptime H: type) type {
    return Rsassa(bits, H, true);
}

/// RSASSA-PKCS1-v1_5.
///
/// Key generation computes d modulo lcm(p - 1, q - 1), as FIPS 186-5 does.
pub fn RsaPkcs1v15(comptime bits: u16, comptime H: type) type {
    return Rsassa(bits, H, false);
}

fn Rsassa(comptime bits: u16, comptime H: type, comptime pss: bool) type {
    const policy: core.Policy = .{
        .kind = if (pss) .pss else .pkcs1v15,
        .hash = core.hashId(H),
        .salt_length = H.digest_length,
        .label = std.fmt.comptimePrint("{s} {d} {s}", .{ if (pss) "RsaPss" else "RsaPkcs1v15", bits, core.hashName(H) }),
    };
    const R = core.Rsa(bits);

    return struct {
        pub const modulus_bits = bits;
        pub const modulus_length = R.modulus_length;
        pub const prime_length = R.prime_length;
        pub const PublicKeyError = core.PublicKeyError;
        pub const SecretKeyError = core.SecretKeyError;
        pub const Hash = H;

        pub const PublicKey = struct {
            key: R.PublicKey,

            const F = core.PublicKeyFunctions(PublicKey, bits, policy);
            pub const Format = PublicKeyFormat;
            pub const Components = F.Components;
            pub const der_encoded_length_max = F.der_encoded_length_max;
            pub const pem_encoded_length_max = F.pem_encoded_length_max;
            pub const fromComponents = F.fromComponents;
            pub const toComponents = F.toComponents;
            pub const fromDer = F.fromDer;
            pub const toDer = F.toDer;
            pub const fromPem = F.fromPem;
            pub const toPem = F.toPem;
        };

        pub const SecretKey = struct {
            key: R.SecretKey,

            const F = core.SecretKeyFunctions(SecretKey, PublicKey, bits, policy);
            pub const Format = SecretKeyFormat;
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
        };

        pub const KeyPair = struct {
            public_key: PublicKey,
            secret_key: SecretKey,

            const F = core.KeyPairFunctions(KeyPair, bits, policy);
            pub const seed_length = F.seed_length;
            pub const generate = F.generate;
            pub const generateDeterministic = F.generateDeterministic;
            pub const fromSecretKey = F.fromSecretKey;

            /// Signs a message.
            /// Returns `error.KeyMismatch` if the public key doesn't match the secret key, or if the fault check fails.
            pub fn sign(kp: *const KeyPair, msg: []const u8, io: std.Io) KeyMismatchError!Signature {
                var s = try kp.signer(io);
                s.update(msg);
                return s.finalize();
            }

            /// Signs the hash of a message.
            pub fn signPrehashed(kp: *const KeyPair, msg_hash: [H.digest_length]u8, io: std.Io) KeyMismatchError!Signature {
                try F.check(kp);
                var em = if (pss) em: {
                    var salt: [H.digest_length]u8 = undefined;
                    io.random(&salt);
                    break :em padding.pssEncode(H, modulus_length, &msg_hash, &salt);
                } else padding.pkcs1v15Encode(H, modulus_length, &msg_hash);
                defer core.wipe(&em);
                const bytes = kp.secret_key.key.rsadp(&em, core.IoSource{ .io = io }) catch |err| switch (err) {
                    error.NonCanonical => unreachable, // EM is always below n.
                    error.KeyMismatch => |e| return e,
                };
                return .{ .bytes = bytes };
            }

            /// Returns a signer for a message given in pieces.
            /// The key pair must outlive the signer, and stay unchanged while it is in use.
            pub fn signer(kp: *const KeyPair, io: std.Io) KeyMismatchError!Signer {
                try F.check(kp);
                return .{ .h = H.init(.{}), .key_pair = kp, .io = io };
            }
        };

        pub const Signature = struct {
            pub const encoded_length = modulus_length;
            pub const VerifyError = Verifier.InitError || Verifier.VerifyError;

            bytes: [encoded_length]u8,

            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return .{ .bytes = bytes };
            }

            pub fn toBytes(sig: Signature) [encoded_length]u8 {
                return sig.bytes;
            }

            /// Returns a verifier for a message given in pieces.
            /// Returns `error.NonCanonical` if the signature isn't below the modulus.
            pub fn verifier(sig: Signature, public_key: PublicKey) Verifier.InitError!Verifier {
                const s = try public_key.key.element(&sig.bytes);
                var v: Verifier = .{ .h = H.init(.{}), .em = undefined };
                public_key.key.rsaep(s).toBytes(&v.em, .big) catch unreachable;
                return v;
            }

            /// Verifies the signature of a message.
            pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) VerifyError!void {
                var v = try sig.verifier(public_key);
                v.update(msg);
                return v.verify();
            }

            /// Verifies the signature of the hash of a message.
            pub fn verifyPrehashed(sig: Signature, msg_hash: [H.digest_length]u8, public_key: PublicKey) VerifyError!void {
                return (try sig.verifier(public_key)).verifyHash(&msg_hash);
            }
        };

        pub const Signer = struct {
            h: H,
            key_pair: *const KeyPair,
            io: std.Io,

            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            /// Returns the signature, or `error.KeyMismatch` if the fault check fails.
            pub fn finalize(self: *Signer) KeyMismatchError!Signature {
                return self.key_pair.signPrehashed(self.h.finalResult(), self.io);
            }
        };

        pub const Verifier = struct {
            pub const InitError = NonCanonicalError;
            pub const VerifyError = SignatureVerificationError;

            h: H,
            em: [modulus_length]u8,

            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Verifier) VerifyError!void {
                return self.verifyHash(&self.h.finalResult());
            }

            fn verifyHash(self: Verifier, msg_hash: *const [H.digest_length]u8) VerifyError!void {
                const ok = if (pss)
                    padding.pssVerify(H, modulus_length, H.digest_length, msg_hash, self.em)
                else
                    timing_safe.eql([modulus_length]u8, padding.pkcs1v15Encode(H, modulus_length, msg_hash), self.em);
                if (!ok) return error.SignatureVerificationFailed;
            }
        };
    };
}

test {
    _ = @import("tests.zig");
}
