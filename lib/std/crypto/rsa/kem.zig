//! RSA key encapsulation: RSA-KEM (RFC 9690), and RSA-OAEP carrying a random 32-byte secret, as used by the composite ML-KEM KEMs of draft-ietf-lamps-pq-composite-kem.
//!
//! Each scheme type works with a single modulus size, a multiple of 8 between 2048 and 16384 bits.
//! RFC 9690 says that a KEM key SHOULD NOT be used for signatures.
//!
//! `decaps()` takes an `io` for blinding.
//! With `std.options.side_channels_mitigations` set to `.none`, it runs in variable time, and anyone who can time it can recover the secrets (the Marvin and Manger attacks).
//! Don't use `.none` on a service that decapsulates ciphertexts from anyone.
//!
//! Secrets in stack buffers are wiped, but the temporaries of `std.crypto.ff` aren't.
//! Keys have no destructor: wipe them with `std.crypto.secureZero()` when you're done.

const std = @import("std");
const crypto = std.crypto;
const core = @import("core.zig");
const padding = @import("padding.zig");

const AuthenticationError = crypto.errors.AuthenticationError;
const KeyMismatchError = crypto.errors.KeyMismatchError;
const NonCanonicalError = crypto.errors.NonCanonicalError;

pub const PublicKeyFormat = core.PublicKeyFormat;
pub const SecretKeyFormat = core.SecretKeyFormat;
pub const PublicKeyError = core.PublicKeyError;
pub const SecretKeyError = core.SecretKeyError;
pub const modulusBitsFromDer = core.modulusBitsFromDer;
pub const modulusBitsFromPem = core.modulusBitsFromPem;

/// RSA-KEM (RFC 9690), with KDF3 and SHA-256, the only hash allowed for now.
///
/// The shared secret is SHA-256(0x00000001 || Z), where Z is the k-byte encoding of the random z.
/// Its first `ssLen` bytes are the shared secret of RFC 9690, for any `ssLen` up to 32.
/// Every ciphertext below n is accepted, including 0, 1 and n - 1.
///
/// Public keys are written as KEM-only keys, with id-rsa-kem-spki, and rsaEncryption is accepted too when reading them.
/// Secret keys use rsaEncryption in PKCS #8.
pub fn RsaKem(comptime bits: u16, comptime H: type) type {
    if (H != crypto.hash.sha2.Sha256) @compileError("RsaKem only supports SHA-256");
    return Kem(bits, H, false);
}

/// RSAES-OAEP encrypting a random 32-byte secret, with MGF1 using the same hash, and an empty label.
///
/// With SHA-256, this is the RSA part of the composite ML-KEM KEMs of draft-ietf-lamps-pq-composite-kem.
/// Ciphertexts that don't decrypt to a valid 32-byte secret are rejected with `error.AuthenticationFailed`, in constant time.
/// Getting no error says nothing about who sent the ciphertext.
pub fn RsaOaepKem(comptime bits: u16, comptime H: type) type {
    return Kem(bits, H, true);
}

fn Kem(comptime bits: u16, comptime H: type, comptime oaep: bool) type {
    const policy: core.Policy = .{
        .kind = if (oaep) .oaep_kem else .rsa_kem,
        .label = std.fmt.comptimePrint("{s} {d} {s}", .{ if (oaep) "RsaOaepKem" else "RsaKem", bits, core.hashName(H) }),
    };
    const R = core.Rsa(bits);

    return struct {
        pub const modulus_bits = bits;
        pub const modulus_length = R.modulus_length;
        pub const prime_length = R.prime_length;
        pub const PublicKeyError = core.PublicKeyError;
        pub const SecretKeyError = core.SecretKeyError;
        pub const Hash = H;

        pub const shared_length = 32;
        pub const ciphertext_length = modulus_length;
        /// How many random bytes `encapsDeterministic()` takes: z for RSA-KEM, or the secret followed by the OAEP seed for RSA-OAEP.
        pub const encaps_seed_length: usize = if (oaep) shared_length + H.digest_length else modulus_length;

        pub const DecapsError = NonCanonicalError || KeyMismatchError || (if (oaep) AuthenticationError else error{});
        pub const EncapsDeterministicError = if (oaep) error{} else NonCanonicalError;

        pub const EncapsulatedSecret = struct {
            shared_secret: [shared_length]u8,
            ciphertext: [ciphertext_length]u8,
        };

        fn kdf(z: *const [modulus_length]u8) [shared_length]u8 {
            var h = H.init(.{});
            h.update(&.{ 0, 0, 0, 1 });
            h.update(z);
            defer core.wipe(&h);
            return h.finalResult();
        }

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

            /// Generates a shared secret and its encapsulation.
            /// `io.random()` must be a cryptographically secure generator.
            pub fn encaps(pk: PublicKey, io: std.Io) EncapsulatedSecret {
                var seed: [encaps_seed_length]u8 = undefined;
                defer crypto.secureZero(u8, &seed);
                // For RSA-KEM, z must be below n, which happens more than half of the time.
                while (true) {
                    io.random(&seed);
                    return pk.encapsDeterministic(&seed) catch continue;
                }
            }

            /// Encapsulates with the given randomness, which must be secret, fresh and uniformly random outside of tests.
            /// For RSA-KEM, that's z, and `error.NonCanonical` is returned if it isn't below n.
            pub fn encapsDeterministic(pk: PublicKey, seed: *const [encaps_seed_length]u8) EncapsDeterministicError!EncapsulatedSecret {
                var es: EncapsulatedSecret = undefined;
                var m = if (oaep) m: {
                    var em = padding.oaepEncode(H, modulus_length, seed[0..shared_length], seed[shared_length..]);
                    defer crypto.secureZero(u8, &em);
                    break :m pk.key.element(&em) catch unreachable;
                } else try pk.key.element(seed);
                defer core.wipe(&m);
                es.shared_secret = if (oaep) seed[0..shared_length].* else kdf(seed);
                pk.key.rsaep(m).toBytes(&es.ciphertext, .big) catch unreachable;
                return es;
            }
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

            /// Returns the shared secret of a ciphertext.
            ///
            /// Errors come in this order: `error.NonCanonical` if the ciphertext isn't below n, `error.KeyMismatch` if the fault check fails, and, for RSA-OAEP, `error.AuthenticationFailed`.
            ///
            /// `error.KeyMismatch` means the key or the hardware is broken, and is meant for logs and alerts.
            /// Peers must not be able to tell it apart from a rejected ciphertext, neither from the response nor from its timing.
            ///
            /// With `side_channels_mitigations` set to `.none`, don't expose this function to anyone who can measure its timing.
            pub fn decaps(sk: *const SecretKey, ct: *const [ciphertext_length]u8, io: std.Io) DecapsError![shared_length]u8 {
                var m = try sk.key.rsadp(ct, core.IoSource{ .io = io });
                defer crypto.secureZero(u8, &m);
                if (!oaep) return kdf(&m);
                var secret: [shared_length]u8 = undefined;
                if (!padding.oaepDecode(H, modulus_length, &m, &secret)) {
                    crypto.secureZero(u8, &secret);
                    return error.AuthenticationFailed;
                }
                return secret;
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
    };
}
