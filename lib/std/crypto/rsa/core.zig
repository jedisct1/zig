//! Key material, key validation, and the RSA primitives shared by every scheme.

const std = @import("std");
const crypto = std.crypto;
const ff = crypto.ff;
const mem = std.mem;
const assert = std.debug.assert;
const errors = crypto.errors;
const timing_safe = crypto.timing_safe;
const der = @import("der.zig");
const pem = @import("pem.zig");
const keygen = @import("keygen.zig");

const EncodingError = errors.EncodingError;
const KeyMismatchError = errors.KeyMismatchError;
const NonCanonicalError = errors.NonCanonicalError;
const WeakParametersError = errors.WeakParametersError;
const WeakPublicKeyError = errors.WeakPublicKeyError;

pub const PublicKeyError = EncodingError || WeakPublicKeyError;
pub const SecretKeyError = EncodingError || WeakPublicKeyError || KeyMismatchError;

pub const PublicKeyFormat = der.PublicKeyFormat;
pub const SecretKeyFormat = der.SecretKeyFormat;

const level = std.options.side_channels_mitigations;

// Size of the exponent and modulus blinding factors: at least 64 bits and two machine words.
const blinding_bits = @max(64, 2 * @bitSizeOf(usize));
const blinding_length = blinding_bits / 8;

/// How many random draws in a row can be unusable before an operation gives up.
pub const max_attempts = 16;

pub fn wipe(x: anytype) void {
    crypto.secureZero(u8, mem.asBytes(x));
}

/// Encodes a public exponent as big-endian bytes, without leading zeros.
pub fn exponentBytes(e: u64, buf: *[8]u8) []const u8 {
    mem.writeInt(u64, buf, e, .big);
    return buf[@clz(e) / 8 ..];
}

/// Returns the identifier of an allowed hash function, and rejects the others at compile time.
pub fn hashId(comptime H: type) der.HashId {
    return switch (H) {
        crypto.hash.sha2.Sha256 => .sha256,
        crypto.hash.sha2.Sha384 => .sha384,
        crypto.hash.sha2.Sha512 => .sha512,
        else => @compileError("the hash function must be SHA-256, SHA-384 or SHA-512"),
    };
}

pub fn hashName(comptime H: type) []const u8 {
    return switch (hashId(H)) {
        .sha256 => "SHA-256",
        .sha384 => "SHA-384",
        .sha512 => "SHA-512",
    };
}

/// Returns the modulus size in bits of a DER-encoded public key, without validating anything else.
/// Sizes above 16384 bits are rejected with `error.InvalidEncoding`.
pub fn modulusBitsFromDer(bytes: []const u8, comptime format: PublicKeyFormat) EncodingError!u16 {
    return der.modulusBits(bytes, switch (format) {
        .pkcs1 => .pkcs1_public,
        .spki => .spki,
        _ => @compileError("unsupported public key format"),
    });
}

/// Returns the modulus size in bits of the first key in a PEM file, public or secret, without validating anything else.
/// Sizes above 16384 bits and encrypted keys are rejected with `error.InvalidEncoding`.
pub fn modulusBitsFromPem(text: []const u8) EncodingError!u16 {
    const block = try pem.find(text, &.{ .public_key, .rsa_public_key, .private_key, .rsa_private_key, .encrypted_private_key });
    var buf: [256]u8 = undefined;
    defer crypto.secureZero(u8, &buf);
    const bytes = try pem.decodePrefix(block.body, &buf);
    return der.modulusBits(bytes, switch (block.label) {
        .public_key => .spki,
        .rsa_public_key => .pkcs1_public,
        .private_key => .pkcs8,
        .rsa_private_key => .pkcs1_private,
        .encrypted_private_key => return error.InvalidEncoding,
    });
}

/// A source of randomness for the private-key operation.
pub const IoSource = struct {
    io: std.Io,

    pub fn squeeze(s: IoSource, buf: []u8) void {
        s.io.random(buf);
    }
};

/// Picks a uniformly random element of [0, n).
/// Returns null if `max_attempts` draws in a row were rejected, which essentially never happens.
pub fn uniform(n: anytype, source: anytype) ?@TypeOf(n).Fe {
    var buf: [@TypeOf(n).uniform_bytes_length]u8 = undefined;
    defer crypto.secureZero(u8, &buf);
    for (0..max_attempts) |_| {
        source.squeeze(&buf);
        if (n.uniform(&buf)) |x| return x;
    }
    return null;
}

/// What a scheme accepts and writes as the algorithm identifier of its keys, and how it generates them.
pub const Policy = struct {
    kind: enum { pss, pkcs1v15, blind, partially_blind, rsa_kem, oaep_kem },
    /// The hash of PSS and of the blind schemes.
    hash: der.HashId = .sha256,
    /// The salt length of PSS and of the blind schemes.
    salt_length: u32 = 0,
    /// Binds deterministic key generation to the scheme.
    label: []const u8,

    /// The algorithm of keys that come from components, PKCS #1 or key generation.
    pub fn defaultAlgorithm(comptime policy: Policy) der.Algorithm {
        return switch (policy.kind) {
            .blind, .partially_blind => .{ .rsassa_pss = .{ .hash = policy.hash, .salt_length = policy.salt_length } },
            else => .rsa_encryption,
        };
    }

    fn accept(comptime policy: Policy, alg: der.Algorithm, comptime spki: bool) EncodingError!der.Algorithm {
        const ok = switch (policy.kind) {
            .pss => switch (alg) {
                .rsa_encryption => true,
                .rsa_kem => false,
                .rsassa_pss => |params| if (params) |p| p.hash == policy.hash and p.salt_length <= policy.salt_length else true,
            },
            .blind, .partially_blind => switch (alg) {
                .rsassa_pss => |params| if (params) |p| p.hash == policy.hash and p.salt_length == policy.salt_length else false,
                else => false,
            },
            .rsa_kem => alg == .rsa_encryption or (spki and alg == .rsa_kem),
            .pkcs1v15, .oaep_kem => alg == .rsa_encryption,
        };
        return if (ok) alg else error.InvalidEncoding;
    }

    // The algorithm identifier to write when exporting a key.
    fn exportAlgorithm(comptime policy: Policy, stored: der.Algorithm, comptime spki: bool) der.Algorithm {
        if (policy.kind == .rsa_kem) return if (spki) .rsa_kem else .rsa_encryption;
        return stored;
    }
};

/// Key material and primitives for a modulus of exactly `bits` bits.
pub fn Rsa(comptime bits: u16) type {
    comptime assert(bits % 8 == 0 and bits >= 2048 and bits <= 16384);

    return struct {
        pub const modulus_length = bits / 8;
        pub const half_bits = bits / 2;
        pub const prime_length = (half_bits + 7) / 8;

        pub const N = ff.Modulus(bits);
        pub const P = ff.Modulus(half_bits);
        pub const NUint = ff.Uint(bits);
        pub const HalfUint = ff.Uint(half_bits);
        const WideUint = ff.Uint(half_bits + blinding_bits);
        const BlindedP = ff.Modulus(half_bits + blinding_bits);
        // The CRT moduli, with or without modulus blinding.
        const CrtP = if (level == .full) BlindedP else P;

        const exponent_blinding = level == .medium or level == .full;
        // Exponents are encoded at a fixed width that only depends on the modulus size.
        const exponent_length = if (exponent_blinding) @divCeil(half_bits + blinding_bits, 8) else prime_length;

        pub const PublicComponents = struct {
            n: [modulus_length]u8,
            e: u64,
        };

        pub const SecretComponents = struct {
            n: [modulus_length]u8,
            e: u64,
            d: [modulus_length]u8,
            p: [prime_length]u8,
            q: [prime_length]u8,
            dp: [prime_length]u8,
            dq: [prime_length]u8,
            qinv: [prime_length]u8,
        };

        pub const PublicKey = struct {
            n: N,
            e: u64,
            alg: der.Algorithm,

            pub fn fromComponents(c: PublicComponents, alg: der.Algorithm) PublicKeyError!PublicKey {
                if (c.n[0] & 0x80 == 0) return error.InvalidEncoding;
                if (c.e & 1 == 0 or c.e < 3 or c.e >> 33 != 0) return error.WeakPublicKey;
                const n = N.fromBytes(&c.n, .big) catch return error.WeakPublicKey;
                return .{ .n = n, .e = c.e, .alg = alg };
            }

            pub fn toComponents(pk: PublicKey) PublicComponents {
                var c: PublicComponents = .{ .n = undefined, .e = pk.e };
                pk.n.toBytes(&c.n, .big) catch unreachable;
                return c;
            }

            /// Returns x^e mod n.
            pub fn rsaep(pk: PublicKey, x: N.Fe) N.Fe {
                var buf: [8]u8 = undefined;
                return pk.n.powWithEncodedPublicExponent(x, exponentBytes(pk.e, &buf), .big) catch unreachable;
            }

            /// Decodes a value that must be below n, such as a signature or a ciphertext.
            pub fn element(pk: PublicKey, bytes: *const [modulus_length]u8) NonCanonicalError!N.Fe {
                return N.Fe.fromBytes(pk.n, bytes, .big) catch error.NonCanonical;
            }
        };

        pub const SecretKey = struct {
            public_key: PublicKey,
            d: NUint,
            p: P,
            q: P,
            dp: HalfUint,
            dq: HalfUint,
            qinv: P.Fe,

            // Checks that d and the CRT exponent of a prime p are inverses of e modulo p - 1.
            fn checkExponents(p_u: HalfUint, dp: HalfUint, d: NUint, e: u64) bool {
                var pm1 = p_u;
                _ = pm1.subWithOverflow(HalfUint.fromPrimitive(u8, 1) catch unreachable);
                defer wipe(&pm1);
                var m = P.fromUintSecret(pm1, half_bits) catch unreachable;
                defer wipe(&m);
                const e_fe = m.reduce(HalfUint.fromPrimitive(u64, e) catch unreachable);
                // Once dp * e = 1, d * e = 1 is the same as d = dp, modulo p - 1.
                return dp.lessThan(pm1) & m.isOne(m.mul(m.reduce(dp), e_fe)) & m.reduce(d).v.eql(dp);
            }

            /// Imports a secret key after checking that its components are consistent, like BoringSSL's RSA_check_key() does.
            /// Both primes must be exactly half the size of the modulus.
            /// The checks run in constant time, but p and q aren't tested for primality.
            pub fn fromComponents(c: *const SecretComponents, alg: der.Algorithm) SecretKeyError!SecretKey {
                const public_key = try PublicKey.fromComponents(.{ .n = c.n, .e = c.e }, alg);

                // Check that the primes are odd and have exactly half_bits bits before doing any math with them.
                const top_shift = (half_bits - 1) % 8;
                const sizes_ok = timing_safe.eql(u8, c.p[0] >> top_shift, 1) & timing_safe.eql(u8, c.q[0] >> top_shift, 1) &
                    !timing_safe.isZero(u8, c.p[prime_length - 1] & c.q[prime_length - 1] & 1);
                if (!timing_safe.valueBarrier(sizes_ok)) return error.KeyMismatch;

                var p_u = HalfUint.fromBytes(&c.p, .big) catch unreachable;
                defer wipe(&p_u);
                var q_u = HalfUint.fromBytes(&c.q, .big) catch unreachable;
                defer wipe(&q_u);
                var d = NUint.fromBytes(&c.d, .big) catch unreachable;
                defer wipe(&d);
                var dp = HalfUint.fromBytes(&c.dp, .big) catch return error.KeyMismatch;
                defer wipe(&dp);
                var dq = HalfUint.fromBytes(&c.dq, .big) catch return error.KeyMismatch;
                defer wipe(&dq);
                var qinv_u = HalfUint.fromBytes(&c.qinv, .big) catch return error.KeyMismatch;
                defer wipe(&qinv_u);

                var n = NUint.zero;
                const overflow = n.mulAddWithOverflow(p_u.cast(NUint) catch unreachable, q_u.cast(NUint) catch unreachable);
                var ok = timing_safe.isZero(u1, overflow) & n.eql(public_key.n.v) & d.lessThan(public_key.n.v);
                ok &= checkExponents(p_u, dp, d, c.e) & checkExponents(q_u, dq, d, c.e);

                var p = P.fromUintSecret(p_u, half_bits) catch unreachable;
                defer wipe(&p);
                var qinv = p.reduce(qinv_u);
                defer wipe(&qinv);
                ok &= qinv_u.lessThan(p_u) & p.isOne(p.mul(qinv, p.reduce(q_u)));
                if (!timing_safe.valueBarrier(ok)) return error.KeyMismatch;

                return .{
                    .public_key = public_key,
                    .d = d,
                    .p = p,
                    .q = P.fromUintSecret(q_u, half_bits) catch unreachable,
                    .dp = dp,
                    .dq = dq,
                    .qinv = qinv,
                };
            }

            pub fn toComponents(sk: *const SecretKey) SecretComponents {
                var c: SecretComponents = undefined;
                c.e = sk.public_key.e;
                sk.public_key.n.toBytes(&c.n, .big) catch unreachable;
                inline for (.{ "d", "p", "q", "dp", "dq", "qinv" }) |f| @field(sk, f).toBytes(&@field(c, f), .big) catch unreachable;
                return c;
            }

            // The random values of one private-key operation, drawn with a single call.
            const Blinding = extern struct {
                // The base blinding factor r and the unit s that blinds its inversion.
                base: [if (level == .full) 2 * N.uniform_bytes_length else 0]u8,
                exponent: [2][blinding_length]u8,
                modulus: [2][blinding_length]u8,
            };

            // Computes x^dp mod p, or with blinding, x^(dp + b * (p - 1)) mod (g * p), reduced modulo p.
            fn crtHalf(p: P, dp: HalfUint, x: N.Fe, b: *const [blinding_length]u8, g: *const [blinding_length]u8) KeyMismatchError!P.Fe {
                var m: CrtP = if (level == .full) m: {
                    var g_bytes = g.*;
                    defer wipe(&g_bytes);
                    g_bytes[0] |= 0x80;
                    g_bytes[blinding_length - 1] |= 1;
                    var gp = WideUint.zero;
                    _ = gp.mulAddWithOverflow(WideUint.fromBytes(&g_bytes, .big) catch unreachable, p.toUint().cast(WideUint) catch unreachable);
                    defer wipe(&gp);
                    break :m BlindedP.fromUintSecret(gp, half_bits + blinding_bits) catch unreachable;
                } else p;
                defer wipe(&m);

                var e_bytes: [exponent_length]u8 = undefined;
                defer wipe(&e_bytes);
                if (exponent_blinding) {
                    var pm1 = p.toUint();
                    _ = pm1.subWithOverflow(HalfUint.fromPrimitive(u8, 1) catch unreachable);
                    var e = dp.cast(WideUint) catch unreachable;
                    _ = e.mulAddWithOverflow(WideUint.fromBytes(b, .big) catch unreachable, pm1.cast(WideUint) catch unreachable);
                    e.toBytes(&e_bytes, .big) catch unreachable;
                    wipe(&e);
                    wipe(&pm1);
                } else {
                    dp.toBytes(&e_bytes, .big) catch unreachable;
                }
                // Only a fault can zero the exponent.
                var y = m.powWithEncodedExponent(m.reduce(x.v), &e_bytes, .big) catch return error.KeyMismatch;
                defer wipe(&y);
                return if (level == .full) p.reduce(y.v) else y;
            }

            /// The RSA private-key operation, c^d mod n with the CRT, followed by the fault check.
            /// `source` has a `squeeze()` function that fills a buffer with random bytes, such as `IoSource`.
            pub fn rsadp(sk: *const SecretKey, c: *const [modulus_length]u8, source: anytype) (NonCanonicalError || KeyMismatchError)![modulus_length]u8 {
                var buf: [8]u8 = undefined;
                return sk.rsadpWith(sk.dp, sk.dq, exponentBytes(sk.public_key.e, &buf), c, source);
            }

            /// Same as `rsadp()`, with other CRT exponents and their public exponent `e`, as big-endian bytes.
            pub fn rsadpWith(
                sk: *const SecretKey,
                dp: HalfUint,
                dq: HalfUint,
                e: []const u8,
                c_bytes: *const [modulus_length]u8,
                source: anytype,
            ) (NonCanonicalError || KeyMismatchError)![modulus_length]u8 {
                const n = sk.public_key.n;
                const c = try sk.public_key.element(c_bytes);

                var rnd: Blinding = undefined;
                defer wipe(&rnd);
                var x = c;
                defer wipe(&x);
                var r_inv = n.one();
                defer wipe(&r_inv);
                for (0..max_attempts) |_| {
                    if (exponent_blinding) source.squeeze(if (level == .full) mem.asBytes(&rnd) else mem.asBytes(&rnd.exponent));
                    if (level != .full) break;
                    const r = n.uniform(rnd.base[0..N.uniform_bytes_length]) orelse continue;
                    const s = n.uniform(rnd.base[N.uniform_bytes_length..]) orelse continue;
                    r_inv = n.invertBlinded(r, s) orelse continue;
                    x = n.mul(c, n.powWithEncodedPublicExponent(r, e, .big) catch unreachable);
                    break;
                } else return error.KeyMismatch;

                var m1 = try crtHalf(sk.p, dp, x, &rnd.exponent[0], &rnd.modulus[0]);
                defer wipe(&m1);
                var m2 = try crtHalf(sk.q, dq, x, &rnd.exponent[1], &rnd.modulus[1]);
                defer wipe(&m2);

                // Combine the halves: h = (m1 - m2) * qinv mod p, and m = m2 + q * h, which is below n.
                var h = sk.p.mul(sk.p.sub(m1, sk.p.reduce(m2.v)), sk.qinv);
                defer wipe(&h);
                var h_n = h.v.cast(NUint) catch unreachable;
                defer wipe(&h_n);
                var q_n = sk.q.toUint().cast(NUint) catch unreachable;
                defer wipe(&q_n);
                var m: N.Fe = .{ .v = m2.v.cast(NUint) catch unreachable };
                defer wipe(&m);
                _ = m.v.mulAddWithOverflow(q_n, h_n);
                if (level == .full) m = n.mul(m, r_inv);

                const fault_check = n.powWithEncodedPublicExponent(m, e, .big) catch unreachable;
                if (!timing_safe.valueBarrier(fault_check.eql(c))) return error.KeyMismatch;
                var out: [modulus_length]u8 = undefined;
                m.toBytes(&out, .big) catch unreachable;
                return out;
            }
        };
    };
}

/// Functions shared by the public key types of every scheme, which have a single `key` field.
pub fn PublicKeyFunctions(comptime Self: type, comptime bits: u16, comptime policy: Policy) type {
    const R = Rsa(bits);
    return struct {
        pub const Components = R.PublicComponents;
        pub const der_encoded_length_max = der.publicKeyLengthMax(R.modulus_length);
        pub const pem_encoded_length_max = pem.encodedLength(der_encoded_length_max);

        /// Imports a public key from its components.
        pub fn fromComponents(c: Components) PublicKeyError!Self {
            return .{ .key = try .fromComponents(c, policy.defaultAlgorithm()) };
        }

        /// Returns the components of the key.
        pub fn toComponents(pk: Self) Components {
            return pk.key.toComponents();
        }

        /// Imports a public key encoded in DER, as PKCS #1 RSAPublicKey or SubjectPublicKeyInfo.
        pub fn fromDer(bytes: []const u8, comptime format: PublicKeyFormat) PublicKeyError!Self {
            var c: Components = undefined;
            const alg = try der.parsePublicKey(bytes, format, &c);
            return .{ .key = try .fromComponents(c, if (alg) |a| try policy.accept(a, true) else policy.defaultAlgorithm()) };
        }

        /// Encodes the key in DER, and returns the slice of `buf` that was written.
        pub fn toDer(pk: Self, comptime format: PublicKeyFormat, buf: *[der_encoded_length_max]u8) []u8 {
            return der.writePublicKey(buf, format, policy.exportAlgorithm(pk.key.alg, true), pk.key.toComponents());
        }

        /// Imports the first "PUBLIC KEY" or "RSA PUBLIC KEY" block of a PEM file.
        pub fn fromPem(text: []const u8) PublicKeyError!Self {
            const block = try pem.find(text, &.{ .public_key, .rsa_public_key });
            var buf: [der_encoded_length_max]u8 = undefined;
            const bytes = try pem.decode(block.body, &buf);
            return if (block.label == .public_key) fromDer(bytes, .spki) else fromDer(bytes, .pkcs1);
        }

        /// Encodes the key in PEM, and returns the slice of `buf` that was written.
        pub fn toPem(pk: Self, comptime format: PublicKeyFormat, buf: *[pem_encoded_length_max]u8) []u8 {
            var der_buf: [der_encoded_length_max]u8 = undefined;
            return pem.encode(buf, if (format == .spki) .public_key else .rsa_public_key, toDer(pk, format, &der_buf));
        }
    };
}

/// Functions shared by the secret key types of every scheme, which have a single `key` field.
pub fn SecretKeyFunctions(comptime Self: type, comptime PublicKey: type, comptime bits: u16, comptime policy: Policy) type {
    const R = Rsa(bits);
    return struct {
        pub const Components = R.SecretComponents;
        pub const der_encoded_length_max = der.secretKeyLengthMax(R.modulus_length, R.prime_length);
        pub const pem_encoded_length_max = pem.encodedLength(der_encoded_length_max);

        /// Imports a secret key from its components, which must all be present and consistent.
        /// The components are secret: wipe them with `std.crypto.secureZero()` once they are no longer needed.
        pub fn fromComponents(c: *const Components) SecretKeyError!Self {
            return .{ .key = try .fromComponents(c, policy.defaultAlgorithm()) };
        }

        /// Returns the components of the key, which must be wiped after use.
        pub fn toComponents(sk: *const Self) Components {
            return sk.key.toComponents();
        }

        /// Imports a secret key encoded in DER, as PKCS #1 RSAPrivateKey or PKCS #8 PrivateKeyInfo.
        /// Encrypted keys are rejected with `error.InvalidEncoding`.
        pub fn fromDer(bytes: []const u8, comptime format: SecretKeyFormat) SecretKeyError!Self {
            var c: Components = undefined;
            defer wipe(&c);
            const alg = try der.parseSecretKey(bytes, format, &c);
            return .{ .key = try .fromComponents(&c, if (alg) |a| try policy.accept(a, false) else policy.defaultAlgorithm()) };
        }

        /// Encodes the key in DER, and returns the slice of `buf` that was written.
        pub fn toDer(sk: *const Self, comptime format: SecretKeyFormat, buf: *[der_encoded_length_max]u8) []u8 {
            var c = sk.key.toComponents();
            defer wipe(&c);
            return der.writeSecretKey(buf, format, policy.exportAlgorithm(sk.key.public_key.alg, false), &c);
        }

        /// Imports the first "PRIVATE KEY", "RSA PRIVATE KEY" or "ENCRYPTED PRIVATE KEY" block of a PEM file.
        /// Encrypted keys, including the legacy ones with a "Proc-Type" header, are rejected with `error.InvalidEncoding`.
        pub fn fromPem(text: []const u8) SecretKeyError!Self {
            const block = try pem.find(text, &.{ .private_key, .rsa_private_key, .encrypted_private_key });
            var buf: [der_encoded_length_max + der.attributes_length_max]u8 = undefined;
            defer crypto.secureZero(u8, &buf);
            const bytes = try pem.decode(block.body, &buf);
            return switch (block.label) {
                .private_key => fromDer(bytes, .pkcs8),
                .rsa_private_key => fromDer(bytes, .pkcs1),
                else => error.InvalidEncoding,
            };
        }

        /// Encodes the key in PEM, and returns the slice of `buf` that was written.
        pub fn toPem(sk: *const Self, comptime format: SecretKeyFormat, buf: *[pem_encoded_length_max]u8) []u8 {
            var der_buf: [der_encoded_length_max]u8 = undefined;
            defer crypto.secureZero(u8, &der_buf);
            return pem.encode(buf, if (format == .pkcs8) .private_key else .rsa_private_key, toDer(sk, format, &der_buf));
        }

        /// Returns the public key.
        pub fn publicKey(sk: *const Self) PublicKey {
            return .{ .key = sk.key.public_key };
        }
    };
}

/// Functions shared by the key pair types of every scheme, which have `public_key` and `secret_key` fields.
pub fn KeyPairFunctions(comptime Self: type, comptime bits: u16, comptime policy: Policy) type {
    const R = Rsa(bits);
    return struct {
        pub const seed_length = keygen.seed_length;

        /// Generates a new key pair.
        ///
        /// `io.random()` must be a cryptographically secure generator.
        /// If the operating system can't provide entropy, `Io.Threaded` silently falls back to a predictable seed, and the key is then predictable too.
        /// To rule that out, get a seed from `io.randomSecure()` and call `generateDeterministic()` instead.
        pub fn generate(io: std.Io) KeyMismatchError!Self {
            while (true) {
                var seed: [seed_length]u8 = undefined;
                io.random(&seed);
                defer crypto.secureZero(u8, &seed);
                return generateDeterministic(seed) catch |err| switch (err) {
                    error.WeakParameters => continue,
                    error.KeyMismatch => |e| return e,
                };
            }
        }

        /// Generates the key pair for a seed, using version 1 of the derivation.
        ///
        /// The derivation is frozen: a seed gives the same key in every version of the standard library.
        /// A later version may refuse a key it finds unsafe, with `error.WeakParameters`, but it never returns a different key.
        /// The seed is secret, and must be uniformly random.
        pub fn generateDeterministic(seed: [seed_length]u8) (KeyMismatchError || WeakParametersError)!Self {
            var c = keygen.generate(R, &seed, policy.label, policy.kind == .partially_blind);
            defer wipe(&c);
            var sk = R.SecretKey.fromComponents(&c, policy.defaultAlgorithm()) catch return error.KeyMismatch;
            defer wipe(&sk);

            // Run one private-key operation with its fault check, to catch a broken key before returning it.
            var final_check = keygen.stream(0x03, &seed, policy.label);
            defer wipe(&final_check);
            var x_bytes: [R.modulus_length]u8 = undefined;
            defer wipe(&x_bytes);
            var x = uniform(sk.public_key.n, &final_check) orelse return error.KeyMismatch;
            defer wipe(&x);
            x.toBytes(&x_bytes, .big) catch unreachable;
            var y = sk.rsadp(&x_bytes, &final_check) catch return error.KeyMismatch;
            wipe(&y);
            return .{ .public_key = .{ .key = sk.public_key }, .secret_key = .{ .key = sk } };
        }

        /// Returns the key pair of a secret key.
        pub fn fromSecretKey(secret_key: @FieldType(Self, "secret_key")) Self {
            return .{ .public_key = secret_key.publicKey(), .secret_key = secret_key };
        }

        /// Checks that the public key matches the secret key, since both fields can be set separately.
        pub fn check(kp: *const Self) KeyMismatchError!void {
            const a = kp.public_key.key;
            const b = kp.secret_key.key.public_key;
            if (a.e != b.e or !a.n.v.eql(b.n.v)) return error.KeyMismatch;
        }
    };
}
