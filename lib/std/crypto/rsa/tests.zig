const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const sha2 = std.crypto.hash.sha2;
const sign = @import("sign.zig");
const kem = @import("kem.zig");
const core = @import("core.zig");
const padding = @import("padding.zig");
const builtin = @import("builtin");

pub fn hex(arena: mem.Allocator, s: []const u8) ![]u8 {
    return std.fmt.hexToBytes(try arena.alloc(u8, s.len / 2), s);
}

pub fn hexArray(comptime len: usize, s: []const u8) ![len]u8 {
    var out: [len]u8 = undefined;
    if (s.len != 2 * len) return error.TestUnexpectedResult;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

pub fn parse(comptime T: type, arena: mem.Allocator, comptime file: []const u8) ![]T {
    return std.json.parseFromSliceLeaky([]T, arena, @embedFile("testdata/" ++ file), .{ .ignore_unknown_fields = true });
}

pub fn secretComponents(comptime C: type, v: anytype) !C {
    const k = @typeInfo(@FieldType(C, "n")).array.len;
    const pl = @typeInfo(@FieldType(C, "p")).array.len;
    return .{
        .n = try hexArray(k, v.n),
        .e = try std.fmt.parseInt(u64, v.e, 16),
        .d = try hexArray(k, v.d),
        .p = try hexArray(pl, v.p),
        .q = try hexArray(pl, v.q),
        .dp = try hexArray(pl, v.dp),
        .dq = try hexArray(pl, v.dq),
        .qinv = try hexArray(pl, v.qinv),
    };
}

const OpensslKey = struct {
    bits: u16,
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,
    pkcs1_pub_der: []const u8,
    spki_der: []const u8,
    pkcs1_priv_der: []const u8,
    pkcs8_der: []const u8,
    msg: []const u8,
    pkcs1v15_sha256_sig: []const u8,
    pss_sha256_sig: []const u8,
    pkcs1v15_sha384_sig: []const u8,
    pss_sha384_sig: []const u8,
    pkcs1v15_sha512_sig: []const u8,
    pss_sha512_sig: []const u8,
    oaep_sha256_secret: []const u8,
    oaep_sha256_ct: []const u8,
};

test "OpenSSL keys and signatures" {
    @setEvalBranchQuota(100_000);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    for (try parse(OpensslKey, arena, "openssl.json")) |v| {
        const msg = try hex(arena, v.msg);
        switch (v.bits) {
            inline 2048, 2056, 3072, 4096 => |bits| inline for (.{ sha2.Sha256, sha2.Sha384, sha2.Sha512 }) |H| {
                const hash_name = comptime @tagName(core.hashId(H));
                inline for (.{ sign.RsaPkcs1v15(bits, H), sign.RsaPss(bits, H) }, .{ "pkcs1v15_", "pss_" }) |S, prefix| {
                    var c = try secretComponents(S.SecretKey.Components, v);
                    const sk = try S.SecretKey.fromComponents(&c);
                    try testing.expectEqualDeep(c, sk.toComponents());
                    const kp = S.KeyPair.fromSecretKey(sk);

                    // Every encoding gives the same key, and is written back exactly as OpenSSL writes it.
                    // This doesn't depend on the hash, so only check it once.
                    if (H == sha2.Sha256) {
                        if (S == sign.RsaPss(bits, H)) try testing.expectEqualSlices(u8, try hex(arena, v.oaep_sha256_secret), &try (try kem.RsaOaepKem(bits, H).SecretKey.fromComponents(&c)).decaps(&try hexArray(S.modulus_length, v.oaep_sha256_ct), io));
                        inline for (.{ .pkcs1, .spki }, .{ v.pkcs1_pub_der, v.spki_der }) |format, der_hex| {
                            const der = try hex(arena, der_hex);
                            const pk = try S.PublicKey.fromDer(der, format);
                            try testing.expectEqualDeep(kp.public_key.toComponents(), pk.toComponents());
                            var buf: [S.PublicKey.der_encoded_length_max]u8 = undefined;
                            try testing.expectEqualSlices(u8, der, kp.public_key.toDer(format, &buf));
                            var pem_buf: [S.PublicKey.pem_encoded_length_max]u8 = undefined;
                            const pem = kp.public_key.toPem(format, &pem_buf);
                            try testing.expectEqualDeep(pk.toComponents(), (try S.PublicKey.fromPem(pem)).toComponents());
                            try testing.expectEqual(bits, try sign.modulusBitsFromDer(der, format));
                            try testing.expectEqual(bits, try sign.modulusBitsFromPem(pem));
                        }
                        inline for (.{ .pkcs1, .pkcs8 }, .{ v.pkcs1_priv_der, v.pkcs8_der }) |format, der_hex| {
                            const der = try hex(arena, der_hex);
                            const sk2 = try S.SecretKey.fromDer(der, format);
                            try testing.expectEqualDeep(c, sk2.toComponents());
                            var buf: [S.SecretKey.der_encoded_length_max]u8 = undefined;
                            try testing.expectEqualSlices(u8, der, sk.toDer(format, &buf));
                            var pem_buf: [S.SecretKey.pem_encoded_length_max]u8 = undefined;
                            const pem = sk.toPem(format, &pem_buf);
                            try testing.expectEqualDeep(c, (try S.SecretKey.fromPem(pem)).toComponents());
                            try testing.expectEqual(bits, try sign.modulusBitsFromPem(pem));
                        }
                    }

                    const expected = try hexArray(S.Signature.encoded_length, @field(v, prefix ++ hash_name ++ "_sig"));
                    const sig = S.Signature.fromBytes(expected);
                    try sig.verify(msg, kp.public_key);
                    try testing.expectError(error.SignatureVerificationFailed, sig.verify("wrong", kp.public_key));
                    var tampered = expected;
                    tampered[S.modulus_length - 1] ^= 1;
                    try testing.expectError(error.SignatureVerificationFailed, S.Signature.fromBytes(tampered).verify(msg, kp.public_key));

                    const own = try kp.sign(msg, io);
                    try own.verify(msg, kp.public_key);
                    if (S == sign.RsaPkcs1v15(bits, H)) try testing.expectEqualSlices(u8, &expected, &own.bytes);
                    var h: [H.digest_length]u8 = undefined;
                    H.hash(msg, &h, .{});
                    try (try kp.signPrehashed(h, io)).verifyPrehashed(h, kp.public_key);
                }
            },
            else => return error.TestUnexpectedResult,
        }
    }

    const S = sign.RsaPss(2048, sha2.Sha256);
    const Vector = struct { salt_len: u32, spki_der: []const u8, pkcs8_der: []const u8, msg: []const u8, pss_sig: []const u8 };
    for (try parse(Vector, arena, "pss_keys.json")) |v| {
        const pk = try S.PublicKey.fromDer(try hex(arena, v.spki_der), .spki);
        const sk = try S.SecretKey.fromDer(try hex(arena, v.pkcs8_der), .pkcs8);
        // The minimum salt length survives a round trip, even when it is below the scheme's salt.
        const expected: @import("der.zig").Algorithm = .{ .rsassa_pss = .{ .hash = .sha256, .salt_length = v.salt_len } };
        try testing.expectEqualDeep(expected, pk.key.alg);
        try testing.expectEqualDeep(expected, sk.key.public_key.alg);
        var buf: [S.PublicKey.der_encoded_length_max]u8 = undefined;
        try testing.expectEqualDeep(expected, (try S.PublicKey.fromDer(pk.toDer(.spki, &buf), .spki)).key.alg);
        var sk_buf: [S.SecretKey.der_encoded_length_max]u8 = undefined;
        try testing.expectEqualDeep(expected, (try S.SecretKey.fromDer(sk.toDer(.pkcs8, &sk_buf), .pkcs8)).key.public_key.alg);
        // Signatures with the scheme's own salt length verify.
        if (v.salt_len == sha2.Sha256.digest_length) {
            try S.Signature.fromBytes(try hexArray(S.Signature.encoded_length, v.pss_sig)).verify(try hex(arena, v.msg), pk);
        }
        const kp = S.KeyPair.fromSecretKey(sk);
        try (try kp.sign("message", testing.io)).verify("message", pk);
    }
}

const KemVector = struct {
    bits: u16 = 0,
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,
    spki_der: []const u8 = "",
    rsa_private_key_der: []const u8,
    z: []const u8 = "",
    ct: []const u8,
    ss: []const u8 = "",
    secret: []const u8 = "",
};

test "RFC 9690 RSA-KEM" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    const K = kem.RsaKem(3072, sha2.Sha256);
    const v = (try parse(KemVector, arena, "rfc9690.json"))[0];

    const pk = try K.PublicKey.fromDer(try hex(arena, v.spki_der), .spki);
    const z = try hexArray(K.encaps_seed_length, v.z);
    const es = try pk.encapsDeterministic(&z);
    try testing.expectEqualSlices(u8, &try hexArray(K.ciphertext_length, v.ct), &es.ciphertext);
    const ss = try hex(arena, v.ss);
    try testing.expectEqualSlices(u8, ss, es.shared_secret[0..ss.len]);

    // The PEM of the RFC is labeled PRIVATE KEY, but holds a PKCS #1 RSAPrivateKey.
    const sk = try K.SecretKey.fromDer(try hex(arena, v.rsa_private_key_der), .pkcs1);
    try testing.expectEqualSlices(u8, &es.shared_secret, &try sk.decaps(&es.ciphertext, io));

    // Public keys are written with id-rsa-kem-spki, and read back.
    var buf: [K.PublicKey.der_encoded_length_max]u8 = undefined;
    const spki = pk.toDer(.spki, &buf);
    try testing.expect(mem.find(u8, spki, &.{ 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x0e }) != null);
    try testing.expectEqualDeep(pk.toComponents(), (try K.PublicKey.fromDer(spki, .spki)).toComponents());
    // KEM-only keys are refused by signature schemes.
    try testing.expectError(error.InvalidEncoding, sign.RsaPss(3072, sha2.Sha256).PublicKey.fromDer(spki, .spki));

    // Boundary values: 0, 1 and n - 1 are their own ciphertexts, and leading zero bytes must be kept.
    const n = try hexArray(K.modulus_length, v.n);
    var values: [4 + K.modulus_length][K.modulus_length]u8 = undefined;
    values[0] = @splat(0);
    values[1] = @splat(0);
    values[1][K.modulus_length - 1] = 1;
    values[2] = n;
    values[2][K.modulus_length - 1] -= 1;
    values[3] = z;
    for (values[4..], 0..) |*x, i| {
        x.* = z;
        @memset(x[0..i], 0);
    }
    for (values, 0..) |x, i| {
        // Every number of leading zero bytes in optimized builds, the first and last ones in Debug.
        if (builtin.mode == .debug and i > 12 and i < values.len - 3) continue;
        const e = try pk.encapsDeterministic(&x);
        if (i < 3) try testing.expectEqualSlices(u8, &x, &e.ciphertext);
        try testing.expectEqualSlices(u8, &e.shared_secret, &try sk.decaps(&e.ciphertext, io));
    }
    try testing.expectError(error.NonCanonical, pk.encapsDeterministic(&n));
    try testing.expectError(error.NonCanonical, sk.decaps(&n, io));
    try testing.expectError(error.NonCanonical, sk.decaps(&@splat(0xff), io));

    const r = pk.encaps(io);
    try testing.expectEqualSlices(u8, &r.shared_secret, &try sk.decaps(&r.ciphertext, io));
}

// Encrypts an OAEP encoding built from a given DB, seed and first byte.
fn oaepCiphertext(comptime K: type, pk: K.PublicKey, db: []const u8, seed: []const u8, y: u8) ![K.ciphertext_length]u8 {
    var em: [K.modulus_length]u8 = undefined;
    em[0] = y;
    const masked_seed = em[1..][0..seed.len];
    const masked_db = em[1 + seed.len ..];
    @memcpy(masked_db, db);
    padding.mgf1Xor(K.Hash, masked_db, seed);
    @memcpy(masked_seed, seed);
    padding.mgf1Xor(K.Hash, masked_seed, masked_db);
    var out: [K.ciphertext_length]u8 = undefined;
    try pk.key.rsaep(try pk.key.element(&em)).toBytes(&out, .big);
    return out;
}

test "RSA-OAEP KEM" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    for (try parse(KemVector, arena, "oaep_kem_lamps.json")) |v| {
        switch (v.bits) {
            inline 2048, 3072, 4096 => |bits| {
                const K = kem.RsaOaepKem(bits, sha2.Sha256);
                const sk = try K.SecretKey.fromDer(try hex(arena, v.rsa_private_key_der), .pkcs1);
                const ct = try hexArray(K.ciphertext_length, v.ct);
                try testing.expectEqualSlices(u8, try hex(arena, v.secret), &try sk.decaps(&ct, io));
            },
            else => return error.TestUnexpectedResult,
        }
    }
    const openssl = try parse(OpensslKey, arena, "openssl.json");

    inline for (.{ sha2.Sha256, sha2.Sha512 }) |H| {
        const K = kem.RsaOaepKem(2048, H);
        var c = try secretComponents(K.SecretKey.Components, openssl[0]);
        const kp = K.KeyPair.fromSecretKey(try K.SecretKey.fromComponents(&c));
        const es = kp.public_key.encaps(io);
        try testing.expectEqualSlices(u8, &es.shared_secret, &try kp.secret_key.decaps(&es.ciphertext, io));

        // Break each part of the encoding separately.
        const h_len = H.digest_length;
        const db_len = K.modulus_length - h_len - 1;
        var db: [db_len]u8 = @splat(0);
        H.hash("", db[0..h_len], .{});
        db[db_len - 33] = 1;
        db[db_len - 32 ..].* = @splat(0x42);
        const seed: [h_len]u8 = @splat(7);
        const valid = try oaepCiphertext(K, kp.public_key, &db, &seed, 0);
        try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x42)), &try kp.secret_key.decaps(&valid, io));
        // A wrong hash, padding or separator, and a message that is too long.
        var bads: [4][db_len]u8 = @splat(db);
        bads[0][0] ^= 1;
        bads[1][h_len] = 1;
        bads[2][db_len - 33] = 2;
        bads[3][db_len - 33] = 0;
        bads[3][db_len - 34] = 1;
        for (bads) |bad| {
            const ct = try oaepCiphertext(K, kp.public_key, &bad, &seed, 0);
            try testing.expectError(error.AuthenticationFailed, kp.secret_key.decaps(&ct, io));
        }
        const bad_y = try oaepCiphertext(K, kp.public_key, &db, &seed, 1);
        try testing.expectError(error.AuthenticationFailed, kp.secret_key.decaps(&bad_y, io));
    }
}

const BlindVector = struct {
    name: []const u8,
    randomized: bool,
    salt_len: u32,
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,
    msg: []const u8,
    msg_prefix: []const u8,
    inv: []const u8,
    blinded_msg: []const u8,
    blind_sig: []const u8,
    sig: []const u8,
};

test "RFC 9474 blind signatures" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    const vectors = try parse(BlindVector, arena, "rfc9474.json");
    inline for (.{ .sha384_pss_randomized, .sha384_psszero_randomized, .sha384_pss_deterministic, .sha384_psszero_deterministic }, 0..) |variant, i| {
        const B = sign.BlindRsa(4096, variant);
        const v = vectors[i];
        try testing.expectEqual(B.variant.isRandomized(), v.randomized);
        try testing.expectEqual(B.variant.saltLength(), v.salt_len);
        var c = try secretComponents(B.SecretKey.Components, v);
        const kp = B.KeyPair.fromSecretKey(try B.SecretKey.fromComponents(&c));
        const msg = try hex(arena, v.msg);

        const blind_sig = try kp.secret_key.blindSign(.fromBytes(try hexArray(B.modulus_length, v.blinded_msg)), io);
        try testing.expectEqualSlices(u8, &try hexArray(B.modulus_length, v.blind_sig), &blind_sig.bytes);
        const secret = B.BlindingSecret.fromBytes(try hexArray(B.modulus_length, v.inv) ++ try hexArray(B.randomizer_length, v.msg_prefix));
        try testing.expectEqualDeep(secret, B.BlindingSecret.fromBytes(secret.toBytes()));
        const sig = try kp.public_key.finalize(blind_sig, secret, msg);
        try testing.expectEqualSlices(u8, &try hexArray(B.modulus_length, v.sig), &sig.bytes);
        try sig.verify(msg, kp.public_key);
        try testing.expectError(error.SignatureVerificationFailed, sig.verify("other", kp.public_key));

        // The whole protocol, with fresh randomness.
        const blinding = try kp.public_key.blind(msg, io);
        const sig2 = try kp.public_key.finalize(try kp.secret_key.blindSign(blinding.blind_message, io), blinding.secret, msg);
        try sig2.verify(msg, kp.public_key);
        try testing.expectError(error.SignatureVerificationFailed, kp.public_key.finalize(blind_sig, blinding.secret, msg));

        const n = try hexArray(B.modulus_length, v.n);
        try testing.expectError(error.NonCanonical, kp.secret_key.blindSign(.fromBytes(n), io));
        try testing.expectError(error.NonCanonical, kp.public_key.finalize(.fromBytes(n), secret, msg));

        // Keys are written with exactly the parameters of the variant, and rsaEncryption is refused.
        var buf: [B.PublicKey.der_encoded_length_max]u8 = undefined;
        const spki = kp.public_key.toDer(.spki, &buf);
        _ = try B.PublicKey.fromDer(spki, .spki);
        const Other = sign.BlindRsa(4096, if (B.variant.saltLength() == 0) .sha384_pss_randomized else .sha384_psszero_randomized);
        try testing.expectError(error.InvalidEncoding, Other.PublicKey.fromDer(spki, .spki));
        const Pss = sign.RsaPss(4096, sha2.Sha384);
        var buf2: [Pss.PublicKey.der_encoded_length_max]u8 = undefined;
        const rsa_spki = (try Pss.PublicKey.fromComponents(kp.public_key.toComponents())).toDer(.spki, &buf2);
        try testing.expectError(error.InvalidEncoding, B.PublicKey.fromDer(rsa_spki, .spki));
    }

    // An RFC 9578 issuer key round-trips exactly.
    const B = sign.BlindRsa(2048, .sha384_pss_deterministic);
    const spki = try hex(arena, (try parse(struct { spki_der: []const u8 }, arena, "privacy_pass.json"))[0].spki_der);
    var buf: [B.PublicKey.der_encoded_length_max]u8 = undefined;
    try testing.expectEqualSlices(u8, spki, (try B.PublicKey.fromDer(spki, .spki)).toDer(.spki, &buf));
}

test {
    _ = @import("partially_blind.zig");
    _ = @import("primality.zig");
}

// Builds a DER element from the concatenation of its parts.
fn tlv(arena: mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    const content = try mem.concat(arena, u8, parts);
    const header: []const u8 = if (content.len < 0x80)
        &.{ tag, @intCast(content.len) }
    else if (content.len < 0x100)
        &.{ tag, 0x81, @intCast(content.len) }
    else
        &.{ tag, 0x82, @intCast(content.len >> 8), @truncate(content.len) };
    return mem.concat(arena, u8, &.{ header, content });
}

const oid_rsa = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const oid_pss = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";
const oid_mgf1 = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08";
const oid_sha256 = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
const oid_sha384 = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02";

fn pssAlg(arena: mem.Allocator, oid_hash: []const u8, hash_null: bool, salt: ?[]const u8, trailer: ?[]const u8) ![]u8 {
    const hash = try tlv(arena, 0x30, &.{ oid_hash, if (hash_null) "\x05\x00" else "" });
    var parts: std.ArrayList([]const u8) = .empty;
    try parts.append(arena, try tlv(arena, 0xa0, &.{hash}));
    try parts.append(arena, try tlv(arena, 0xa1, &.{try tlv(arena, 0x30, &.{ oid_mgf1, hash })}));
    if (salt) |s| try parts.append(arena, try tlv(arena, 0xa2, &.{s}));
    if (trailer) |t| try parts.append(arena, try tlv(arena, 0xa3, &.{t}));
    return tlv(arena, 0x30, &.{ oid_pss, try tlv(arena, 0x30, parts.items) });
}

test "strict DER" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = (try parse(OpensslKey, a, "openssl.json"))[0];
    const S = sign.RsaPss(2048, sha2.Sha256);
    const n = try hex(a, v.n);
    const n_int = try tlv(a, 0x02, &.{ "\x00", n });
    const e_int = "\x02\x03\x01\x00\x01";
    const rsa_alg = try tlv(a, 0x30, &.{ oid_rsa, "\x05\x00" });
    const pub_key = try tlv(a, 0x30, &.{ n_int, e_int });
    const spki = struct {
        fn f(arena: mem.Allocator, alg: []const u8, key: []const u8) ![]u8 {
            return tlv(arena, 0x30, &.{ alg, try tlv(arena, 0x03, &.{ "\x00", key }) });
        }
    }.f;

    // Sanity check: tlv() gives the same bytes as OpenSSL.
    try testing.expectEqualSlices(u8, try hex(a, v.pkcs1_pub_der), pub_key);
    try testing.expectEqualSlices(u8, try hex(a, v.spki_der), try spki(a, rsa_alg, pub_key));

    const bad_pkcs1 = [_][]const u8{
        try tlv(a, 0x30, &.{ n_int, "\x02\x04\x00\x01\x00\x01" }), // leading zero
        try tlv(a, 0x30, &.{ n_int, "\x02\x81\x03\x01\x00\x01" }), // long form for a short length
        try tlv(a, 0x30, &.{ try tlv(a, 0x02, &.{n}), e_int }), // negative
        try tlv(a, 0x30, &.{ try tlv(a, 0x02, &.{ "\x00\x00", n }), e_int }), // extra zero byte
        try tlv(a, 0x30, &.{ n_int, e_int, "\x05\x00" }), // extra element
        try mem.concat(a, u8, &.{ pub_key, "\x00" }), // trailing data
        try tlv(a, 0x30, &.{ n_int, "\x04\x03\x01\x00\x01" }), // wrong tag
        try tlv(a, 0x30, &.{n_int}), // missing exponent
        &.{ 0x30, 0x83, 0x00, 0x01, 0x0a }, // length of length too long
    };
    for (bad_pkcs1) |der| try testing.expectError(error.InvalidEncoding, S.PublicKey.fromDer(der, .pkcs1));

    const bad_spki = [_][]const u8{
        try spki(a, try tlv(a, 0x30, &.{oid_rsa}), pub_key), // missing NULL
        try spki(a, try tlv(a, 0x30, &.{ oid_rsa, "\x05\x01\x00" }), pub_key), // NULL with contents
        try tlv(a, 0x30, &.{ rsa_alg, try tlv(a, 0x03, &.{ "\x01", pub_key }) }), // unused bits
        try spki(a, try pssAlg(a, oid_sha256, false, "\x02\x01\x20", "\x02\x01\x01"), pub_key), // explicit trailer field
        try spki(a, try pssAlg(a, oid_sha256, false, "\x02\x01\x14", null), pub_key), // explicit default salt length
        try spki(a, try pssAlg(a, oid_sha256, false, "\x02\x01\x21", null), pub_key), // salt longer than the scheme's
        try spki(a, try pssAlg(a, oid_sha384, false, "\x02\x01\x20", null), pub_key), // another hash
    };
    for (bad_spki) |der| try testing.expectError(error.InvalidEncoding, S.PublicKey.fromDer(der, .spki));

    // PSS parameters survive a round trip, a salt length below the scheme's is accepted, and NULL hash parameters are dropped.
    for ([_]?[]const u8{ "\x02\x01\x10", null }) |salt| {
        const pss_alg = try pssAlg(a, oid_sha256, false, salt, null);
        const der = try spki(a, pss_alg, pub_key);
        var buf: [S.PublicKey.der_encoded_length_max]u8 = undefined;
        try testing.expectEqualSlices(u8, der, (try S.PublicKey.fromDer(der, .spki)).toDer(.spki, &buf));
        const with_null = try spki(a, try pssAlg(a, oid_sha256, true, salt, null), pub_key);
        try testing.expectEqualSlices(u8, der, (try S.PublicKey.fromDer(with_null, .spki)).toDer(.spki, &buf));
    }
    const unrestricted = try spki(a, try tlv(a, 0x30, &.{oid_pss}), pub_key);
    var buf: [S.PublicKey.der_encoded_length_max]u8 = undefined;
    try testing.expectEqualSlices(u8, unrestricted, (try S.PublicKey.fromDer(unrestricted, .spki)).toDer(.spki, &buf));
    try testing.expectError(error.InvalidEncoding, sign.BlindRsa(2048, .sha384_pss_randomized).PublicKey.fromDer(unrestricted, .spki));

    // Secret keys: versions, and PKCS #8 attributes of at most 1024 bytes.
    const pkcs1 = try hex(a, v.pkcs1_priv_der);
    var v1 = try a.dupe(u8, pkcs1);
    v1[6] = 1;
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(v1, .pkcs1));
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(pkcs1, .pkcs8));
    const pkcs8_body = (try hex(a, v.pkcs8_der))[4..];
    const Attrs = struct {
        body: []const u8,
        fn key(self: @This(), arena: mem.Allocator, attrs: []const []const u8) ![]u8 {
            return tlv(arena, 0x30, &.{ self.body, try tlv(arena, 0xa0, attrs) });
        }
        fn attr(arena: mem.Allocator, oid: []const u8, values: []const u8) ![]u8 {
            return tlv(arena, 0x30, &.{ oid, try tlv(arena, 0x31, &.{values}) });
        }
    };
    const with: Attrs = .{ .body = pkcs8_body };
    for ([_]usize{ 1024, 1025 }) |len| {
        const value = try a.alloc(u8, len - 21);
        @memset(value, 'x');
        const der = try with.key(a, &.{try Attrs.attr(a, "\x06\x03\x55\x04\x03", try tlv(a, 0x04, &.{value}))});
        try testing.expectEqual(len, der.len - pkcs8_body.len - 4);
        var pem_buf: [8192]u8 = undefined;
        const pem = @import("pem.zig").encode(&pem_buf, .private_key, der);
        if (len == 1024) {
            _ = try S.SecretKey.fromDer(der, .pkcs8);
            _ = try S.SecretKey.fromPem(pem);
        } else {
            try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(der, .pkcs8));
            try testing.expectError(error.InvalidEncoding, S.SecretKey.fromPem(pem));
        }
    }
    var pkcs8_v1 = try hex(a, v.pkcs8_der);
    pkcs8_v1[6] = 1;
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(pkcs8_v1, .pkcs8));
    for ([_][]const u8{ "\x06\x02\x55\x84", "\x06\x02\x80\x01", "\x06\x00" }) |oid| {
        try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(try with.key(a, &.{try Attrs.attr(a, oid, "\x04\x01\x61")}), .pkcs8));
    }

    // Attribute values are opaque, but must be well-formed elements, in sets sorted by encoding.
    const oid_cn = "\x06\x03\x55\x04\x03";
    const oid_o = "\x06\x03\x55\x04\x0a";
    var nested: []const u8 = "\x05\x00";
    while (nested.len < 1024 - 32) nested = try tlv(a, 0x30, &.{nested});
    const good_values = [_][]const u8{
        "\x04\x01\x61\x04\x01\x61", // duplicates
        "\x04\x01\x61\x04\x01\x62",
        "\x30\x00",
        nested, // as deep as the size limit allows
        "\x30\x05\x31\x03\x01\x01\x07", // the contents of primitive elements are not checked
        "\x31\x06\x04\x01\x62\x04\x01\x61", // nor the order of nested sets
        "\x1f\x1f\x00",
        "\xbf\x81\x00\x00",
    };
    const bad_values = [_][]const u8{
        "", // empty set
        "\x01", // truncated element
        "\x04\x02\x61", // contents past the end
        "\x04\x01\x62\x04\x01\x61", // unsorted
        "\x30\x03\x04\x02\x61", // nested element past the end of its parent
        "\x30\x04\x04\x01\x61", // contents past the end, in a constructed element
        "\x30\x04\x04\x01\x61\x00", // truncated element after a valid one, in a constructed element
        "\x30\x80\x00\x00", // indefinite length
        "\x30\x01\x04\x01\x61", // nested length past the end of its parent
        "\x30\x01\x1f\x81\x00\x00", // nested tag past the end of its parent
        "\x00\x00", // end-of-contents
        "\x0f\x00", // reserved universal tag
        "\x10\x00", // primitive SEQUENCE
        "\x24\x03\x04\x01\x61", // constructed OCTET STRING
        "\x3f\x1f\x00", // constructed universal type with a high tag number
        "\x1f\x1e\x00", // high tag number that fits in the first byte
        "\x1f\x80\x20\x00", // high tag number with a leading zero
        "\x1f\x81", // truncated high tag number
    };
    for ([_][]const []const u8{ &good_values, &bad_values }, 0..) |values, i| {
        for (values) |value| {
            const result = S.SecretKey.fromDer(try with.key(a, &.{try Attrs.attr(a, oid_cn, value)}), .pkcs8);
            if (i == 0) _ = try result else try testing.expectError(error.InvalidEncoding, result);
        }
    }
    // Attributes are sorted by their whole encoding, so a shorter one comes first even if its OID is larger.
    const attr_cn = try Attrs.attr(a, oid_cn, "\x04\x03\x61\x61\x61");
    const attr_o = try Attrs.attr(a, oid_o, "\x04\x01\x61");
    _ = try S.SecretKey.fromDer(try with.key(a, &.{ attr_o, attr_cn }), .pkcs8);
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(try with.key(a, &.{ attr_cn, attr_o }), .pkcs8));
    // An attribute with something after its values.
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromDer(try with.key(a, &.{try tlv(a, 0x30, &.{ oid_cn, "\x31\x03\x04\x01\x61", "\x05\x00" })}), .pkcs8));

    // Exporting a secret key leaves nothing behind once the returned slice is wiped.
    const sk = try S.SecretKey.fromDer(pkcs1, .pkcs1);
    inline for (.{ .pkcs1, .pkcs8 }) |format| {
        var sk_buf: [S.SecretKey.der_encoded_length_max]u8 = @splat(0);
        const encoded = sk.toDer(format, &sk_buf);
        try testing.expect(encoded.len < sk_buf.len);
        std.crypto.secureZero(u8, encoded);
        try testing.expect(std.mem.allEqual(u8, &sk_buf, 0));
    }

    // Sizes: a modulus that is too large for the helpers, and keys of another size.
    const huge = try a.alloc(u8, 2049);
    @memset(huge, 0x7f);
    const huge_key = try tlv(a, 0x30, &.{ try tlv(a, 0x02, &.{huge}), e_int });
    try testing.expectError(error.InvalidEncoding, sign.modulusBitsFromDer(huge_key, .pkcs1));
    try testing.expectError(error.InvalidEncoding, S.PublicKey.fromDer(huge_key, .pkcs1));
    @memset(huge, 0xff);
    huge[0] = 0;
    const largest_key = try tlv(a, 0x30, &.{ try tlv(a, 0x02, &.{huge}), e_int });
    try testing.expectEqual(16384, try sign.modulusBitsFromDer(largest_key, .pkcs1));
    try testing.expectError(error.InvalidEncoding, sign.RsaPss(3072, sha2.Sha256).PublicKey.fromDer(pub_key, .pkcs1));
    // The modulus must be inside the sequence.
    try testing.expectError(error.InvalidEncoding, sign.modulusBitsFromDer(&.{ 0x30, 0x00, 0x02, 0x02, 0x00, 0x80 }, .pkcs1));
    try testing.expectError(error.InvalidEncoding, sign.modulusBitsFromDer(&.{ 0x30, 0x03, 0x02, 0x82, 0x01, 0x01, 0x00, 0x80 }, .pkcs1));
}

test "PEM" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const S = sign.RsaPss(2056, sha2.Sha256);
    const spki = @embedFile("testdata/rsa2056_spki.pem");
    const pkcs8 = @embedFile("testdata/rsa2056_pkcs8.pem");
    const expected = (try S.PublicKey.fromPem(spki)).toComponents();
    try testing.expectEqualDeep(expected, (try S.PublicKey.fromPem(@embedFile("testdata/rsa2056_pkcs1_pub.pem"))).toComponents());
    const sk = try S.SecretKey.fromPem(pkcs8);
    try testing.expectEqualDeep(sk.toComponents(), (try S.SecretKey.fromPem(@embedFile("testdata/rsa2056_pkcs1_priv.pem"))).toComponents());

    // Line endings, whitespace, explanatory text and other blocks.
    const crlf = try mem.replaceOwned(u8, a, spki, "\n", "\r\n");
    const cr = try mem.replaceOwned(u8, a, spki, "\n", "\r");
    const spaced = try mem.replaceOwned(u8, a, spki, "\n", " \t\n\x0b\x0c ");
    const text = try mem.concat(a, u8, &.{ "Explanatory text\n", pkcs8, "more text\n", spki, "-----BEGIN PUBLIC KEY-----\ninvalid\n" });
    for ([_][]const u8{ crlf, cr, spaced, text }) |pem| {
        try testing.expectEqualDeep(expected, (try S.PublicKey.fromPem(pem)).toComponents());
        try testing.expectEqual(2056, try sign.modulusBitsFromPem(pem));
    }
    try testing.expectEqualDeep(sk.toComponents(), (try S.SecretKey.fromPem(text)).toComponents());

    // Encrypted keys are refused, even when a valid key follows.
    for ([_][]const u8{ @embedFile("testdata/rsa2048_pkcs8_encrypted.pem"), @embedFile("testdata/rsa2048_pkcs1_priv_encrypted.pem") }) |enc| {
        const P = sign.RsaPss(2048, sha2.Sha256);
        try testing.expectError(error.InvalidEncoding, P.SecretKey.fromPem(enc));
        try testing.expectError(error.InvalidEncoding, S.SecretKey.fromPem(try mem.concat(a, u8, &.{ enc, pkcs8 })));
        try testing.expectError(error.InvalidEncoding, sign.modulusBitsFromPem(enc));
    }

    const body_start = mem.findScalar(u8, spki, '\n').? + 1;
    const end_start = mem.find(u8, spki, "-----END").?;
    const bad = [_][]const u8{
        spki[0..end_start], // no END line
        try mem.replaceOwned(u8, a, spki, "-----END PUBLIC KEY", "-----END RSA PUBLIC KEY"),
        try mem.concat(a, u8, &.{ spki[0..body_start], "Proc-Type: 4,ENCRYPTED\n", spki[body_start..] }),
        try mem.concat(a, u8, &.{ spki[0..body_start], "A", spki[body_start..] }), // not canonical
        try mem.concat(a, u8, &.{ spki[0 .. body_start - 1], spki[body_start..] }), // no line break after the label
        try mem.replaceOwned(u8, a, spki, "PUBLIC KEY", "CERTIFICATE"),
        try mem.concat(a, u8, &.{ spki[0 .. end_start - 4], "=", spki[end_start - 3 ..] }),
        try mem.concat(a, u8, &.{ spki[0 .. end_start - 1], spki[end_start..] }), // END not at the start of a line
        try mem.replaceOwned(u8, a, spki, "-----END PUBLIC KEY-----", "-----END PUBLIC KEY------"),
        "",
    };
    for (bad) |pem| try testing.expectError(error.InvalidEncoding, S.PublicKey.fromPem(pem));

    // Public keys skip secret keys and the other way around.
    try testing.expectError(error.InvalidEncoding, S.PublicKey.fromPem(pkcs8));
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromPem(spki));
}

test "secret key consistency" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = (try parse(OpensslKey, a, "openssl.json"))[1];
    const S = sign.RsaPss(2056, sha2.Sha256);
    const good = try secretComponents(S.SecretKey.Components, v);
    _ = try S.SecretKey.fromComponents(&good);

    var c = good;
    c.n[S.modulus_length - 1] ^= 1; // even n
    try testing.expectError(error.WeakPublicKey, S.SecretKey.fromComponents(&c));
    c = good;
    c.n[0] = 0x7f; // too small
    try testing.expectError(error.InvalidEncoding, S.SecretKey.fromComponents(&c));
    for ([_]u64{ 1, 2, 65536, 1 << 33, (1 << 33) + 1, std.math.maxInt(u64) }) |e| {
        c = good;
        c.e = e;
        try testing.expectError(error.WeakPublicKey, S.SecretKey.fromComponents(&c));
    }
    // Another valid exponent, flipped bits, a prime equal to 1, p = q, swapped primes with the wrong qinv, d >= n, and unreduced CRT exponents.
    var bad: [13]S.SecretKey.Components = @splat(good);
    bad[0].e = 3;
    inline for (.{ "d", "p", "q", "dp", "dq", "qinv" }, 1..) |field, i| @field(bad[i], field)[@field(bad[i], field).len - 1] ^= 2;
    @memset(&bad[7].p, 0);
    bad[7].p[S.prime_length - 1] = 1;
    bad[8].q = good.p;
    bad[9].p = good.q;
    bad[9].q = good.p;
    bad[10].d = good.n;
    bad[11].dp[0] |= 0x08;
    bad[12].dp[0] |= 0x80;
    for (&bad) |*x| try testing.expectError(error.KeyMismatch, S.SecretKey.fromComponents(x));

    // A generated key pair signs, but not once its halves don't match.
    var mixed = try S.KeyPair.generate(testing.io);
    try (try mixed.sign("message", testing.io)).verify("message", mixed.public_key);
    mixed.public_key = try .fromComponents(.{ .n = good.n, .e = good.e });
    try testing.expectError(error.KeyMismatch, mixed.sign("message", testing.io));
    try testing.expectError(error.KeyMismatch, mixed.signer(testing.io));
}

test "fault check" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const S = sign.RsaPkcs1v15(2048, sha2.Sha256);
    var components = try secretComponents(S.SecretKey.Components, (try parse(OpensslKey, arena_state.allocator(), "openssl.json"))[0]);
    const secret_key = try S.SecretKey.fromComponents(&components);
    const sk = &secret_key.key;
    var e_buf: [8]u8 = undefined;
    const e = core.exponentBytes(sk.public_key.e, &e_buf);
    const c: [S.modulus_length]u8 = @splat(0x42);
    const source: core.IoSource = .{ .io = testing.io };
    _ = try sk.rsadp(&c, source);
    // A wrong CRT exponent stands in for a hardware fault.
    var dp = sk.dp;
    dp.limbs_buffer[0] ^= 2;
    try testing.expectError(error.KeyMismatch, sk.rsadpWith(dp, sk.dq, e, &c, source));
    // A zeroed exponent too, with no exponent blinding to hide it, and base blinding factors of 1 at `.full`.
    const fixed_source = struct {
        pub fn squeeze(_: @This(), buf: []u8) void {
            @memset(buf, 0);
            const len = @TypeOf(sk.public_key.n).uniform_bytes_length;
            if (buf.len > 2 * len) {
                buf[len - 1] = 1;
                buf[2 * len - 1] = 1;
            }
        }
    }{};
    _ = try sk.rsadpWith(sk.dp, sk.dq, e, &c, fixed_source);
    try testing.expectError(error.KeyMismatch, sk.rsadpWith(.zero, sk.dq, e, &c, fixed_source));
}

test "PSS encoding steps 6 and 9" {
    const H = sha2.Sha256;
    const k = 256;
    var m_hash: [H.digest_length]u8 = undefined;
    H.hash("message", &m_hash, .{});
    var found_set = false;
    var salt: [H.digest_length]u8 = @splat(0);
    while (!found_set) : (salt[0] += 1) {
        const em = padding.pssEncode(H, k, &m_hash, &salt);
        // Stop at the first salt where the mask sets the top bit of DB, which verification has to clear.
        var db = em[0 .. k - H.digest_length - 1].*;
        padding.mgf1Xor(H, &db, em[k - H.digest_length - 1 ..][0..H.digest_length]);
        found_set = db[0] & 0x80 != 0;
        try testing.expect(padding.pssVerify(H, k, H.digest_length, &m_hash, em));
        var bad = em;
        bad[0] |= 0x80;
        try testing.expect(!padding.pssVerify(H, k, H.digest_length, &m_hash, bad));
    }
}

fn expectKey(comptime S: type, expected_hex: []const u8) !void {
    const c = (try S.KeyPair.generateDeterministic(std.simd.iota(u8, 32))).secret_key.toComponents();
    var h: [32]u8 = undefined;
    sha2.Sha256.hash(&(c.p ++ c.q ++ c.d), &h, .{});
    try testing.expectEqualSlices(u8, &try hexArray(32, expected_hex), &h);
}

// Known answers for version 1 of the derivation, over p, q and d, checked against an independent model.
test "deterministic key generation" {
    try expectKey(sign.RsaPss(2048, sha2.Sha256), "f1e27068c4917bfb09750fb10925a17de8c0e2697d0a528ae0e3e0187949d8c0");
    try expectKey(sign.RsaPss(2056, sha2.Sha256), "a7261bf20f28925ddff14932ce6ca305f3dcdb5791841aed048e68ddd54ada21");
    try expectKey(sign.RsaPkcs1v15(2048, sha2.Sha256), "01207473136231f944c37f31c0baac54bb1d98bd44d05f5f8aeefdc22ef1c36b");
    try expectKey(sign.BlindRsa(2048, .sha384_pss_randomized), "42e2b367c2eaba6ba2d2f7d9f1c898b002a416a9ac436ecc9a3850acc221f14e");
    // These are too slow for Debug builds.
    if (builtin.mode == .debug) return;
    try expectKey(sign.RsaPss(4096, sha2.Sha256), "44477b5635962dce243c57b9ce837a3c319ddaf39e7fe9ca2942c33cb60ed4d6");
    try expectKey(sign.PartiallyBlindRsa(2048, .sha384_pss_randomized), "5807bd0fdb8a1e7c96d9c646dcfa8ab29abe5543ea9169951e39c87139ca7f81");
}

const FuzzContext = struct {
    key: sign.RsaPss(2048, sha2.Sha256).KeyPair,
    kem_key: kem.RsaOaepKem(2048, sha2.Sha256).SecretKey,
};

fn fuzzOne(ctx: *const FuzzContext, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [4096]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    const S = sign.RsaPss(2048, sha2.Sha256);
    const B = sign.BlindRsa(2048, .sha384_pss_randomized);
    inline for (.{ S, B, kem.RsaKem(2048, sha2.Sha256) }) |T| {
        inline for (.{ .pkcs1, .spki }) |format| _ = T.PublicKey.fromDer(input, format) catch {};
        inline for (.{ .pkcs1, .pkcs8 }) |format| _ = T.SecretKey.fromDer(input, format) catch {};
        _ = T.PublicKey.fromPem(input) catch {};
        _ = T.SecretKey.fromPem(input) catch {};
    }
    inline for (.{ .pkcs1, .spki }) |format| _ = sign.modulusBitsFromDer(input, format) catch {};
    _ = sign.modulusBitsFromPem(input) catch {};
    if (input.len >= @sizeOf(S.SecretKey.Components)) {
        var c: S.SecretKey.Components = undefined;
        @memcpy(mem.asBytes(&c), input[0..@sizeOf(S.SecretKey.Components)]);
        _ = S.SecretKey.fromComponents(&c) catch {};
        _ = S.PublicKey.fromComponents(.{ .n = c.n, .e = c.e }) catch {};
    }
    if (input.len >= 256) {
        const bytes = input[0..256].*;
        S.Signature.fromBytes(bytes).verify(input[256..], ctx.key.public_key) catch {};
        _ = ctx.kem_key.decaps(&bytes, testing.io) catch {};
    }
}

test "fuzz the decoders and the public functions" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v = (try parse(OpensslKey, a, "openssl.json"))[0];
    var c = try secretComponents(sign.RsaPss(2048, sha2.Sha256).SecretKey.Components, v);
    const ctx: FuzzContext = .{
        .key = .fromSecretKey(try .fromComponents(&c)),
        .kem_key = try .fromComponents(&c),
    };
    var pem_buf: [4096]u8 = undefined;
    const seeds = [_][]const u8{
        try hex(a, v.pkcs1_pub_der),
        try hex(a, v.spki_der),
        try hex(a, v.pkcs1_priv_der),
        try hex(a, v.pkcs8_der),
        @import("pem.zig").encode(&pem_buf, .public_key, try hex(a, v.spki_der)),
        @embedFile("testdata/rsa2056_pkcs1_priv.pem"),
        @embedFile("testdata/rsa2048_pkcs8_encrypted.pem"),
    };
    // Smith.slice() reads a little-endian length before the bytes.
    var corpus: [seeds.len][]const u8 = undefined;
    for (&corpus, seeds) |*entry, seed| {
        entry.* = try mem.concat(a, u8, &.{ &mem.toBytes(mem.nativeToLittle(u32, @intCast(seed.len))), seed });
    }
    try testing.fuzz(&ctx, fuzzOne, .{ .corpus = &corpus });
}
