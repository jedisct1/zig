//! The paddings of RFC 8017, for moduli whose size is a multiple of 8.
//!
//! With such a modulus, the encoded message is as long as the modulus, and its top bit is always cleared.

const std = @import("std");
const mem = std.mem;
const timing_safe = std.crypto.timing_safe;
const core = @import("core.zig");
const der = @import("der.zig");

/// XORs MGF1(seed, out.len) into `out`.
pub fn mgf1Xor(comptime H: type, out: []u8, seed: []const u8) void {
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < out.len) : (counter += 1) {
        var h = H.init(.{});
        h.update(seed);
        h.update(&mem.toBytes(mem.nativeToBig(u32, counter)));
        var mask: [H.digest_length]u8 = undefined;
        h.final(&mask);
        core.wipe(&h);
        const len = @min(mask.len, out.len - i);
        for (out[i..][0..len], mask[0..len]) |*o, m| o.* ^= m;
        std.crypto.secureZero(u8, &mask);
        i += len;
    }
}

fn pssHash(comptime H: type, m_hash: *const [H.digest_length]u8, salt: []const u8, out: *[H.digest_length]u8) void {
    var h = H.init(.{});
    h.update(&@as([8]u8, @splat(0)));
    h.update(m_hash);
    h.update(salt);
    h.final(out);
}

/// EMSA-PSS-ENCODE, given the hash of the message.
pub fn pssEncode(comptime H: type, comptime k: usize, m_hash: *const [H.digest_length]u8, salt: []const u8) [k]u8 {
    const db_len = k - H.digest_length - 1;
    std.debug.assert(db_len >= salt.len + 1);
    var em: [k]u8 = @splat(0);
    pssHash(H, m_hash, salt, em[db_len..][0..H.digest_length]);
    em[db_len - salt.len - 1] = 0x01;
    @memcpy(em[db_len - salt.len .. db_len], salt);
    mgf1Xor(H, em[0..db_len], em[db_len..][0..H.digest_length]);
    em[0] &= 0x7f;
    em[k - 1] = 0xbc;
    return em;
}

/// EMSA-PSS-VERIFY, given the hash of the message and a fixed salt length.
pub fn pssVerify(comptime H: type, comptime k: usize, comptime salt_length: usize, m_hash: *const [H.digest_length]u8, em: [k]u8) bool {
    const h_len = H.digest_length;
    const db_len = k - h_len - 1;
    comptime std.debug.assert(db_len >= salt_length + 1);
    // Step 6: the top bit of maskedDB must be clear.
    var ok = timing_safe.eql(u8, em[k - 1], 0xbc) & timing_safe.isZero(u8, em[0] & 0x80);
    var db = em[0..db_len].*;
    const h = em[db_len..][0..h_len];
    mgf1Xor(H, &db, h);
    // Step 9: clear the top bit of DB, which the mask may have set.
    db[0] &= 0x7f;
    ok &= timing_safe.isZero([]const u8, db[0 .. db_len - salt_length - 1]);
    ok &= timing_safe.eql(u8, db[db_len - salt_length - 1], 0x01);
    var expected: [h_len]u8 = undefined;
    pssHash(H, m_hash, db[db_len - salt_length ..], &expected);
    ok &= timing_safe.eql([h_len]u8, expected, h.*);
    return ok;
}

/// EMSA-PKCS1-v1_5-ENCODE: 0x00 || 0x01 || 0xff... || 0x00 || DigestInfo.
pub fn pkcs1v15Encode(comptime H: type, comptime k: usize, m_hash: *const [H.digest_length]u8) [k]u8 {
    const prefix = comptime der.digestInfoPrefix(core.hashId(H));
    const t_len = prefix.len + H.digest_length;
    comptime std.debug.assert(k >= t_len + 11);
    var em: [k]u8 = @splat(0xff);
    em[0..2].* = .{ 0x00, 0x01 };
    em[k - t_len - 1] = 0x00;
    @memcpy(em[k - t_len ..][0..prefix.len], prefix);
    em[k - H.digest_length ..].* = m_hash.*;
    return em;
}

/// EME-OAEP encoding of a 32-byte message with an empty label.
pub fn oaepEncode(comptime H: type, comptime k: usize, msg: *const [32]u8, seed: *const [H.digest_length]u8) [k]u8 {
    const h_len = H.digest_length;
    const db_len = k - h_len - 1;
    comptime std.debug.assert(k >= 2 * h_len + 2 + 32);
    var em: [k]u8 = @splat(0);
    const db = em[1 + h_len ..];
    H.hash("", db[0..h_len], .{});
    db[db_len - 33] = 0x01;
    db[db_len - 32 ..].* = msg.*;
    mgf1Xor(H, db, seed);
    const masked_seed = em[1..][0..h_len];
    masked_seed.* = seed.*;
    mgf1Xor(H, masked_seed, db);
    return em;
}

/// EME-OAEP decoding of a 32-byte message with an empty label.
/// The message is always read from the same place, and validity is a single flag computed in constant time.
pub fn oaepDecode(comptime H: type, comptime k: usize, em: *const [k]u8, msg: *[32]u8) bool {
    const h_len = H.digest_length;
    const db_len = k - h_len - 1;
    var seed = em[1..][0..h_len].*;
    var db = em[1 + h_len ..][0..db_len].*;
    defer std.crypto.secureZero(u8, &seed);
    defer std.crypto.secureZero(u8, &db);
    mgf1Xor(H, &seed, &db);
    mgf1Xor(H, &db, &seed);
    var l_hash: [h_len]u8 = undefined;
    H.hash("", &l_hash, .{});
    const valid = timing_safe.isZero(u8, em[0]) &
        timing_safe.eql([h_len]u8, l_hash, db[0..h_len].*) &
        timing_safe.isZero([]const u8, db[h_len .. db_len - 33]) &
        timing_safe.eql(u8, db[db_len - 33], 0x01);
    msg.* = db[db_len - 32 ..].*;
    // Keeps the compiler from turning the checks above into separate branches.
    return timing_safe.valueBarrier(valid);
}
