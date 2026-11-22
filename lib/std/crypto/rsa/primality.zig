//! Constant-time primality testing for key generation: trial division, Miller-Rabin, and a base-2 Fermat test.
//!
//! The candidates are secret, so the tests run in constant time for a candidate that passes.
//! A composite candidate can be rejected early, which only reveals something about a number that gets thrown away.

const std = @import("std");
const ff = std.crypto.ff;
const timing_safe = std.crypto.timing_safe;
const core = @import("core.zig");

// Barrett reduction of v modulo d, with mu = (2^64 - 1) / d, where the estimated quotient can be one too small.
fn barrettMod(v: u64, d: u64, mu: u64) u64 {
    // The high half of v * mu, using only 32x32-bit multiplications.
    const v0: u64 = @as(u32, @truncate(v));
    const v1 = v >> 32;
    const mu0: u64 = @as(u32, @truncate(mu));
    const mu1 = mu >> 32;
    const lo_hi = v0 * mu1;
    const hi_lo = v1 * mu0;
    const mid = ((v0 * mu0) >> 32) + @as(u32, @truncate(lo_hi)) + @as(u32, @truncate(hi_lo));
    const q = v1 * mu1 + (lo_hi >> 32) + (hi_lo >> 32) + (mid >> 32);
    const r = v - q * d;
    return r - (d & timing_safe.mask(u64, !timing_safe.lessThan(u64, r, d)));
}

/// Returns the remainder of a big-endian integer modulo a small divisor, in constant time.
pub fn remainder(bytes: []const u8, divisor: u32) u32 {
    const mu = std.math.maxInt(u64) / @as(u64, divisor);
    var i = bytes.len % 4;
    var r = barrettMod(std.mem.readVarInt(u64, bytes[0..i], .big), divisor, mu);
    while (i < bytes.len) : (i += 4) {
        r = barrettMod((r << 32) | std.mem.readInt(u32, bytes[i..][0..4], .big), divisor, mu);
    }
    return @intCast(r);
}

/// Returns whether a big-endian integer x is divisible by an odd prime up to `bound`, or, if `safe` is set, whether x or 2x + 1 is.
pub fn hasSmallFactor(x: []const u8, comptime bound: u32, comptime safe: bool) bool {
    // The odd primes up to `bound`, and their grouping into products that fit in 32 bits.
    const primes, const groups = comptime blk: {
        @setEvalBranchQuota(100_000_000);
        const Group = struct { product: u32, first: usize, count: usize };
        var primes: []const u64 = &.{};
        var groups: []const Group = &.{};
        var product: u64 = 1;
        var first: usize = 0;
        var c: u32 = 3;
        while (c <= bound) : (c += 2) {
            const is_prime = for (primes) |p| {
                if (p * p > c) break true;
                if (c % p == 0) break false;
            } else true;
            if (!is_prime) continue;
            if (product * c > std.math.maxInt(u32)) {
                groups = groups ++ [_]Group{.{ .product = product, .first = first, .count = primes.len - first }};
                product = 1;
                first = primes.len;
            }
            product *= c;
            primes = primes ++ [_]u64{c};
        }
        groups = groups ++ [_]Group{.{ .product = product, .first = first, .count = primes.len - first }};
        break :blk .{ primes[0..primes.len].*, groups[0..groups.len].* };
    };
    var found = false;
    for (groups) |g| {
        const r = remainder(x, g.product);
        for (primes[g.first..][0..g.count]) |p| {
            const rp = barrettMod(r, p, std.math.maxInt(u64) / p);
            found |= timing_safe.isZero(u64, rp);
            if (safe) {
                const t = 2 * rp + 1;
                found |= timing_safe.isZero(u64, timing_safe.select(u64, .fromBool(!timing_safe.lessThan(u64, t, p)), t -% p, t));
            }
        }
        if (timing_safe.valueBarrier(found)) return true;
    }
    return false;
}

/// Miller-Rabin test of an odd candidate `w` with exactly `bits` bits.
/// Each witness is 2 + (x mod (w - 3)), where x is read from `witnesses`, with 64 more bits than w.
/// It takes the same time for every candidate, except that it stops as soon as w is proven composite.
pub fn millerRabin(comptime M: type, w: anytype, bits: usize, rounds: usize, witnesses: anytype) bool {
    const U = @TypeOf(w);
    const X = ff.Uint(8 * (U.encoded_length + 8));

    var m = M.fromUintSecret(w, bits) catch unreachable;
    defer core.wipe(&m);
    var wm3 = w;
    defer core.wipe(&wm3);
    _ = wm3.subWithOverflow(U.fromPrimitive(u8, 3) catch unreachable);
    var witness_modulus = M.fromUintSecret(wm3, bits) catch unreachable;
    defer core.wipe(&witness_modulus);

    // w - 1 = 2^a * odd
    var odd = w;
    defer core.wipe(&odd);
    _ = odd.subWithOverflow(U.fromPrimitive(u8, 1) catch unreachable);
    const a = odd.trailingZeroBits();
    odd.shiftRight(a);
    var exponent: [U.encoded_length]u8 = undefined;
    odd.toBytes(&exponent, .big) catch unreachable;
    defer std.crypto.secureZero(u8, &exponent);

    var minus_one = m.subOne(m.zero);
    m.toMontgomery(&minus_one) catch unreachable;

    for (0..rounds) |_| {
        var x_bytes: [X.encoded_length]u8 = undefined;
        witnesses.squeeze(&x_bytes);
        var r = witness_modulus.reduce(X.fromBytes(&x_bytes, .big) catch unreachable);
        std.crypto.secureZero(u8, &x_bytes);
        var r_u = r.v.cast(U) catch unreachable;
        _ = r_u.addWithOverflow(U.fromPrimitive(u8, 2) catch unreachable);
        const b = m.reduce(r_u);
        core.wipe(&r);
        core.wipe(&r_u);

        var z = m.powWithEncodedExponent(b, &exponent, .big) catch unreachable;
        var probably_prime = m.isOne(z);
        m.toMontgomery(&z) catch unreachable;
        probably_prime |= z.eql(minus_one);
        for (1..bits) |j| {
            z = m.sq(z);
            probably_prime |= (timing_safe.lessThan(usize, j, a) & z.eql(minus_one));
            // Later squarings can't change the verdict, and a prime always has it set by now.
            if (timing_safe.valueBarrier(timing_safe.eql(usize, j, a) & !probably_prime)) break;
        }
        if (!probably_prime) return false;
    }
    return true;
}

/// Base-2 Fermat test of an odd candidate `w` with exactly `bits` bits.
pub fn fermatBase2(comptime M: type, w: anytype, bits: usize) bool {
    const U = @TypeOf(w);
    var m = M.fromUintSecret(w, bits) catch unreachable;
    defer core.wipe(&m);
    var wm1 = w;
    defer core.wipe(&wm1);
    _ = wm1.subWithOverflow(U.fromPrimitive(u8, 1) catch unreachable);
    var exponent: [U.encoded_length]u8 = undefined;
    wm1.toBytes(&exponent, .big) catch unreachable;
    defer std.crypto.secureZero(u8, &exponent);

    // Multiplying by 2 is just an addition, which is cheaper than a generic exponentiation.
    var z = m.one();
    m.toMontgomery(&z) catch unreachable;
    var i = bits;
    while (i > 0) {
        i -= 1;
        z = m.sq(z);
        const bit = (exponent[exponent.len - 1 - i / 8] >> @intCast(i % 8)) & 1;
        z.v.cmov(bit != 0, m.add(z, z).v);
    }
    return m.isOne(z);
}

// Witness streams that give the same witness for every round.
const FixedWitness = struct {
    x: u64,

    fn squeeze(self: *FixedWitness, buf: []u8) void {
        @memset(buf, 0);
        std.mem.writeInt(u64, buf[buf.len - 8 ..][0..8], self.x, .big);
    }
};

fn testMillerRabin(comptime bits: usize, w: u64, witness: u64) bool {
    var stream: FixedWitness = .{ .x = witness - 2 };
    const U = ff.Uint(bits);
    return millerRabin(ff.Modulus(bits), U.fromPrimitive(u64, w) catch unreachable, bits, 1, &stream);
}

test "Miller-Rabin" {
    // The strong liars of 221 = 13 * 17 in [2, 219] are exactly 21, 47, 174 and 200.
    for (2..220) |b| {
        const liar = b == 21 or b == 47 or b == 174 or b == 200;
        try std.testing.expectEqual(liar, testMillerRabin(8, 221, b));
    }
    // 3215031751 is a strong pseudoprime to the bases 2, 3, 5 and 7, but not 11.
    for ([_]u64{ 2, 3, 5, 7 }) |b| try std.testing.expect(testMillerRabin(32, 3215031751, b));
    try std.testing.expect(!testMillerRabin(32, 3215031751, 11));
    // Witnesses at both ends of the range, and a reduction modulo w - 3 that wraps around.
    const p: u64 = (1 << 61) - 1;
    for ([_]u64{ 2, p - 2, 1 << 60 }) |b| try std.testing.expect(testMillerRabin(61, p, b));
    var stream: FixedWitness = .{ .x = p - 3 };
    try std.testing.expect(millerRabin(ff.Modulus(61), ff.Uint(61).fromPrimitive(u64, p) catch unreachable, 61, 3, &stream));

    // 341 = 11 * 31 is a base-2 Fermat pseudoprime.
    try std.testing.expect(fermatBase2(ff.Modulus(9), ff.Uint(9).fromPrimitive(u16, 341) catch unreachable, 9));
    try std.testing.expect(fermatBase2(ff.Modulus(9), ff.Uint(9).fromPrimitive(u16, 509) catch unreachable, 9));
    try std.testing.expect(!fermatBase2(ff.Modulus(9), ff.Uint(9).fromPrimitive(u16, 511) catch unreachable, 9));
}

test "trial division" {
    const be = std.mem.nativeToBig;
    try std.testing.expect(hasSmallFactor(&std.mem.toBytes(be(u64, 3671 * 4294967291)), 3671, false));
    try std.testing.expect(!hasSmallFactor(&std.mem.toBytes(be(u64, 3673 * 4294967291)), 3671, false));
    try std.testing.expect(hasSmallFactor(&std.mem.toBytes(be(u64, 3673 * 4294967291)), 8161, false));
    try std.testing.expect(!hasSmallFactor(&std.mem.toBytes(be(u64, 4294967291)), 8161, false));
    // 2147620921 is prime, and 2 * 2147620921 + 1 is a multiple of 3.
    try std.testing.expect(!hasSmallFactor(&std.mem.toBytes(be(u64, 2147620921)), 8161, false));
    try std.testing.expect(hasSmallFactor(&std.mem.toBytes(be(u64, 2147620921)), 3, true));
    try std.testing.expect(!hasSmallFactor(&std.mem.toBytes(be(u64, 4294967291)), 8161, true));
    // A length that isn't a multiple of 4.
    try std.testing.expectEqual(1, remainder(&.{ 0x01, 0x00, 0x02 }, 65537));
}
