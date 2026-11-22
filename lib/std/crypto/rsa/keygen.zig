//! Key generation from a seed, version 1, based on FIPS 186-5 appendix A.1.3.
//!
//! This derivation is frozen: a seed must give the same key, or an error, in every later version.
//! With `label` naming the scheme, the size, and the hash or variant:
//!
//!     base         = seed || "std.crypto.rsa keygen v1 " || label
//!     candidates   = TurboSHAKE256(base, D = 0x01)
//!     witnesses(i) = TurboSHAKE256(base || 0x00 || I2OSP(i, 8), D = 0x02)
//!     final_check  = TurboSHAKE256(base, D = 0x03)
//!
//! Each candidate takes `prime_length` bytes of `candidates`, read as a big-endian integer.
//! The bits from the size of the prime upwards are cleared, then the two top bits and the low bit are set.
//! The candidate with index i, counting from 0 over the whole stream, takes its Miller-Rabin witnesses from `witnesses(i)`, each one as 2 + (x mod (w - 3)) from `prime_length + 8` bytes x.
//!
//! An ordinary prime p has `modulus_bits / 2` bits, and is rejected if p - 1 is a multiple of e, if a small odd prime divides it, or if it fails 5 Miller-Rabin rounds (4 from 1345 bits, 3 from 3747 bits).
//! Small primes go up to 3671, or 8161 for candidates of more than 1024 bits.
//! A safe prime p = 2p' + 1 is built from a candidate p' of `modulus_bits / 2 - 1` bits.
//! It is rejected if p' is a multiple of e, if a small odd prime divides p' or p, if p fails a base-2 Fermat test, or if p' fails 64 Miller-Rabin rounds.
//!
//! The second prime is rejected if |p - q| <= 2^(modulus_bits / 2 - 100).
//! The primes are ordered so that p > q, and d is e^-1 modulo lcm(p - 1, q - 1), or (p - 1) * (q - 1) for safe primes.
//! If d <= 2^(modulus_bits / 2), both primes are discarded, and the search goes on with the next candidates.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const timing_safe = crypto.timing_safe;
const core = @import("core.zig");
const primality = @import("primality.zig");
const wipe = core.wipe;
const TurboShake256 = crypto.hash.sha3.TurboShake256;

pub const seed_length = 32;
const e: u32 = 65537;

/// Returns the stream with the given domain, after the seed and label are absorbed.
pub fn stream(comptime domain: u7, seed: *const [seed_length]u8, label: []const u8) TurboShake256(domain) {
    var h = TurboShake256(domain).init(.{});
    h.update(seed);
    h.update("std.crypto.rsa keygen v1 ");
    h.update(label);
    return h;
}

/// Generates the components of a key, `R` being `core.Rsa(bits)`.
pub fn generate(comptime R: type, seed: *const [seed_length]u8, comptime label: []const u8, comptime safe_primes: bool) R.SecretComponents {
    const half = R.half_bits;
    const U = R.HalfUint;
    const one = U.fromPrimitive(u8, 1) catch unreachable;

    const Generator = struct {
        // The size of the candidates: p, or p' for safe primes.
        const bits = if (safe_primes) half - 1 else half;
        // The same trial division bound and Miller-Rabin rounds as BoringSSL.
        const trial_division_bound = if (bits <= 1024) 3671 else 8161;

        candidates: TurboShake256(0x01),
        witness_base: TurboShake256(0x02),
        index: u64 = 0,

        // Returns the next prime.
        fn next(gen: *@This()) U {
            while (true) {
                var bytes: [R.prime_length]u8 = undefined;
                defer wipe(&bytes);
                gen.candidates.squeeze(&bytes);
                const extra_bits = 8 * R.prime_length - bits;
                bytes[0] = (bytes[0] & (0xff >> extra_bits)) | (0xc0 >> extra_bits);
                bytes[R.prime_length - 1] |= 1;
                var x = U.fromBytes(&bytes, .big) catch unreachable;
                defer wipe(&x);
                const index = gen.index;
                gen.index += 1;

                // p - 1 must not be a multiple of e, which is 2x for a safe prime p = 2x + 1.
                if (timing_safe.eql(u32, primality.remainder(&bytes, e), if (safe_primes) 0 else 1)) continue;
                if (primality.hasSmallFactor(&bytes, trial_division_bound, safe_primes)) continue;
                var p = x;
                defer wipe(&p);
                if (safe_primes) {
                    _ = p.addWithOverflow(x);
                    p.setBit(0);
                    if (!primality.fermatBase2(R.P, p, half)) continue;
                }
                var w_stream = gen.witness_base;
                defer wipe(&w_stream);
                w_stream.update(&([_]u8{0} ++ mem.toBytes(mem.nativeToBig(u64, index))));
                const rounds = if (safe_primes) 64 else if (bits >= 3747) 3 else if (bits >= 1345) 4 else 5;
                if (!primality.millerRabin(R.P, x, bits, rounds, &w_stream)) continue;
                return p;
            }
        }
    };
    var gen: Generator = .{
        .candidates = stream(0x01, seed, label),
        .witness_base = stream(0x02, seed, label),
    };
    defer wipe(&gen);

    while (true) {
        var p = gen.next();
        defer wipe(&p);
        var q = gen.next();
        defer wipe(&q);
        // Draw q again until |p - q| > 2^(half - 100), revealing nothing else.
        while (true) {
            var diff = p;
            defer wipe(&diff);
            const borrow: bool = @bitCast(diff.subWithOverflow(q));
            var q_minus_p = q;
            defer wipe(&q_minus_p);
            _ = q_minus_p.subWithOverflow(p);
            diff.cmov(borrow, q_minus_p);
            const equal: bool = @bitCast(diff.subWithOverflow(one));
            diff.shiftRightPublic(half - 100);
            if (timing_safe.valueBarrier(!equal & !diff.isZero())) break;
            wipe(&q);
            q = gen.next();
        }
        timing_safe.conditionalSwap(@TypeOf(p.limbs_buffer), .fromBool(!q.lessThan(p)), &p.limbs_buffer, &q.limbs_buffer);

        var pm1 = p;
        _ = pm1.subWithOverflow(one);
        defer wipe(&pm1);
        var qm1 = q;
        _ = qm1.subWithOverflow(one);
        defer wipe(&qm1);

        var d = d: {
            if (safe_primes) {
                var phi = R.NUint.zero;
                _ = phi.mulAddWithOverflow(pm1.cast(R.NUint) catch unreachable, qm1.cast(R.NUint) catch unreachable);
                defer wipe(&phi);
                break :d phi.inverseOfSmall(e).?;
            }
            var l = pm1.lcm(qm1);
            defer wipe(&l);
            break :d l.inverseOfSmall(e).?.cast(R.NUint) catch unreachable;
        };
        defer wipe(&d);
        var d_min = R.NUint.zero;
        d_min.setBit(half);
        if (!d_min.lessThan(d)) continue;

        var c: R.SecretComponents = undefined;
        var n = R.NUint.zero;
        _ = n.mulAddWithOverflow(p.cast(R.NUint) catch unreachable, q.cast(R.NUint) catch unreachable);
        n.toBytes(&c.n, .big) catch unreachable;
        c.e = e;
        d.toBytes(&c.d, .big) catch unreachable;
        p.toBytes(&c.p, .big) catch unreachable;
        q.toBytes(&c.q, .big) catch unreachable;
        var dp = pm1.inverseOfSmall(e).?;
        defer wipe(&dp);
        dp.toBytes(&c.dp, .big) catch unreachable;
        var dq = qm1.inverseOfSmall(e).?;
        defer wipe(&dq);
        dq.toBytes(&c.dq, .big) catch unreachable;
        var pm = R.P.fromUintSecret(p, half) catch unreachable;
        defer wipe(&pm);
        var qinv = pm.invert(pm.reduce(q)).?;
        defer wipe(&qinv);
        qinv.toBytes(&c.qinv, .big) catch unreachable;
        return c;
    }
}
