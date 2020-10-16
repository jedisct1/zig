const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const TimingSafeEql = struct {
    fn generic(comptime T: type, comptime len: usize, a: [len]T, b: [len]T) bool {
        var z: T = 0;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            z |= a[i] ^ b[i];
            asm volatile (""
                :
                : [a] "rm" (a[i]),
                  [b] "rm" (b[i]),
                  [z] "rm" (z)
                : "memory"
            );
        }
        return z == 0;
    }
};

/// Compares two slices in constant time (for a given length) and returns whether they are equal.
/// This function was designed to compare short cryptographic secrets (MACs, signatures).
/// For all other applications, use mem.eql() instead.
pub fn timingSafeEql(comptime T: type, comptime len: usize, a: [len]T, b: [len]T) bool {
    comptime debug.assert(len > 0);

    return @call(.{ .modifier = .never_inline },  TimingSafeEql.generic, .{ T, len, a, b });
}

test "timingSafeEql" {
    var a: [256]u8 = undefined;
    var b: [256]u8 = undefined;
    comptime var i: usize = 1;
    inline while (i <= 256) : (i += 13) {
        crypto.randomBytes(a[0..i]) catch unreachable;
        crypto.randomBytes(b[0..i]) catch unreachable;
        if (mem.eql(u8, a[0..i], b[0..i])) {
            testing.expect(timingSafeEql(u8, i, a[0..i].*, b[0..i].*));
            a[0] ^= 0xff;
        }
        testing.expect(!timingSafeEql(u8, i, a[0..i].*, b[0..i].*));
        mem.copy(u8, a[0..i], b[0..i]);
        testing.expect(timingSafeEql(u8, i, a[0..i].*, b[0..i].*));
        a[0] +%= 1;
        testing.expect(!timingSafeEql(u8, i, a[0..i].*, b[0..i].*));
        a[0] = b[0];
        a[i - 1] -%= 1;
        testing.expect(!timingSafeEql(u8, i, a[0..i].*, b[0..i].*));
    }
}
