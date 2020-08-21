// SPDX-License-Identifier: MIT
// Copyright (c) 2015-2020 Zig Contributors
// This file is part of [zig](https://ziglang.org/), which is MIT licensed.
// The MIT license requires this copyright notice to be included in all copies
// and substantial portions of the software.
const std = @import("std");
const mem = std.mem;

pub const Poly1305 = if (@sizeOf(usize) >= 8)
// Implementation optimized for 64-bit platforms using 3 limbs and 128-bit muls/adds
    struct {
        pub const block_size: usize = 16;
        pub const mac_length = 16;
        pub const minimum_key_length = 32;

        // constant multiplier (from the secret key)
        r: [3]u64,
        // accumulated hash
        h: [3]u64 = [_]u64{ 0, 0, 0 },
        // random number added at the end (from the secret key)
        pad: [2]u64,
        // how many bytes are waiting to be processed in a partial block
        leftover: usize = 0,
        // partial block buffer
        buf: [block_size]u8 align(16) = undefined,

        pub fn init(key: []const u8) Poly1305 {
            std.debug.assert(key.len >= minimum_key_length);
            const t0 = mem.readIntLittle(u64, key[0..8]);
            const t1 = mem.readIntLittle(u64, key[8..16]);
            return Poly1305{
                .r = [_]u64{
                    t0 & 0xffc0fffffff,
                    ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff,
                    ((t1 >> 24)) & 0x00ffffffc0f,
                },
                .pad = [_]u64{
                    mem.readIntLittle(u64, key[16..24]),
                    mem.readIntLittle(u64, key[24..32]),
                },
            };
        }

        fn blocks(st: *Poly1305, m: []const u8, last: comptime bool) void {
            const hibit: u64 = if (last) 0 else 1 << 40;
            const r0 = st.r[0];
            const r1 = st.r[1];
            const r2 = st.r[2];
            const s1 = r1 * (5 << 2);
            const s2 = r2 * (5 << 2);
            var i: usize = 0;
            while (i + block_size <= m.len) : (i += block_size) {
                // h += m[i]
                const t0 = mem.readIntLittle(u64, m[i..][0..8]);
                const t1 = mem.readIntLittle(u64, m[i + 8 ..][0..8]);
                st.h[0] += t0 & 0xfffffffffff;
                st.h[1] += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
                st.h[2] += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

                // h *= r
                const d0 = @as(u128, st.h[0]) * r0 + @as(u128, st.h[1]) * s2 + @as(u128, st.h[2]) * s1;
                var d1 = @as(u128, st.h[0]) * r1 + @as(u128, st.h[1]) * r0 + @as(u128, st.h[2]) * s2;
                var d2 = @as(u128, st.h[0]) * r2 + @as(u128, st.h[1]) * r1 + @as(u128, st.h[2]) * r0;

                // partial reduction
                var carry = d0 >> 44;
                st.h[0] = @truncate(u64, d0) & 0xfffffffffff;
                d1 += carry;
                carry = @intCast(u64, d1 >> 44);
                st.h[1] = @truncate(u64, d1) & 0xfffffffffff;
                d2 += carry;
                carry = @intCast(u64, d2 >> 42);
                st.h[2] = @truncate(u64, d2) & 0x3ffffffffff;
                st.h[0] += @truncate(u64, carry) * 5;
                carry = st.h[0] >> 44;
                st.h[0] &= 0xfffffffffff;
                st.h[1] += @truncate(u64, carry);
            }
        }

        pub fn update(st: *Poly1305, m: []const u8) void {
            var mb = m;

            // handle leftover
            if (st.leftover > 0) {
                const want = std.math.min(block_size - st.leftover, mb.len);
                const mc = mb[0..want];
                for (mc) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                mb = mb[want..];
                st.leftover += want;
                if (st.leftover > block_size) {
                    return;
                }
                st.blocks(&st.buf, false);
                st.leftover = 0;
            }

            // process full blocks
            if (mb.len >= block_size) {
                const want = mb.len & ~(block_size - 1);
                st.blocks(mb[0..want], false);
                mb = mb[want..];
            }

            // store leftover
            if (mb.len > 0) {
                for (mb) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                st.leftover += mb.len;
            }
        }

        pub fn final(st: *Poly1305, out: []u8) void {
            std.debug.assert(out.len >= mac_length);
            if (st.leftover > 0) {
                var i = st.leftover;
                st.buf[i] = 1;
                i += 1;
                while (i < block_size) : (i += 1) {
                    st.buf[i] = 0;
                }
                st.blocks(&st.buf, true);
            }
            // fully carry h
            var carry = st.h[1] >> 44;
            st.h[1] &= 0xfffffffffff;
            st.h[2] += carry;
            carry = st.h[2] >> 42;
            st.h[2] &= 0x3ffffffffff;
            st.h[0] += carry * 5;
            carry = st.h[0] >> 44;
            st.h[0] &= 0xfffffffffff;
            st.h[1] += carry;
            carry = st.h[1] >> 44;
            st.h[1] &= 0xfffffffffff;
            st.h[2] += carry;
            carry = st.h[2] >> 42;
            st.h[2] &= 0x3ffffffffff;
            st.h[0] += carry * 5;
            carry = st.h[0] >> 44;
            st.h[0] &= 0xfffffffffff;
            st.h[1] += carry;

            // compute h + -p
            var g0 = st.h[0] + 5;
            carry = g0 >> 44;
            g0 &= 0xfffffffffff;
            var g1 = st.h[1] + carry;
            carry = g1 >> 44;
            g1 &= 0xfffffffffff;
            var g2 = st.h[2] + carry -% (1 << 42);

            // (hopefully) constant-time select h if h < p, or h + -p if h >= p
            const mask = (g2 >> 63) -% 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            const nmask = ~mask;
            st.h[0] = (st.h[0] & nmask) | g0;
            st.h[1] = (st.h[1] & nmask) | g1;
            st.h[2] = (st.h[2] & nmask) | g2;

            // h = (h + pad)
            const t0 = st.pad[0];
            const t1 = st.pad[1];
            st.h[0] += (t0 & 0xfffffffffff);
            carry = (st.h[0] >> 44);
            st.h[0] &= 0xfffffffffff;
            st.h[1] += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + carry;
            carry = (st.h[1] >> 44);
            st.h[1] &= 0xfffffffffff;
            st.h[2] += (((t1 >> 24)) & 0x3ffffffffff) + carry;
            st.h[2] &= 0x3ffffffffff;

            // mac = h % (2^128)
            st.h[0] |= st.h[1] << 44;
            st.h[1] = (st.h[1] >> 20) | (st.h[2] << 24);

            mem.writeIntLittle(u64, out[0..8], st.h[0]);
            mem.writeIntLittle(u64, out[8..16], st.h[1]);

            std.mem.secureZero(u8, @ptrCast([*]u8, st)[0..@sizeOf(Poly1305)]);
        }

        pub fn create(out: []u8, msg: []const u8, key: []const u8) void {
            std.debug.assert(out.len >= mac_length);
            std.debug.assert(key.len >= minimum_key_length);

            var st = Poly1305.init(key);
            st.update(msg);
            st.final(out);
        }
    }
else
// 32-bit version using 5 limbs
    struct {
        pub const block_size: usize = 16;
        pub const mac_length = 16;
        pub const minimum_key_length = 32;

        // constant multiplier (from the secret key)
        r: [5]u32,
        // accumulated hash
        h: [5]u32 = [_]u32{ 0, 0, 0, 0, 0 },
        // random number added at the end (from the secret key)
        pad: [4]u32,
        // how many bytes are waiting to be processed in a partial block
        leftover: usize = 0,
        // partial block buffer
        buf: [block_size]u8 align(16) = undefined,

        pub fn init(key: []const u8) Poly1305 {
            std.debug.assert(key.len >= minimum_key_length);
            return Poly1305{
                .r = [_]u32{
                    mem.readIntLittle(u32, key[0..4]) & 0x3ffffff,
                    (mem.readIntLittle(u32, key[3..7]) >> 2) & 0x3ffff03,
                    (mem.readIntLittle(u32, key[6..10]) >> 4) & 0x3ffc0ff,
                    (mem.readIntLittle(u32, key[9..13]) >> 6) & 0x3f03fff,
                    (mem.readIntLittle(u32, key[12..16]) >> 8) & 0x00fffff,
                },
                .pad = [_]u32{
                    mem.readIntLittle(u32, key[16..20]),
                    mem.readIntLittle(u32, key[20..24]),
                    mem.readIntLittle(u32, key[24..28]),
                    mem.readIntLittle(u32, key[28..32]),
                },
            };
        }

        fn blocks(st: *Poly1305, m: []const u8, last: comptime bool) void {
            const hibit: u32 = if (last) 0 else 1 << 24;
            const r0 = st.r[0];
            const r1 = st.r[1];
            const r2 = st.r[2];
            const r3 = st.r[3];
            const r4 = st.r[4];
            const s1 = r1 * 5;
            const s2 = r2 * 5;
            const s3 = r3 * 5;
            const s4 = r4 * 5;
            var i: usize = 0;
            while (i + block_size <= m.len) : (i += block_size) {
                // h += m[i]
                st.h[0] += mem.readIntLittle(u32, m[i..][0..4]) & 0x3ffffff;
                st.h[1] += (mem.readIntLittle(u32, m[i + 3 ..][0..4]) >> 2) & 0x3ffffff;
                st.h[2] += (mem.readIntLittle(u32, m[i + 6 ..][0..4]) >> 4) & 0x3ffffff;
                st.h[3] += (mem.readIntLittle(u32, m[i + 9 ..][0..4]) >> 6) & 0x3ffffff;
                st.h[4] += (mem.readIntLittle(u32, m[i + 12 ..][0..4]) >> 8) | hibit;

                // h *= r
                const d0 = (@as(u64, st.h[0]) * r0) + (@as(u64, st.h[1]) * s4) + (@as(u64, st.h[2]) * s3) + (@as(u64, st.h[3]) * s2) + (@as(u64, st.h[4]) * s1);
                var d1 = (@as(u64, st.h[0]) * r1) + (@as(u64, st.h[1]) * r0) + (@as(u64, st.h[2]) * s4) + (@as(u64, st.h[3]) * s3) + (@as(u64, st.h[4]) * s2);
                var d2 = (@as(u64, st.h[0]) * r2) + (@as(u64, st.h[1]) * r1) + (@as(u64, st.h[2]) * r0) + (@as(u64, st.h[3]) * s4) + (@as(u64, st.h[4]) * s3);
                var d3 = (@as(u64, st.h[0]) * r3) + (@as(u64, st.h[1]) * r2) + (@as(u64, st.h[2]) * r1) + (@as(u64, st.h[3]) * r0) + (@as(u64, st.h[4]) * s4);
                var d4 = (@as(u64, st.h[0]) * r4) + (@as(u64, st.h[1]) * r3) + (@as(u64, st.h[2]) * r2) + (@as(u64, st.h[3]) * r1) + (@as(u64, st.h[4]) * r0);

                // partial reduction
                var carry = @truncate(u32, d0 >> 26);
                st.h[0] = @truncate(u32, d0) & 0x3ffffff;
                d1 += carry;
                carry = @truncate(u32, d1 >> 26);
                st.h[1] = @truncate(u32, d1) & 0x3ffffff;
                d2 += carry;
                carry = @truncate(u32, d2 >> 26);
                st.h[2] = @truncate(u32, d2) & 0x3ffffff;
                d3 += carry;
                carry = @truncate(u32, d3 >> 26);
                st.h[3] = @truncate(u32, d3) & 0x3ffffff;
                d4 += carry;
                carry = @truncate(u32, d4 >> 26);
                st.h[4] = @truncate(u32, d4) & 0x3ffffff;
                st.h[0] += carry * 5;
                carry = st.h[0] >> 26;
                st.h[0] &= 0x3ffffff;
                st.h[1] += carry;
            }
        }

        pub fn update(st: *Poly1305, m: []const u8) void {
            var mb = m;

            // handle leftover
            if (st.leftover > 0) {
                const want = std.math.min(block_size - st.leftover, mb.len);
                const mc = mb[0..want];
                for (mc) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                mb = mb[want..];
                st.leftover += want;
                if (st.leftover > block_size) {
                    return;
                }
                st.blocks(&st.buf, false);
                st.leftover = 0;
            }

            // process full blocks
            if (mb.len >= block_size) {
                const want = mb.len & ~(block_size - 1);
                st.blocks(mb[0..want], false);
                mb = mb[want..];
            }

            // store leftover
            if (mb.len > 0) {
                for (mb) |x, i| {
                    st.buf[st.leftover + i] = x;
                }
                st.leftover += mb.len;
            }
        }

        pub fn final(st: *Poly1305, out: []u8) void {
            std.debug.assert(out.len >= mac_length);
            if (st.leftover > 0) {
                var i = st.leftover;
                st.buf[i] = 1;
                i += 1;
                while (i < block_size) : (i += 1) {
                    st.buf[i] = 0;
                }
                st.blocks(&st.buf, true);
            }

            // fully carry h
            var carry = st.h[1] >> 26;
            st.h[1] = st.h[1] & 0x3ffffff;
            st.h[2] += carry;
            carry = st.h[2] >> 26;
            st.h[2] = st.h[2] & 0x3ffffff;
            st.h[3] += carry;
            carry = st.h[3] >> 26;
            st.h[3] = st.h[3] & 0x3ffffff;
            st.h[4] += carry;
            carry = st.h[4] >> 26;
            st.h[4] = st.h[4] & 0x3ffffff;
            st.h[0] += carry * 5;
            carry = st.h[0] >> 26;
            st.h[0] = st.h[0] & 0x3ffffff;
            st.h[1] += carry;

            // compute h + -p
            var g0 = st.h[0] + 5;
            carry = g0 >> 26;
            g0 &= 0x3ffffff;
            var g1 = st.h[1] + carry;
            carry = g1 >> 26;
            g1 &= 0x3ffffff;
            var g2 = st.h[2] + carry;
            carry = g2 >> 26;
            g2 &= 0x3ffffff;
            var g3 = st.h[3] + carry;
            carry = g3 >> 26;
            g3 &= 0x3ffffff;
            var g4 = st.h[4] + carry -% (1 << 26);

            // (hopefully) constant-time select h if h < p, or h + -p if h >= p
            const mask = (g4 >> 31) -% 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            const nmask = ~mask;
            st.h[0] = (st.h[0] & nmask) | g0;
            st.h[1] = (st.h[1] & nmask) | g1;
            st.h[2] = (st.h[2] & nmask) | g2;
            st.h[3] = (st.h[3] & nmask) | g3;
            st.h[4] = (st.h[4] & nmask) | g4;

            // mac = h % (2^128)
            st.h[0] = (st.h[0] | (st.h[1] << 26)) & 0xffffffff;
            st.h[1] = ((st.h[1] >> 6) | (st.h[2] << 20)) & 0xffffffff;
            st.h[2] = ((st.h[2] >> 12) | (st.h[3] << 14)) & 0xffffffff;
            st.h[3] = ((st.h[3] >> 18) | (st.h[4] << 8)) & 0xffffffff;

            // h = (h + pad)
            var f = @as(u64, st.h[0]) + st.pad[0];
            st.h[0] = @truncate(u32, f);
            f = @as(u64, st.h[1]) + st.pad[1] + (f >> 32);
            st.h[1] = @truncate(u32, f);
            f = @as(u64, st.h[2]) + st.pad[2] + (f >> 32);
            st.h[2] = @truncate(u32, f);
            f = @as(u64, st.h[3]) + st.pad[3] + (f >> 32);
            st.h[3] = @truncate(u32, f);

            mem.writeIntLittle(u32, out[0..4], st.h[0]);
            mem.writeIntLittle(u32, out[4..8], st.h[1]);
            mem.writeIntLittle(u32, out[8..12], st.h[2]);
            mem.writeIntLittle(u32, out[12..16], st.h[3]);

            std.mem.secureZero(u8, @ptrCast([*]u8, st)[0..@sizeOf(Poly1305)]);
        }

        pub fn create(out: []u8, msg: []const u8, key: []const u8) void {
            std.debug.assert(out.len >= mac_length);
            std.debug.assert(key.len >= minimum_key_length);

            var st = Poly1305.init(key);
            st.update(msg);
            st.final(out);
        }
    };

test "poly1305 rfc7439 vector1" {
    const expected_mac = "\xa8\x06\x1d\xc1\x30\x51\x36\xc6\xc2\x2b\x8b\xaf\x0c\x01\x27\xa9";

    const msg = "Cryptographic Forum Research Group";
    const key = "\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8" ++
        "\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b";

    var mac: [16]u8 = undefined;
    Poly1305.create(mac[0..], msg, key);

    std.testing.expectEqualSlices(u8, expected_mac, &mac);
}
