const std = @import("std");
const crypto = std.crypto;
const aes = crypto.core.aes;
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

pub const Aes128Ocb = AesOcb(aes.Aes128);
pub const Aes256Ocb = AesOcb(aes.Aes256);

const Block = [16]u8;

fn AesOcb(comptime Aes: anytype) type {
    const EncryptCtx = aes.AesEncryptCtx(Aes);
    const DecryptCtx = aes.AesDecryptCtx(Aes);

    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const nonce_length: usize = 12;
        pub const tag_length: usize = 16;

        const Lx = struct {
            star: Block align(16),
            dol: Block align(16),
            table: [56]Block align(16) = undefined,
            upto: usize,

            fn double(l: Block) callconv(.Inline) Block {
                const l_ = mem.readIntBig(u128, &l);
                const l_2 = (l_ << 1) ^ (0x87 & -%(l_ >> 127));
                var l2: Block = undefined;
                mem.writeIntBig(u128, &l2, l_2);
                return l2;
            }

            fn precomp(lx: *Lx, upto: usize) []const Block {
                const table = &lx.table;
                assert(upto < table.len);
                var i = lx.upto;
                while (i + 1 <= upto) : (i += 1) {
                    table[i + 1] = double(table[i]);
                }
                lx.upto = upto;
                return lx.table[0 .. upto + 1];
            }

            fn init(aes_enc_ctx: EncryptCtx) Lx {
                const zeros = [_]u8{0} ** 16;
                var star: Block = undefined;
                aes_enc_ctx.encrypt(&star, &zeros);
                const dol = double(star);
                var lx = Lx{ .star = star, .dol = dol, .upto = 0 };
                lx.table[0] = double(dol);
                return lx;
            }
        };

        fn hash(aes_enc_ctx: EncryptCtx, lx: *Lx, a: []const u8) Block {
            const full_blocks: usize = a.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            const lt = lx.precomp(x_max);
            var sum = [_]u8{0} ** 16;
            var offset = [_]u8{0} ** 16;
            var i: usize = 0;
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(usize, i + 1)]);
                var e = xorBlocks(offset, a[i * 16 ..][0..16].*);
                aes_enc_ctx.encrypt(&e, &e);
                xorWith(&sum, e);
            }
            const leftover = a.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var padded = [_]u8{0} ** 16;
                mem.copy(u8, padded[0..leftover], a[i * 16 ..][0..leftover]);
                padded[leftover] = 1;
                var e = xorBlocks(offset, padded);
                aes_enc_ctx.encrypt(&e, &e);
                xorWith(&sum, e);
            }
            return sum;
        }

        fn getOffset(aes_enc_ctx: EncryptCtx, npub: [nonce_length]u8) Block {
            var nx = [_]u8{0} ** 16;
            nx[0] = @intCast(u8, @truncate(u7, tag_length * 8) << 1);
            nx[16 - nonce_length - 1] = 1;
            mem.copy(u8, nx[16 - nonce_length ..], &npub);

            const bottom = @truncate(u6, nx[15]);
            nx[15] &= 0xc0;
            var ktop_: Block = undefined;
            aes_enc_ctx.encrypt(&ktop_, &nx);
            const ktop = mem.readIntBig(u128, &ktop_);
            var stretch = (@as(u192, ktop) << 64) | @as(u192, @truncate(u64, ktop >> 64) ^ @truncate(u64, ktop >> 56));
            var offset: Block = undefined;
            mem.writeIntBig(u128, &offset, @truncate(u128, stretch >> (64 - @as(u7, bottom))));
            return offset;
        }

        const has_aesni = comptime std.Target.x86.featureSetHas(std.Target.current.cpu.features, .aes);
        const wb: usize = if (std.Target.current.cpu.arch == .x86_64 and has_aesni) 4 else 0;

        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            assert(c.len == m.len);

            const aes_enc_ctx = Aes.initEnc(key);
            const full_blocks: usize = m.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            var lx = Lx.init(aes_enc_ctx);
            const lt = lx.precomp(x_max);

            var offset = getOffset(aes_enc_ctx, npub);
            var sum = [_]u8{0} ** 16;
            var i: usize = 0;

            while (wb > 0 and i + wb <= full_blocks) : (i += wb) {
                var offsets: [wb]Block align(16) = undefined;
                var es: [16 * wb]u8 align(16) = undefined;
                var j: usize = 0;
                while (j < wb) : (j += 1) {
                    xorWith(&offset, lt[@ctz(usize, i + 1 + j)]);
                    offsets[j] = offset;
                    const p = m[(i + j) * 16 ..][0..16].*;
                    mem.copy(u8, es[j * 16 ..][0..16], &xorBlocks(p, offsets[j]));
                    xorWith(&sum, p);
                }
                aes_enc_ctx.encryptWide(wb, &es, &es);
                j = 0;
                while (j < wb) : (j += 1) {
                    const e = es[j * 16 ..][0..16].*;
                    mem.copy(u8, c[(i + j) * 16 ..][0..16], &xorBlocks(e, offsets[j]));
                }
            }
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(usize, i + 1)]);
                const p = m[i * 16 ..][0..16].*;
                var e = xorBlocks(p, offset);
                aes_enc_ctx.encrypt(&e, &e);
                mem.copy(u8, c[i * 16 ..][0..16], &xorBlocks(e, offset));
                xorWith(&sum, p);
            }
            const leftover = m.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var pad = offset;
                aes_enc_ctx.encrypt(&pad, &pad);
                for (m[i * 16 ..]) |x, j| {
                    c[i * 16 + j] = pad[j] ^ x;
                }
                var e = [_]u8{0} ** 16;
                mem.copy(u8, e[0..leftover], m[i * 16 ..][0..leftover]);
                e[leftover] = 0x80;
                xorWith(&sum, e);
            }
            var e = xorBlocks(xorBlocks(sum, offset), lx.dol);
            aes_enc_ctx.encrypt(&e, &e);
            tag.* = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
        }

        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) !void {
            assert(c.len == m.len);

            const aes_enc_ctx = Aes.initEnc(key);
            const aes_dec_ctx = DecryptCtx.initFromEnc(aes_enc_ctx);
            const full_blocks: usize = m.len / 16;
            const x_max = if (full_blocks > 0) math.log2_int(usize, full_blocks) else 0;
            var lx = Lx.init(aes_enc_ctx);
            const lt = lx.precomp(x_max);

            var offset = getOffset(aes_enc_ctx, npub);
            var sum = [_]u8{0} ** 16;
            var i: usize = 0;

            while (wb > 0 and i + wb <= full_blocks) : (i += wb) {
                var offsets: [wb]Block align(16) = undefined;
                var es: [16 * wb]u8 align(16) = undefined;
                var j: usize = 0;
                while (j < wb) : (j += 1) {
                    xorWith(&offset, lt[@ctz(usize, i + 1 + j)]);
                    offsets[j] = offset;
                    const q = c[(i + j) * 16 ..][0..16].*;
                    mem.copy(u8, es[j * 16 ..][0..16], &xorBlocks(q, offsets[j]));
                }
                aes_dec_ctx.decryptWide(wb, &es, &es);
                j = 0;
                while (j < wb) : (j += 1) {
                    const p = xorBlocks(es[j * 16 ..][0..16].*, offsets[j]);
                    mem.copy(u8, m[(i + j) * 16 ..][0..16], &p);
                    xorWith(&sum, p);
                }
            }
            while (i < full_blocks) : (i += 1) {
                xorWith(&offset, lt[@ctz(usize, i + 1)]);
                const q = c[i * 16 ..][0..16].*;
                var e = xorBlocks(q, offset);
                aes_dec_ctx.decrypt(&e, &e);
                const p = xorBlocks(e, offset);
                mem.copy(u8, m[i * 16 ..][0..16], &p);
                xorWith(&sum, p);
            }
            const leftover = m.len % 16;
            if (leftover > 0) {
                xorWith(&offset, lx.star);
                var pad = offset;
                aes_enc_ctx.encrypt(&pad, &pad);
                for (c[i * 16 ..]) |x, j| {
                    m[i * 16 + j] = pad[j] ^ x;
                }
                var e = [_]u8{0} ** 16;
                mem.copy(u8, e[0..leftover], m[i * 16 ..][0..leftover]);
                e[leftover] = 0x80;
                xorWith(&sum, e);
            }
            var e = xorBlocks(xorBlocks(sum, offset), lx.dol);
            aes_enc_ctx.encrypt(&e, &e);
            var computed_tag = xorBlocks(e, hash(aes_enc_ctx, &lx, ad));
            const verify = crypto.utils.timingSafeEql([tag_length]u8, computed_tag, tag);
            crypto.utils.secureZero(u8, &computed_tag);
            if (!verify) {
                return error.AuthenticationFailed;
            }
        }
    };
}

fn xorBlocks(x: Block, y: Block) callconv(.Inline) Block {
    var z: Block = x;
    for (z) |*v, i| {
        v.* = x[i] ^ y[i];
    }
    return z;
}

fn xorWith(x: *Block, y: Block) callconv(.Inline) void {
    for (x) |*v, i| {
        v.* ^= y[i];
    }
}

test "AesOcb" {
    const hexToBytes = std.fmt.hexToBytes;

    var k: [Aes128Ocb.key_length]u8 = undefined;
    var nonce: [Aes128Ocb.nonce_length]u8 = undefined;
    var tag: [Aes128Ocb.tag_length]u8 = undefined;
    var m: [40]u8 = undefined;
    var c: [m.len]u8 = undefined;
    _ = try hexToBytes(&k, "000102030405060708090a0b0c0d0e0f");
    _ = try hexToBytes(&m, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");
    _ = try hexToBytes(&nonce, "BBAA9988776655443322110F");

    Aes128Ocb.encrypt(&c, &tag, &m, "", nonce, k);

    var expected_c: [c.len]u8 = undefined;
    var expected_tag: [tag.len]u8 = undefined;
    _ = try hexToBytes(&expected_tag, "479ad363ac366b95a98ca5f3000b1479");
    _ = try hexToBytes(&expected_c, "4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e");

    var m2: [m.len]u8 = undefined;
    try Aes128Ocb.decrypt(&m2, &c, tag, "", nonce, k);
    assert(mem.eql(u8, &m, &m2));
}
