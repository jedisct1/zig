const std = @import("std");
const assert = std.debug.assert;
const builtin = std.builtin;
const crypto = std.crypto;
const debug = std.debug;
const Ghash = std.crypto.onetimeauth.Ghash;
const mem = std.mem;
const modes = crypto.core.modes;

pub fn AESGCM(comptime AES: anytype) type {
    debug.assert(AES.block.block_size == 16);

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = AES.key_bits / 8;

        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            debug.assert(c.len == m.len);
            const aes = AES.initEnc(key);

            var h: [16]u8 = undefined;
            var bc = [_]u8{0} ** 16;
            aes.encrypt(&h, &bc);

            var t: [16]u8 = undefined;
            var j: [16]u8 = undefined;
            mem.copy(u8, j[0..nonce_length], npub[0..]);
            mem.writeIntBig(u32, j[nonce_length..][0..4], 1);
            aes.encrypt(&t, &j);

            var mac = Ghash.init(&h);
            mac.update(ad);
            bc[15] |= 1;
            modes.ctr(@TypeOf(aes), aes, c, m, bc, builtin.Endian.Big);
            mac.update(c[0..m.len][0..]);

            var final_block = h;
            mem.writeIntBig(u64, final_block[0..8], ad.len);
            mem.writeIntBig(u64, final_block[8..16], m.len);
            mac.update(&final_block);
            mac.final(tag);
            for (t) |x, i| {
                tag[i] ^= x;
            }
        }
    };
}

const htest = @import("test.zig");
const testing = std.testing;

test "AES256GCM 1" {
    const AEAD = AESGCM(crypto.core.aes.AES256);
    const key: [AEAD.key_length]u8 = [_]u8{0x69} ** AEAD.key_length;
    const nonce: [AEAD.nonce_length]u8 = [_]u8{0x42} ** AEAD.nonce_length;
    const ad = "";
    const m = "";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [AEAD.tag_length]u8 = undefined;

    AEAD.encrypt(&c, &tag, m, ad, nonce, key);
    std.debug.print("{x}\n", .{tag});

    htest.assertEqual("6b6ff610a16fa4cd59f1fb7903154e92", &tag);
}

test "AES256GCM 2" {
    const AEAD = AESGCM(crypto.core.aes.AES256);
    const key: [AEAD.key_length]u8 = [_]u8{0x69} ** AEAD.key_length;
    const nonce: [AEAD.nonce_length]u8 = [_]u8{0x42} ** AEAD.nonce_length;
    const m = "";
    const ad = "testtesttesttest";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [AEAD.tag_length]u8 = undefined;

    AEAD.encrypt(&c, &tag, m, ad, nonce, key);
    std.debug.print("{x}\n", .{tag});

    htest.assertEqual("6b6ff610a16fa4cd59f1fb7903154e92", &tag);
}
