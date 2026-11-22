//! Strict, allocation-free DER encoding and decoding of RSA keys.
//!
//! Only what RSA keys need is supported: RSAPublicKey and RSAPrivateKey (PKCS #1), SubjectPublicKeyInfo, PKCS #8 PrivateKeyInfo, and RSASSA-PSS parameters.
//!
//! Inputs must be strict DER: minimal lengths and integers, no negative integers, and no trailing data.
//! PKCS #8 attribute values are the exception: their types are unknown, so only their structure is checked, not their contents or the order of the sets inside them.

const std = @import("std");
const mem = std.mem;
const EncodingError = std.crypto.errors.EncodingError;

pub const HashId = enum { sha256, sha384, sha512 };

/// RSASSA-PSS parameters, restricted to a SHA-2 hash that MGF1 uses too, and no trailer field.
pub const PssParams = struct {
    hash: HashId,
    /// For keys, this is the minimum salt length.
    salt_length: u32,
};

/// The algorithm identifier of a key in SubjectPublicKeyInfo and PKCS #8.
pub const Algorithm = union(enum) {
    rsa_encryption,
    rsa_kem,
    /// `null` when the parameters are absent, which doesn't restrict the key.
    rsassa_pss: ?PssParams,
};

pub const PublicKeyFormat = enum(u8) { pkcs1, spki, _ };
pub const SecretKeyFormat = enum(u8) { pkcs1, pkcs8, _ };

const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
const oid_rsassa_pss = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
const oid_mgf1 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08 };
const oid_rsa_kem = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x0e };
const oid_hashes = [_][9]u8{
    .{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 },
    .{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 },
    .{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 },
};
const null_params = [_]u8{ 0x05, 0x00 };
const version_zero = [_]u8{ 0x02, 0x01, 0x00 };

const tag_integer = 0x02;
const tag_bit_string = 0x03;
const tag_octet_string = 0x04;
const tag_null = 0x05;
const tag_oid = 0x06;
const tag_sequence = 0x30;
const tag_set = 0x31;

/// The largest PKCS #8 attributes accepted, in bytes.
pub const attributes_length_max = 1024;

// The largest algorithm identifier that is accepted: id-RSASSA-PSS with all the fields and NULL hash parameters.
const algorithm_length_max = 80;

/// The DER encoding of DigestInfo, without the digest itself.
pub fn digestInfoPrefix(comptime hash: HashId) []const u8 {
    const oid = oid_hashes[@backingInt(hash)];
    const digest_length = ([_]u8{ 32, 48, 64 })[@backingInt(hash)];
    const alg = [_]u8{ tag_sequence, oid.len + 4, tag_oid, oid.len } ++ oid ++ null_params;
    return &([_]u8{ tag_sequence, alg.len + 2 + digest_length } ++ alg ++ [_]u8{ tag_octet_string, digest_length });
}

/// Largest encoding of a public key, in either format.
pub fn publicKeyLengthMax(comptime modulus_length: usize) usize {
    // SubjectPublicKeyInfo, with a 4-byte header for the sequence, the bit string and the modulus.
    return 4 + algorithm_length_max + 5 + 4 + (4 + 1 + modulus_length) + (2 + 9);
}

/// Largest encoding of a secret key, in either format, without PKCS #8 attributes.
pub fn secretKeyLengthMax(comptime modulus_length: usize, comptime prime_length: usize) usize {
    const rsa_private_key = 4 + 3 + 2 * (4 + 1 + modulus_length) + (2 + 9) + 5 * (4 + 1 + prime_length);
    return 4 + 3 + algorithm_length_max + 4 + rsa_private_key;
}

const Parser = struct {
    bytes: []const u8,
    pos: usize = 0,
    // The end of the innermost element entered with enterLimited(), which can be past the available bytes.
    limit: usize = std.math.maxInt(usize),

    // Reads the header of an element, and limits what follows to its contents, which don't have to be all there.
    fn enterLimited(p: *Parser, tag: u8) EncodingError!usize {
        const len = try p.enter(tag);
        if (len > p.limit - p.pos) return error.InvalidEncoding;
        p.limit = p.pos + len;
        p.bytes = p.bytes[0..@min(p.bytes.len, p.limit)];
        return len;
    }

    // Reads the header of an element with the given tag, and returns the length of its contents, without checking that they are all there.
    fn enter(p: *Parser, tag: u8) EncodingError!usize {
        if (p.pos >= p.bytes.len or p.bytes[p.pos] != tag) return error.InvalidEncoding;
        p.pos += 1;
        return p.length();
    }

    fn length(p: *Parser) EncodingError!usize {
        if (p.pos >= p.bytes.len) return error.InvalidEncoding;
        var len: usize = p.bytes[p.pos];
        p.pos += 1;
        if (len < 0x80) return len;
        const len_len = len & 0x7f;
        if (len_len == 0 or len_len > 2 or p.bytes.len - p.pos < len_len) return error.InvalidEncoding;
        len = mem.readVarInt(usize, p.bytes[p.pos..][0..len_len], .big);
        p.pos += len_len;
        if (len < 0x80 or (len_len == 2 and len < 0x100)) return error.InvalidEncoding;
        return len;
    }

    fn element(p: *Parser, tag: u8) EncodingError![]const u8 {
        const len = try p.enter(tag);
        if (p.bytes.len - p.pos < len) return error.InvalidEncoding;
        defer p.pos += len;
        return p.bytes[p.pos..][0..len];
    }

    // Returns the big-endian bytes of a nonnegative integer, without the sign byte.
    fn unsigned(p: *Parser) EncodingError![]const u8 {
        const c = try p.element(tag_integer);
        if (c.len == 0 or c[0] & 0x80 != 0) return error.InvalidEncoding;
        if (c.len == 1 or c[0] != 0) return c;
        if (c[1] & 0x80 == 0) return error.InvalidEncoding;
        return c[1..];
    }

    // Reads a nonnegative integer into a fixed-size, big-endian array.
    fn integer(p: *Parser, out: []u8) EncodingError!void {
        const c = try p.unsigned();
        if (c.len > out.len) return error.InvalidEncoding;
        @memset(out[0 .. out.len - c.len], 0);
        @memcpy(out[out.len - c.len ..], c);
    }

    // Reads a nonnegative integer, saturated to 64 bits.
    fn saturatedU64(p: *Parser) EncodingError!u64 {
        const c = try p.unsigned();
        if (c.len > 8) return std.math.maxInt(u64);
        return mem.readVarInt(u64, c, .big);
    }

    // Reads the identifier of a SHA-2 hash, with absent or NULL parameters.
    fn hashId(p: *Parser) EncodingError!HashId {
        var s: Parser = .{ .bytes = try p.element(tag_sequence) };
        const oid = try s.element(tag_oid);
        if (s.pos < s.bytes.len and (try s.element(tag_null)).len != 0) return error.InvalidEncoding;
        if (s.pos != s.bytes.len) return error.InvalidEncoding;
        for (oid_hashes, 0..) |h, i| {
            if (mem.eql(u8, oid, &h)) return @fromBackingInt(@intCast(i));
        }
        return error.InvalidEncoding;
    }

    fn algorithm(p: *Parser) EncodingError!Algorithm {
        var s: Parser = .{ .bytes = try p.element(tag_sequence) };
        const oid = try s.element(tag_oid);
        const alg: Algorithm = if (mem.eql(u8, oid, &oid_rsa_encryption)) alg: {
            if ((try s.element(tag_null)).len != 0) return error.InvalidEncoding;
            break :alg .rsa_encryption;
        } else if (mem.eql(u8, oid, &oid_rsa_kem))
            .rsa_kem
        else if (!mem.eql(u8, oid, &oid_rsassa_pss))
            return error.InvalidEncoding
        else if (s.pos == s.bytes.len)
            .{ .rsassa_pss = null }
        else alg: {
            // The hash and the mask generation function don't have usable defaults (SHA-1), so they are required.
            // The trailer field must be absent, as in BoringSSL's key parser.
            var params: Parser = .{ .bytes = try s.element(tag_sequence) };
            var f: Parser = .{ .bytes = try params.element(0xa0) };
            const hash = try f.hashId();
            if (f.pos != f.bytes.len) return error.InvalidEncoding;
            f = .{ .bytes = try params.element(0xa1) };
            var mgf: Parser = .{ .bytes = try f.element(tag_sequence) };
            if (!mem.eql(u8, try mgf.element(tag_oid), &oid_mgf1)) return error.InvalidEncoding;
            if (try mgf.hashId() != hash) return error.InvalidEncoding;
            if (mgf.pos != mgf.bytes.len or f.pos != f.bytes.len) return error.InvalidEncoding;
            var salt_length: u32 = 20;
            if (params.pos < params.bytes.len) {
                f = .{ .bytes = try params.element(0xa2) };
                salt_length = std.math.cast(u32, try f.saturatedU64()) orelse return error.InvalidEncoding;
                // DER forbids encoding the default value.
                if (salt_length == 20 or f.pos != f.bytes.len) return error.InvalidEncoding;
            }
            if (params.pos != params.bytes.len) return error.InvalidEncoding;
            break :alg .{ .rsassa_pss = .{ .hash = hash, .salt_length = salt_length } };
        };
        if (s.pos != s.bytes.len) return error.InvalidEncoding;
        return alg;
    }

    fn rsaPublicKey(p: *Parser, c: anytype) EncodingError!void {
        var s: Parser = .{ .bytes = try p.element(tag_sequence) };
        try s.integer(&c.n);
        // An exponent that doesn't fit is saturated, and rejected later as weak.
        c.e = try s.saturatedU64();
        if (s.pos != s.bytes.len) return error.InvalidEncoding;
    }

    fn rsaPrivateKey(p: *Parser, c: anytype) EncodingError!void {
        var s: Parser = .{ .bytes = try p.element(tag_sequence) };
        if (!mem.eql(u8, try s.element(tag_integer), &.{0})) return error.InvalidEncoding;
        try s.integer(&c.n);
        c.e = try s.saturatedU64();
        inline for (.{ "d", "p", "q", "dp", "dq", "qinv" }) |field| try s.integer(&@field(c, field));
        if (s.pos != s.bytes.len) return error.InvalidEncoding;
    }
};

/// Decodes a public key into `c`, which has an `n` array and an `e` integer.
/// Returns the algorithm identifier, or `null` for PKCS #1, which doesn't have one.
pub fn parsePublicKey(bytes: []const u8, comptime format: PublicKeyFormat, c: anytype) EncodingError!?Algorithm {
    var p: Parser = .{ .bytes = bytes };
    var alg: ?Algorithm = null;
    switch (format) {
        .pkcs1 => try p.rsaPublicKey(c),
        .spki => {
            var s: Parser = .{ .bytes = try p.element(tag_sequence) };
            alg = try s.algorithm();
            const bits = try s.element(tag_bit_string);
            if (bits.len == 0 or bits[0] != 0) return error.InvalidEncoding;
            var k: Parser = .{ .bytes = bits[1..] };
            try k.rsaPublicKey(c);
            if (k.pos != k.bytes.len or s.pos != s.bytes.len) return error.InvalidEncoding;
        },
        _ => @compileError("unsupported public key format"),
    }
    if (p.pos != p.bytes.len) return error.InvalidEncoding;
    return alg;
}

/// Decodes a secret key into `c`, which has the eight fields of RSAPrivateKey.
/// Returns the algorithm identifier, or `null` for PKCS #1, which doesn't have one.
pub fn parseSecretKey(bytes: []const u8, comptime format: SecretKeyFormat, c: anytype) EncodingError!?Algorithm {
    var p: Parser = .{ .bytes = bytes };
    var alg: ?Algorithm = null;
    switch (format) {
        .pkcs1 => try p.rsaPrivateKey(c),
        .pkcs8 => {
            var s: Parser = .{ .bytes = try p.element(tag_sequence) };
            if (!mem.eql(u8, try s.element(tag_integer), &.{0})) return error.InvalidEncoding;
            alg = try s.algorithm();
            var k: Parser = .{ .bytes = try s.element(tag_octet_string) };
            try k.rsaPrivateKey(c);
            if (k.pos != k.bytes.len) return error.InvalidEncoding;
            if (s.pos < s.bytes.len) {
                // Attributes are skipped, after checking that both levels of SET OF are sorted and that the values are well-formed elements.
                // The values are opaque, so only their structure is checked.
                const start = s.pos;
                var attrs: Parser = .{ .bytes = try s.element(0xa0) };
                if (s.pos - start > attributes_length_max) return error.InvalidEncoding;
                var prev_attr: []const u8 = "";
                while (attrs.pos < attrs.bytes.len) {
                    const attr_start = attrs.pos;
                    var attr: Parser = .{ .bytes = try attrs.element(tag_sequence) };
                    // The OID must be a sequence of minimally encoded base-128 integers.
                    const oid = try attr.element(tag_oid);
                    if (oid.len == 0 or oid[oid.len - 1] & 0x80 != 0) return error.InvalidEncoding;
                    for (oid, 0..) |b, i| {
                        if (b == 0x80 and (i == 0 or oid[i - 1] & 0x80 == 0)) return error.InvalidEncoding;
                    }
                    const values = try attr.element(tag_set);
                    if (values.len == 0 or attr.pos != attr.bytes.len) return error.InvalidEncoding;
                    var v: Parser = .{ .bytes = values };
                    // Each level of nesting takes at least two bytes, which bounds the depth.
                    var ends: [attributes_length_max / 2]u16 = undefined;
                    var depth: usize = 0;
                    var value_start: usize = 0;
                    var prev_value: []const u8 = "";
                    while (v.pos < values.len) {
                        // A child's header must fit in its parent, like its contents.
                        v.bytes = values[0..if (depth == 0) values.len else ends[depth - 1]];
                        if (depth == 0) value_start = v.pos;
                        const first = v.bytes[v.pos];
                        v.pos += 1;
                        if (first & 0x1f == 0x1f) {
                            // A long tag number must be minimally encoded, and too large for the short form.
                            if (v.pos >= v.bytes.len or v.bytes[v.pos] == 0x80 or v.bytes[v.pos] < 0x1f) return error.InvalidEncoding;
                            while (v.bytes[v.pos] & 0x80 != 0) {
                                v.pos += 1;
                                if (v.pos >= v.bytes.len) return error.InvalidEncoding;
                            }
                            v.pos += 1;
                        }
                        const constructed = first & 0x20 != 0;
                        if (first & 0xc0 == 0) {
                            // Universal types have a fixed form, DER has no end-of-contents marker, and tag 15 is reserved.
                            const number = first & 0x1f;
                            const must_construct = switch (number) {
                                8, 11, 16, 17, 29 => true,
                                else => false,
                            };
                            if (number == 0 or number == 15 or constructed != must_construct) return error.InvalidEncoding;
                        }
                        const len = try v.length();
                        if (len > v.bytes.len - v.pos) return error.InvalidEncoding;
                        if (constructed) {
                            ends[depth] = @intCast(v.pos + len);
                            depth += 1;
                        } else {
                            v.pos += len;
                        }
                        while (depth > 0 and v.pos == ends[depth - 1]) depth -= 1;
                        if (depth > 0) continue;
                        const value = values[value_start..v.pos];
                        if (mem.order(u8, prev_value, value) == .gt) return error.InvalidEncoding;
                        prev_value = value;
                    }
                    const encoded = attrs.bytes[attr_start..attrs.pos];
                    if (mem.order(u8, prev_attr, encoded) == .gt) return error.InvalidEncoding;
                    prev_attr = encoded;
                }
            }
            if (s.pos != s.bytes.len) return error.InvalidEncoding;
        },
        _ => @compileError("unsupported secret key format"),
    }
    if (p.pos != p.bytes.len) return error.InvalidEncoding;
    return alg;
}

pub const KeyFormat = enum { pkcs1_public, spki, pkcs1_private, pkcs8 };

/// Returns the size of the modulus, in bits, reading only up to the beginning of the modulus.
pub fn modulusBits(bytes: []const u8, encoding: KeyFormat) EncodingError!u16 {
    var p: Parser = .{ .bytes = bytes };
    _ = try p.enterLimited(tag_sequence);
    switch (encoding) {
        .pkcs1_public => {},
        .spki => {
            _ = try p.element(tag_sequence);
            if (try p.enterLimited(tag_bit_string) == 0 or p.pos >= p.bytes.len or p.bytes[p.pos] != 0) return error.InvalidEncoding;
            p.pos += 1;
            _ = try p.enterLimited(tag_sequence);
        },
        .pkcs1_private => if (!mem.eql(u8, try p.element(tag_integer), &.{0})) return error.InvalidEncoding,
        .pkcs8 => {
            if (!mem.eql(u8, try p.element(tag_integer), &.{0})) return error.InvalidEncoding;
            _ = try p.element(tag_sequence);
            _ = try p.enterLimited(tag_octet_string);
            _ = try p.enterLimited(tag_sequence);
            if (!mem.eql(u8, try p.element(tag_integer), &.{0})) return error.InvalidEncoding;
        },
    }
    var len = try p.enterLimited(tag_integer);
    if (len == 0 or p.bytes.len - p.pos < @min(len, 2)) return error.InvalidEncoding;
    var top = p.bytes[p.pos];
    if (top & 0x80 != 0) return error.InvalidEncoding;
    if (top == 0 and len > 1) {
        top = p.bytes[p.pos + 1];
        if (top & 0x80 == 0) return error.InvalidEncoding;
        len -= 1;
    }
    if (len > 16384 / 8) return error.InvalidEncoding;
    return @intCast(8 * len - @clz(top));
}

// Writes from the end of the buffer towards its start, so that lengths are known when headers are written.
const BackwardWriter = struct {
    buf: []u8,
    pos: usize,

    fn bytes(w: *BackwardWriter, b: []const u8) void {
        w.pos -= b.len;
        @memcpy(w.buf[w.pos..][0..b.len], b);
    }

    // Writes the header of an element whose contents start at the current position and end at `end`.
    fn header(w: *BackwardWriter, tag: u8, end: usize) void {
        const len = end - w.pos;
        if (len < 0x80) {
            w.bytes(&.{ tag, @intCast(len) });
        } else if (len < 0x100) {
            w.bytes(&.{ tag, 0x81, @intCast(len) });
        } else {
            w.bytes(&.{ tag, 0x82, @intCast(len >> 8), @truncate(len) });
        }
    }

    fn integer(w: *BackwardWriter, be: []const u8) void {
        const end = w.pos;
        var v = be;
        while (v.len > 1 and v[0] == 0) v = v[1..];
        w.bytes(v);
        if (v[0] & 0x80 != 0) w.bytes(&.{0});
        w.header(tag_integer, end);
    }

    fn hashId(w: *BackwardWriter, hash: HashId) void {
        const end = w.pos;
        w.oid(&oid_hashes[@backingInt(hash)]);
        w.header(tag_sequence, end);
    }

    fn oid(w: *BackwardWriter, o: []const u8) void {
        w.bytes(o);
        w.header(tag_oid, w.pos + o.len);
    }

    fn algorithm(w: *BackwardWriter, alg: Algorithm) void {
        const end = w.pos;
        switch (alg) {
            .rsa_encryption => {
                w.bytes(&null_params);
                w.oid(&oid_rsa_encryption);
            },
            .rsa_kem => w.oid(&oid_rsa_kem),
            .rsassa_pss => |params| {
                if (params) |pss| {
                    const params_end = w.pos;
                    if (pss.salt_length != 20) {
                        w.integer(&mem.toBytes(mem.nativeToBig(u64, pss.salt_length)));
                        w.header(0xa2, params_end);
                    }
                    var field_end = w.pos;
                    w.hashId(pss.hash);
                    w.oid(&oid_mgf1);
                    w.header(tag_sequence, field_end);
                    w.header(0xa1, field_end);
                    field_end = w.pos;
                    w.hashId(pss.hash);
                    w.header(0xa0, field_end);
                    w.header(tag_sequence, params_end);
                }
                w.oid(&oid_rsassa_pss);
            },
        }
        w.header(tag_sequence, end);
    }

    // Moves what was written to the start of the buffer, and wipes the rest, which may hold secret key material.
    fn finish(w: BackwardWriter) []u8 {
        const len = w.buf.len - w.pos;
        @memmove(w.buf[0..len], w.buf[w.pos..]);
        std.crypto.secureZero(u8, w.buf[len..]);
        return w.buf[0..len];
    }
};

/// Encodes a public key, given as a struct with an `n` array and an `e` integer.
/// `alg` is only used for SubjectPublicKeyInfo.
pub fn writePublicKey(buf: []u8, comptime format: PublicKeyFormat, alg: Algorithm, c: anytype) []u8 {
    var w: BackwardWriter = .{ .buf = buf, .pos = buf.len };
    w.integer(&mem.toBytes(mem.nativeToBig(u64, c.e)));
    w.integer(&c.n);
    w.header(tag_sequence, buf.len);
    switch (format) {
        .pkcs1 => {},
        .spki => {
            w.bytes(&.{0});
            w.header(tag_bit_string, buf.len);
            w.algorithm(alg);
            w.header(tag_sequence, buf.len);
        },
        _ => @compileError("unsupported public key format"),
    }
    return w.finish();
}

/// Encodes a secret key, given as a struct with the eight fields of RSAPrivateKey.
/// `alg` is only used for PKCS #8.
pub fn writeSecretKey(buf: []u8, comptime format: SecretKeyFormat, alg: Algorithm, c: anytype) []u8 {
    var w: BackwardWriter = .{ .buf = buf, .pos = buf.len };
    inline for (.{ "qinv", "dq", "dp", "q", "p", "d" }) |field| w.integer(&@field(c, field));
    w.integer(&mem.toBytes(mem.nativeToBig(u64, c.e)));
    w.integer(&c.n);
    w.bytes(&version_zero);
    w.header(tag_sequence, buf.len);
    switch (format) {
        .pkcs1 => {},
        .pkcs8 => {
            w.header(tag_octet_string, buf.len);
            w.algorithm(alg);
            w.bytes(&version_zero);
            w.header(tag_sequence, buf.len);
        },
        _ => @compileError("unsupported secret key format"),
    }
    return w.finish();
}
