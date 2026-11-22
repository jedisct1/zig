//! PEM encoding of keys (RFC 7468), without headers.
//!
//! Base64 goes through `std.crypto.codecs.base64`, which runs in constant time.
//! The length of a block and the positions of its line breaks aren't treated as secret.

const std = @import("std");
const mem = std.mem;
const base64 = std.crypto.codecs.base64;
const EncodingError = std.crypto.errors.EncodingError;

pub const Label = enum {
    public_key,
    rsa_public_key,
    private_key,
    rsa_private_key,
    encrypted_private_key,

    pub fn text(label: Label) []const u8 {
        return switch (label) {
            .public_key => "PUBLIC KEY",
            .rsa_public_key => "RSA PUBLIC KEY",
            .private_key => "PRIVATE KEY",
            .rsa_private_key => "RSA PRIVATE KEY",
            .encrypted_private_key => "ENCRYPTED PRIVATE KEY",
        };
    }
};

pub const Block = struct {
    label: Label,
    /// The base64 text between the boundary lines, including line breaks.
    body: []const u8,
};

// The whitespace of RFC 7468, without line breaks.
const blanks = " \t\x0b\x0c";

/// Returns the first block whose label is one of `labels`, skipping any other text and blocks.
/// A later block is never used if the first one is invalid.
pub fn find(text: []const u8, comptime labels: []const Label) EncodingError!Block {
    const begin = "-----BEGIN ";
    const dashes = "-----";
    // Only look for markers at the start of lines, so that searching never indexes a table with bytes of a key.
    var pos: usize = 0;
    while (pos < text.len) : (pos = (mem.findAnyPos(u8, text, pos, "\r\n") orelse text.len) + 1) {
        if (!mem.startsWith(u8, text[pos..], begin)) continue;
        const label = inline for (labels) |l| {
            if (mem.startsWith(u8, text[pos + begin.len ..], comptime l.text() ++ dashes)) break l;
        } else continue;

        const body_start = mem.findNonePos(u8, text, pos + begin.len + label.text().len + dashes.len, blanks) orelse text.len;
        if (body_start == text.len or (text[body_start] != '\n' and text[body_start] != '\r')) return error.InvalidEncoding;

        const end = "-----END ";
        var body_end = body_start;
        while (!mem.startsWith(u8, text[body_end..], end)) {
            const line_end = mem.findAnyPos(u8, text, body_end, "\r\n") orelse return error.InvalidEncoding;
            body_end = mem.findNonePos(u8, text, line_end + 1, blanks) orelse text.len;
        }
        var footer = text[body_end + end.len ..];
        if (!mem.startsWith(u8, footer, label.text()) or !mem.startsWith(u8, footer[label.text().len..], dashes)) return error.InvalidEncoding;
        footer = mem.trimStart(u8, footer[label.text().len + dashes.len ..], blanks);
        if (footer.len != 0 and footer[0] != '\n' and footer[0] != '\r') return error.InvalidEncoding;
        return .{ .label = label, .body = text[body_start..body_end] };
    }
    return error.InvalidEncoding;
}

/// Decodes the body of a block, which must be canonical base64, into `out`.
pub fn decode(body: []const u8, out: []u8) EncodingError![]const u8 {
    const decoder = base64.decoderWithIgnore(&std.ascii.whitespace) catch unreachable;
    return decoder.decode(out, body, .standard) catch error.InvalidEncoding;
}

/// Decodes the first `out.len` bytes of the body of a block, or less if the block is shorter.
pub fn decodePrefix(body: []const u8, out: []u8) EncodingError![]const u8 {
    var chars: [4 * 128]u8 = undefined;
    defer std.crypto.secureZero(u8, &chars);
    const max = @min(chars.len, out.len / 3 * 4);
    var len: usize = 0;
    for (body) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (len == max) break;
        chars[len] = c;
        len += 1;
    }
    return base64.decode(out, chars[0..len], .standard) catch error.InvalidEncoding;
}

/// Returns the largest size of a block holding `der_length` bytes, whatever its label.
pub fn encodedLength(der_length: usize) usize {
    const b64_len = base64.encodedLen(der_length, .standard);
    const longest_label = Label.encrypted_private_key.text().len;
    return "-----BEGIN -----\n".len + "-----END -----\n".len + 2 * longest_label + b64_len + (b64_len + 63) / 64;
}

/// Writes a block, with 64-character lines and LF line endings.
pub fn encode(buf: []u8, label: Label, der: []const u8) []u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("-----BEGIN {s}-----\n", .{label.text()}) catch unreachable;
    var chunk: [64]u8 = undefined;
    var i: usize = 0;
    while (i < der.len) : (i += 48) {
        const line = base64.encode(&chunk, der[i..@min(i + 48, der.len)], .standard) catch unreachable;
        w.print("{s}\n", .{line}) catch unreachable;
    }
    std.crypto.secureZero(u8, &chunk);
    w.print("-----END {s}-----\n", .{label.text()}) catch unreachable;
    return w.buffered();
}
