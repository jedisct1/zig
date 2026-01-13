const MultiReader = @This();

const std = @import("../../std.zig");
const Io = std.Io;
const File = Io.File;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

gpa: Allocator,
streams: *Streams,
batch: Io.Batch,

pub const Context = struct {
    mr: *MultiReader,
    fr: File.Reader,
    vec: [1][]u8,
    err: ?Error,
    eos: bool,
};

pub const Error = Allocator.Error || File.Reader.Error || Io.ConcurrentError;

/// Trailing:
/// * `contexts: [len]Context`
/// * `ring: [len]u32`
/// * `operations: [len]Io.Operation`
pub const Streams = extern struct {
    len: u32,

    pub fn contexts(s: *Streams) []Context {
        _ = s;
        @panic("TODO");
    }

    pub fn ring(s: *Streams) []u32 {
        _ = s;
        @panic("TODO");
    }

    pub fn operations(s: *Streams) []Io.Operation {
        _ = s;
        @panic("TODO");
    }
};

pub fn Buffer(comptime n: usize) type {
    return extern struct {
        len: u32,
        contexts: [n][@sizeOf(Context)]u8 align(@alignOf(Context)),
        ring: [n]u32,
        operations: [n][@sizeOf(Io.Operation)]u8 align(@alignOf(Io.Operation)),

        pub fn toStreams(b: *@This()) *Streams {
            return @ptrCast(b);
        }
    };
}

/// See `Streams.Buffer` for convenience API to obtain the `streams` parameter.
pub fn init(mr: *MultiReader, gpa: Allocator, io: Io, streams: *Streams, files: []const File) void {
    const contexts = streams.contexts();
    for (contexts, files) |*context, file| context.* = .{
        .mr = mr,
        .fr = .{
            .io = io,
            .file = file,
            .mode = .streaming,
            .interface = .{
                .vtable = &.{
                    .stream = stream,
                    .discard = discard,
                    .readVec = readVec,
                    .rebase = rebase,
                },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        },
        .vec = .{&.{}},
        .err = null,
        .eos = false,
    };
    const operations = streams.operations();
    const ring = streams.ring();
    mr.* = .{
        .gpa = gpa,
        .streams = streams,
        .batch = .init(operations, ring),
    };
    for (operations, contexts, files, 0..) |*op, *context, file, i| {
        const r = &context.fr.interface;
        op.* = .{ .file_read_streaming = .{
            .file = file,
            .data = &context.vec,
        } };
        rebaseGrowing(mr, context, 1) catch |err| {
            context.err = err;
            continue;
        };
        context.vec[0] = r.buffer;
        mr.batch.add(i);
    }
}

pub fn deinit(mr: *MultiReader) void {
    const gpa = mr.gpa;
    const contexts = mr.streams.contexts();
    const io = contexts[0].fr.io;
    mr.batch.cancel(io);
    for (contexts) |*context| {
        gpa.free(context.fr.interface.buffer);
    }
}

pub fn reader(mr: *MultiReader, index: usize) *Io.Reader {
    return &mr.streams.contexts()[index].fr.interface;
}

pub fn toOwnedSlice(mr: *MultiReader, index: usize) Allocator.Error![]u8 {
    const gpa = mr.gpa;
    const r: *Io.Reader = reader(mr, index);
    if (r.seek == 0) {
        const new = try gpa.realloc(r.buffer, r.end);
        r.buffer = &.{};
        r.end = 0;
        return new;
    }
    const new = try gpa.dupe(u8, r.buffered());
    gpa.free(r.buffer);
    r.buffer = &.{};
    r.seek = 0;
    r.end = 0;
    return new;
}

fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    _ = limit;
    _ = w;
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    const mr = context.mr;
    return fill(mr, context);
}

fn discard(r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
    _ = limit;
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    const mr = context.mr;
    return fill(mr, context);
}

fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
    _ = data;
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    const mr = context.mr;
    return fill(mr, context);
}

fn rebase(r: *Io.Reader, capacity: usize) Io.Reader.RebaseError!void {
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    const mr = context.mr;

    return rebaseGrowing(mr, context, capacity) catch |err| {
        context.err = err;
        return error.ReadFailed;
    };
}

fn rebaseGrowing(mr: *MultiReader, context: *Context, capacity: usize) Allocator.Error!void {
    const gpa = mr.gpa;
    const r = &context.fr.interface;
    if (r.buffer.len >= capacity) {
        const data = r.buffer[r.seek..r.end];
        @memmove(r.buffer[0..data.len], data);
        r.seek = 0;
        r.end = data.len;
    } else {
        const adjusted_capacity = std.ArrayList(u8).growCapacity(capacity);

        if (r.seek == 0) {
            if (gpa.remap(r.buffer, adjusted_capacity)) |new_memory| {
                r.buffer = new_memory;
                return;
            }
        }

        const data = r.buffer[r.seek..r.end];
        const new = try gpa.alloc(u8, adjusted_capacity);
        @memcpy(new[0..data.len], data);
        r.seek = 0;
        r.end = data.len;
    }
}

fn fill(mr: *MultiReader, original_context: *Context) Io.Reader.Error!usize {
    const contexts = mr.streams.contexts();
    const operations = mr.streams.operations();
    const io = contexts[0].fr.io;

    mr.batch.wait(io, .none) catch |err| switch (err) {
        error.Timeout, error.UnsupportedClock => unreachable,
        else => |e| {
            original_context.err = e;
            return error.ReadFailed;
        },
    };

    while (mr.batch.next()) |i| {
        const context = &contexts[i];
        const operation = &operations[i];
        const n = operation.file_read_streaming.status.result catch |err| {
            context.err = err;
            continue;
        };
        if (n == 0) {
            context.eos = true;
            continue;
        }
        const r = &context.fr.interface;
        r.end += n;
        if (r.buffer.len - r.end == 0) {
            rebaseGrowing(mr, context, r.bufferedLen() + 1) catch |err| {
                context.err = err;
                continue;
            };
            assert(r.seek == 0);
            context.vec[0] = r.buffer;
        }
        operation.file_read_streaming.status = .{ .unstarted = {} };
        mr.batch.add(i);
    }

    if (original_context.err != null) return error.ReadFailed;
    if (original_context.eos) return error.EndOfStream;
    return 0;
}
