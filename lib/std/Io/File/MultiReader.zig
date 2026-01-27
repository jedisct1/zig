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
};

pub const Error = Allocator.Error || File.ReadStreamingError || Io.ConcurrentError;

/// Trailing:
/// * `contexts: [len]Context`
/// * `ring: [len]u32`
/// * `operations: [len]Io.Operation`
pub const Streams = extern struct {
    len: u32,

    pub fn contexts(s: *Streams) []Context {
        const base: usize = @intFromPtr(s);
        const ptr: [*]Context = @ptrFromInt(std.mem.alignForward(usize, base + @sizeOf(Streams), @alignOf(Context)));
        return ptr[0..s.len];
    }

    pub fn ring(s: *Streams) []u32 {
        const prev = contexts(s);
        const end = prev.ptr + prev.len;
        const ptr: [*]u32 = @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(end), @alignOf(u32)));
        return ptr[0..s.len];
    }

    pub fn operations(s: *Streams) []Io.Operation {
        const prev = ring(s);
        const end = prev.ptr + prev.len;
        const ptr: [*]Io.Operation = @ptrFromInt(std.mem.alignForward(usize, @intFromPtr(end), @alignOf(Io.Operation)));
        return ptr[0..s.len];
    }
};

pub fn Buffer(comptime n: usize) type {
    return extern struct {
        len: u32,
        contexts: [n][@sizeOf(Context)]u8 align(@alignOf(Context)),
        ring: [n]u32,
        operations: [n][@sizeOf(Io.Operation)]u8 align(@alignOf(Io.Operation)),

        pub fn toStreams(b: *@This()) *Streams {
            b.len = n;
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

pub fn fileReader(mr: *MultiReader, index: usize) *File.Reader {
    return &mr.streams.contexts()[index].fr;
}

pub fn reader(mr: *MultiReader, index: usize) *Io.Reader {
    return &mr.streams.contexts()[index].fr.interface;
}

/// Checks for errors in all streams, prioritizing `error.Canceled` if it
/// occurred anywhere.
pub fn checkAnyError(mr: *const MultiReader) Error!void {
    const contexts = mr.streams.contexts();
    var other: Error!void = {};
    for (contexts) |*context| {
        if (context.err) |err| switch (err) {
            error.Canceled => |e| return e,
            else => |e| other = e,
        };
    }
    return other;
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
    try fillUntimed(context, 1);
    return 0;
}

fn discard(r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
    _ = limit;
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    try fillUntimed(context, 1);
    return 0;
}

fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
    _ = data;
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    try fillUntimed(context, 1);
    return 0;
}

fn rebase(r: *Io.Reader, capacity: usize) Io.Reader.RebaseError!void {
    const fr: *File.Reader = @alignCast(@fieldParentPtr("interface", r));
    const context: *Context = @fieldParentPtr("fr", fr);
    try fillUntimed(context, capacity);
}

fn fillUntimed(context: *Context, capacity: usize) Io.Reader.Error!void {
    fill(context.mr, capacity, .none) catch |err| switch (err) {
        error.Timeout, error.UnsupportedClock => unreachable,
        error.Canceled, error.ConcurrencyUnavailable => |e| {
            context.err = e;
            return error.ReadFailed;
        },
        error.EndOfStream => |e| return e,
    };
    if (context.err) |err| switch (err) {
        error.EndOfStream => |e| return e,
        else => return error.ReadFailed,
    };
}

pub const FillError = Io.Batch.WaitError || error{
    /// `fill` was called when all streams already have failed or reached the
    /// end.
    EndOfStream,
};

/// Wait until at least one stream receives more data.
pub fn fill(mr: *MultiReader, unused_capacity: usize, timeout: Io.Timeout) FillError!void {
    const contexts = mr.streams.contexts();
    const operations = mr.streams.operations();
    const io = contexts[0].fr.io;
    var any_completed = false;

    try mr.batch.wait(io, timeout);

    while (mr.batch.next()) |i| {
        any_completed = true;
        const context = &contexts[i];
        const operation = &operations[i];
        const n = operation.file_read_streaming.status.result catch |err| {
            context.err = err;
            continue;
        };
        const r = &context.fr.interface;
        r.end += n;
        if (r.buffer.len - r.end < unused_capacity) {
            rebaseGrowing(mr, context, r.bufferedLen() + unused_capacity) catch |err| {
                context.err = err;
                continue;
            };
            assert(r.seek == 0);
        }
        context.vec[0] = r.buffer[r.end..];
        operation.file_read_streaming.status = .{ .unstarted = {} };
        mr.batch.add(i);
    }

    if (!any_completed) return error.EndOfStream;
}

/// Wait until all streams fail or reach the end.
pub fn fillRemaining(mr: *MultiReader, timeout: Io.Timeout) Io.Batch.WaitError!void {
    while (fill(mr, 1, timeout)) |_| {} else |err| switch (err) {
        error.EndOfStream => return,
        else => |e| return e,
    }
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
        gpa.free(r.buffer);
        r.buffer = new;
        r.seek = 0;
        r.end = data.len;
    }
}
