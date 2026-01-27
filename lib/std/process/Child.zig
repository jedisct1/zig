const Child = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;

const std = @import("../std.zig");
const Io = std.Io;
const process = std.process;
const File = std.Io.File;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const Id = switch (native_os) {
    .windows => std.os.windows.HANDLE,
    .wasi => void,
    else => std.posix.pid_t,
};

/// After `wait` or `kill` is called, this becomes `null`.
/// On Windows this is the hProcess.
/// On POSIX this is the pid.
id: ?Id,
thread_handle: if (native_os == .windows) std.os.windows.HANDLE else void,
/// The writing end of the child process's standard input pipe.
/// Usage requires `process.SpawnOptions.StdIo.pipe`.
stdin: ?File,
/// The reading end of the child process's standard output pipe.
/// Usage requires `process.SpawnOptions.StdIo.pipe`.
stdout: ?File,
/// The reading end of the child process's standard error pipe.
/// Usage requires `process.SpawnOptions.StdIo.pipe`.
stderr: ?File,
/// This is available after calling wait if
/// `request_resource_usage_statistics` was set to `true` before calling
/// `spawn`.
/// TODO move this data into `Term`
resource_usage_statistics: ResourceUsageStatistics = .{},
request_resource_usage_statistics: bool,

pub const ResourceUsageStatistics = struct {
    rusage: @TypeOf(rusage_init) = rusage_init,

    /// Returns the peak resident set size of the child process, in bytes,
    /// if available.
    pub inline fn getMaxRss(rus: ResourceUsageStatistics) ?usize {
        switch (native_os) {
            .dragonfly, .freebsd, .netbsd, .openbsd, .illumos, .linux, .serenity => {
                if (rus.rusage) |ru| {
                    return @as(usize, @intCast(ru.maxrss)) * 1024;
                } else {
                    return null;
                }
            },
            .windows => {
                if (rus.rusage) |ru| {
                    return ru.PeakWorkingSetSize;
                } else {
                    return null;
                }
            },
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
                if (rus.rusage) |ru| {
                    // Darwin oddly reports in bytes instead of kilobytes.
                    return @as(usize, @intCast(ru.maxrss));
                } else {
                    return null;
                }
            },
            else => return null,
        }
    }

    const rusage_init = switch (native_os) {
        .dragonfly,
        .freebsd,
        .netbsd,
        .openbsd,
        .illumos,
        .linux,
        .serenity,
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => @as(?std.posix.rusage, null),
        .windows => @as(?std.os.windows.VM_COUNTERS, null),
        else => {},
    };
};

pub const Term = union(enum) {
    exited: u8,
    signal: std.posix.SIG,
    stopped: u32,
    unknown: u32,
};

/// Requests for the operating system to forcibly terminate the child process,
/// then blocks until it terminates, then cleans up all resources.
///
/// Idempotent and does nothing after `wait` returns.
///
/// Uncancelable. Ignores unexpected errors from the operating system.
pub fn kill(child: *Child, io: Io) void {
    if (child.id == null) {
        assert(child.stdin == null);
        assert(child.stdout == null);
        assert(child.stderr == null);
        return;
    }
    io.vtable.childKill(io.userdata, child);
    assert(child.id == null);
}

pub const WaitError = error{
    AccessDenied,
} || Io.Cancelable || Io.UnexpectedError;

/// Blocks until child process terminates and then cleans up all resources.
pub fn wait(child: *Child, io: Io) WaitError!Term {
    assert(child.id != null);
    return io.vtable.childWait(io.userdata, child);
}

pub const CollectOutputError = error{
    StreamTooLong,
} || Io.ConcurrentError || Allocator.Error || Io.File.Reader.Error || Io.Timeout.Error;

pub const CollectOutputOptions = struct {
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
    /// Used for `stdout` and `stderr`. If not provided, only the existing
    /// capacity will be used.
    allocator: ?Allocator = null,
    stdout_limit: Io.Limit = .unlimited,
    stderr_limit: Io.Limit = .unlimited,
    timeout: Io.Timeout = .none,
};

/// Collect the output from the process's stdout and stderr. Will return once
/// all output has been collected. This does not mean that the process has
/// ended. `wait` should still be called to wait for and clean up the process.
///
/// The process must have been started with stdout and stderr set to
/// `process.SpawnOptions.StdIo.pipe`.
pub fn collectOutput(child: *const Child, io: Io, options: CollectOutputOptions) CollectOutputError!void {
    const files: [2]Io.File = .{ child.stdout.?, child.stderr.? };
    const lists: [2]*std.ArrayList(u8) = .{ options.stdout, options.stderr };
    const limits: [2]Io.Limit = .{ options.stdout_limit, options.stderr_limit };
    var reads: [2]Io.Operation = undefined;
    var vecs: [2][1][]u8 = undefined;
    var ring: [2]u32 = undefined;
    var batch: Io.Batch = .init(&reads, &ring);
    defer {
        batch.cancel(io);
        while (batch.next()) |op| {
            lists[op].items.len += reads[op].file_read_streaming.status.result catch continue;
        }
    }
    var remaining: usize = 0;
    for (0.., &reads, &lists, &files, &vecs) |op, *read, list, file, *vec| {
        if (options.allocator) |gpa| try list.ensureUnusedCapacity(gpa, 1);
        const cap = list.unusedCapacitySlice();
        if (cap.len == 0) return error.StreamTooLong;
        vec[0] = cap;
        read.* = .{ .file_read_streaming = .{
            .file = file,
            .data = vec,
        } };
        batch.add(op);
        remaining += 1;
    }
    while (remaining > 0) {
        try batch.wait(io, options.timeout);
        while (batch.next()) |op| {
            const n = reads[op].file_read_streaming.status.result catch |err| switch (err) {
                error.EndOfStream => {
                    remaining -= 1;
                    continue;
                },
                else => |e| return e,
            };
            lists[op].items.len += n;
            if (lists[op].items.len > @intFromEnum(limits[op])) return error.StreamTooLong;
            if (options.allocator) |gpa| try lists[op].ensureUnusedCapacity(gpa, 1);
            const cap = lists[op].unusedCapacitySlice();
            if (cap.len == 0) return error.StreamTooLong;
            vecs[op][0] = cap;
            reads[op].file_read_streaming.status = .{ .unstarted = {} };
            batch.add(op);
        }
    }
}
