const testing = @import("testing.zig");

test "std2" {
    const files = [_][]const u8{
        "base64",
        "bit_set",
        "buf_map",
        "buf_set",
        "build",
        "builtin",
        "c",
        "child_process",
        "coff",
        "compress",
        "comptime_string_map",
        "crypto",
        "cstr",
        "debug",
        "dwarf",
        "dynamic_library",
        "elf",
        "enums",
        "event",
        "fifo",
        "fmt",
        "fs",
        "hash",
        "hash_map",
        "heap",
        "io",
    };

    inline for (files) |file| {
        _ = @import(file ++ ".zig");
        testing.refAllDecls(@This());
    }
}
