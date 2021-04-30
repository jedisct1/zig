const testing = @import("testing.zig");

test "std3" {
    const files = [_][]const u8{
        "json",
        "leb128",
        "linked_list",
        "log",
        "macho",
        "math",
        "mem",
        "meta",
        "multi_array_list",
        "net",
        "once",
        "os",
        "packed_int_array",
        "pdb",
        "priority_dequeue",
        "priority_queue",
        "process",
        "rand",
        "sort",
        "start",
        "target",
        "time",
        "unicode",
        "valgrind",
        "wasm",
        "x",
        "zig",
    };

    inline for (files) |file| {
        _ = @import(file ++ ".zig");
        testing.refAllDecls(@This());
    }
}
