pub const _errno = struct {
    extern "c" var __errno: c_int;
    fn getErrno() *c_int {
        return &__errno;
    }
}.getErrno;
