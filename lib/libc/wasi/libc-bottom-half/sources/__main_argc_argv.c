// New compilers define `__main_argc_argv`. If that doesn't exist, we
// may get called here. Old compilers define `main` expecting an
// argv/argc, so call that.
// TODO: Remove this layer when we no longer have to support old compilers.

int __wasilibc_main(int argc, char *argv[]) {
    static const char *dummy_env[] = { (const void *) 0 };
    return main(argc, argv, dummy_env);
}

void __stack_chk_fail(void) __attribute__ ((__noreturn__)) {
    abort();
}

__attribute__((weak, nodebug))
int __main_argc_argv(int argc, char *argv[]) {
    return __wasilibc_main(argc, argv);
}
