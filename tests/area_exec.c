/*
 * sbx_test, area "exec": programs: CONTAIN, the listener and libsbx_child.so, sbx-exec, SBX_LOCK_EXEC, program trees, spawning, the GPU proxy.
 * Included by tests/sbx_test.c, one translation unit with the harness (tests/sbx_test.h);
 * SBX_TEST_AREA=exec runs this area alone (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

/* ---- SBX_LOCK_CONTAIN: the file system view restricted, sockets and signals left to the kernel. ---- */


static int exec_files(const char *self, char *helper, char *library, size_t size);

static int contain_check(const char *self) {
    /* The preset includes SBX_LOCK_EXEC, which needs the helper and the child library. */
    static char helper[600], library[600];
    exec_files(self, helper, library, sizeof(helper));
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    pid_t parent = getpid();
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {
            .flags = SBX_LOCK_CONTAIN | SBX_LOCK_NET_BROKERED, .exec_helper = helper, .child_library = library};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "contain: not with the brokered network");
        options.flags = SBX_LOCK_CONTAIN;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "contain: lockdown");
        if (locked != 0) _exit(1);
        char key[400], data[400];
        snprintf(key, sizeof(key), "%s/key", secret);
        snprintf(data, sizeof(data), "%s/data.txt", game);
        errno = 0;
        EXPECT(refused(open(key, O_RDONLY)), "contain: the file system view is still the broker's");
        int fd = open(data, O_RDONLY | O_CLOEXEC);
        EXPECT(fd >= 0, "contain: a file the rules allow opens");
        if (fd >= 0) close(fd);
        int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        int unix_ok = 1;
        for (int i = 0; i < 3; i++) {
            int s = socket(AF_UNIX, types[i] | SOCK_CLOEXEC, 0);
            unix_ok &= s >= 0;
            if (s >= 0) close(s);
        }
        EXPECT(unix_ok, "contain: Unix sockets of every type");
        int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        EXPECT(s >= 0, "contain: an inet socket");
        if (s >= 0) close(s);
        s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0 /* NETLINK_ROUTE */);
        EXPECT(s >= 0 || errno != EACCES, "contain: route netlink is not refused by the filter");
        if (s >= 0) close(s);
        errno = 0;
        EXPECT(refused(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 15 /* NETLINK_KOBJECT_UEVENT */)),
               "contain: other netlink protocols are refused");
        struct sockaddr_un away = {.sun_family = AF_UNIX};
        snprintf(away.sun_path, sizeof(away.sun_path), "/sbx-contain-%d", (int) getpid());
        int u = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        errno = 0;
        EXPECT(u >= 0 && connect(u, (struct sockaddr *) &away, sizeof(away)) < 0 && errno == ENOENT,
               "contain: connect goes to the kernel (which finds no such socket)");
        if (u >= 0) close(u);
        EXPECT(kill(parent, 0) == 0, "contain: a signal to another process of the UID");
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = on_usr1;
        sigaction(SIGUSR1, &action, NULL);
        fflush(stdout);
        pid_t grandchild = fork();
        if (grandchild == 0) {
            usr1_seen = 0;
            int sent = kill(getpid(), SIGUSR1) == 0;
            _exit(sent && usr1_seen ? 0 : 1);
        }
        int status = 0;
        waitpid(grandchild, &status, 0);
        EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "contain: a forked child signals itself");
        errno = 0;
        EXPECT(a_ptrace() == EACCES || a_ptrace() == EPERM, "contain: ptrace still refused");
        EXPECT(a_unshare() == EPERM, "contain: unshare still refused");
        EXPECT(a_mount() == EPERM, "contain: mount still refused");
        EXPECT(a_bpf() == EACCES, "contain: bpf still refused");
        EXPECT(a_io_uring() == EACCES, "contain: io_uring still refused");
        errno = 0;
        EXPECT(syscall(__NR_finit_module, -1, "", 0) < 0 && errno == EPERM, "contain: module loading refused");
#ifdef __NR_pidfd_open
        errno = 0;
        EXPECT(syscall(__NR_pidfd_open, parent, 0) < 0 && errno == EPERM, "contain: pidfd_open still refused");
#endif
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    int failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (WIFSIGNALED(status)) printf("FAIL contain: the child died by signal %d\n", WTERMSIG(status));

    /* Every flag at once still fits in a filter. */
    int every[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, every) != 0) return 1;
    if (sbx_broker_start(sbx_policy_new(), every[0]) != 0) return 1;
    fflush(stdout);
    child = fork();
    if (child == 0) {
        close(every[0]);
        struct sbx_lockdown_options options = {
            .flags = SBX_LOCK_CONTAIN | SBX_LOCK_UNIX | SBX_LOCK_INET | SBX_LOCK_LOG_SOCKET | SBX_LOCK_LEARN,
            .exec_helper = helper, .child_library = library};
        int locked = sbx_lockdown(every[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "contain: every flag at once fits in the filter");
        _exit(failures ? 1 : 0);
    }
    close(every[1]);
    waitpid(child, &status, 0);
    failed |= !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    return failed;
}

/* ---- sbx_broker_listen and libsbx_child.so: a tree of processes attaches by path and token. ---- */

#define TEST_TOKEN "sbx-test-token-0123456789abcdef"

/* Runs in an image started with libsbx_child.so on LD_PRELOAD: confined before main. */
static int attached_main(const char *game_folder, const char *secret_folder) {
    char data[400], key[400];
    snprintf(data, sizeof(data), "%s/data.txt", game_folder);
    snprintf(key, sizeof(key), "%s/key", secret_folder);
    EXPECT(getenv("SBX_TOKEN") == NULL && getenv("SBX_BROKER") == NULL, "attached: the token and broker left the environment");
    EXPECT(getenv("SBX_BROKER_FD") != NULL, "attached: the connection's number is in SBX_BROKER_FD");
    int fd = open(data, O_RDONLY | O_CLOEXEC);
    EXPECT(fd >= 0, "attached: a file the rules allow opens through the broker");
    if (fd >= 0) close(fd);
    errno = 0;
    EXPECT(refused(open(key, O_RDONLY | O_CLOEXEC)), "attached: one outside the rules is refused before main ever ran");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int ok = 1;
        int f = open(data, O_RDONLY | O_CLOEXEC);
        ok &= f >= 0;
        if (f >= 0) close(f);
        ok &= open(key, O_RDONLY | O_CLOEXEC) < 0 && errno == EACCES;
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    waitpid(child, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "attached: a forked child shares the connection and stays confined");
    return failures ? 1 : 0;
}

static int run_attached(const char *self, const char *library, const char *broker, const char *token) {
    char preload[600], broker_env[200], token_env[200];
    snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", library);
    snprintf(broker_env, sizeof(broker_env), "SBX_BROKER=%s", broker);
    snprintf(token_env, sizeof(token_env), "SBX_TOKEN=%s", token);
    char *envp[] = {preload, broker_env, token_env, "SBX_FLAGS=0",
                    "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};
    char *argv[] = {(char *) self, "--attached", game, secret, NULL};
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        execve(self, argv, envp);
        _exit(126);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int listen_check(const char *self) {
    char library[600];
    snprintf(library, sizeof(library), "%s", self);
    char *slash = strrchr(library, '/');
    if (!slash) return 1;
    snprintf(slash + 1, sizeof(library) - (size_t) (slash + 1 - library), "libsbx_child.so");
    char broker_path[400];
    snprintf(broker_path, sizeof(broker_path), "%s/broker.sock", root);
    int files_error = host_socket_files(root);
    if (files_error != 0) {
        /* A host app makes the socket in its own data folder; this shell may make none here. */
        printf("skip listen: the broker's socket file (the host refuses them unconfined: %s)\n", strerror(files_error));
        return 0;
    }
    struct sbx_listener *listener = NULL;
    struct sbx_policy *small = sbx_policy_new();
    EXPECT(sbx_broker_listen(small, broker_path, "short", &listener) == -EINVAL, "listen: a short token is refused");
    sbx_policy_free(small);
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    int listened = sbx_broker_listen(policy, broker_path, TEST_TOKEN, &listener);
    errno = -listened;
    EXPECT(listened == 0, "listen: a broker on a socket path");
    if (listened != 0) {
        sbx_policy_free(policy);
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        _exit(sbx_attach(broker_path, "the-wrong-token-for-this-broker", NULL) == -EACCES ? 0 : 1);
    }
    int status = 0;
    waitpid(child, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "listen: an attach with the wrong token is refused");
    int failed = 0;
    if (access(library, R_OK) != 0) {
        printf("FAIL listen: libsbx_child.so is not beside the test (%s)\n", library);
        failed = 1;
    } else {
        int code = run_attached(self, library, broker_path, TEST_TOKEN);
        EXPECT(code == 0, "listen: an image started with libsbx_child.so attached and passed its checks");
        failed |= code != 0;
        code = run_attached(self, library, broker_path, "the-wrong-token-for-this-broker");
        EXPECT(code == 127, "listen: with the wrong token it ends before main (127)");
        failed |= code != 127;
    }
    /*
     * #767: a peer that connects and never greets is dropped after the
     * greeting timeout, and connections past the listener's cap are closed
     * at once, so neither can park the broker's threads. The control: a
     * proper attach still works afterwards.
     */
    enum { SILENT = 70, CAP = 64 };
    int silent[SILENT];
    struct sockaddr_un at;
    memset(&at, 0, sizeof(at));
    at.sun_family = AF_UNIX;
    size_t path_length = strlen(broker_path);
    if (path_length >= sizeof(at.sun_path)) path_length = sizeof(at.sun_path) - 1;
    memcpy(at.sun_path, broker_path, path_length);
    int connected = 0;
    for (int i = 0; i < SILENT; i++) {
        silent[i] = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (silent[i] >= 0 && connect(silent[i], (struct sockaddr *) &at, sizeof(at)) == 0) connected++;
    }
    usleep(500 * 1000);
    int dropped_now = 0;
    char byte;
    for (int i = 0; i < SILENT; i++) {
        if (silent[i] >= 0 && recv(silent[i], &byte, 1, MSG_DONTWAIT) == 0) dropped_now++;
    }
    EXPECT(connected == SILENT && dropped_now >= SILENT - CAP && dropped_now < SILENT,
           "listen: connections past the listener's cap are closed at once (#767)");
    int dropped_later = 0;
    for (int i = 0; i < SILENT; i++) {
        struct timeval wait = {.tv_sec = 9};
        if (silent[i] >= 0) setsockopt(silent[i], SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait));
        if (silent[i] >= 0 && recv(silent[i], &byte, 1, 0) == 0) dropped_later++;
        if (silent[i] >= 0) close(silent[i]);
    }
    EXPECT(dropped_later == SILENT, "listen: a connection that never greets is dropped after the greeting timeout (#767)");
    fflush(stdout);
    pid_t again = fork();
    if (again == 0) _exit(sbx_attach(broker_path, TEST_TOKEN, NULL) == 0 ? 0 : 1);
    waitpid(again, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "listen: afterwards, a proper attach still works");
    sbx_listener_close(listener);
    EXPECT(access(broker_path, F_OK) != 0, "listen: closing removes the socket");
    return failed || failures;
}

/* ---- sbx-exec's loader: a program started through it, as the kernel would start it. ---- */

static int exec_helper_check(const char *self) {
    char helper[600], library[600];
    snprintf(helper, sizeof(helper), "%s", self);
    char *slash = strrchr(helper, '/');
    if (!slash) return 1;
    snprintf(slash + 1, sizeof(helper) - (size_t) (slash + 1 - helper), "sbx-exec");
    snprintf(library, sizeof(library), "%s", helper);
    slash = strrchr(library, '/');
    snprintf(slash + 1, sizeof(library) - (size_t) (slash + 1 - library), "libsbx_child.so");
    if (access(helper, X_OK) != 0) {
#if defined(__x86_64__) || defined(__aarch64__)
        printf("FAIL exec: sbx-exec is not beside the test (%s)\n", helper);
        return 1;
#else
        return 0;
#endif
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, "/", SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int target = open(self, O_RDONLY);
        int directory = open(".", O_PATH | O_DIRECTORY);
        char broker_text[16], cwd_text[16], target_text[16];
        snprintf(broker_text, sizeof(broker_text), "%d", pair[1]);
        snprintf(cwd_text, sizeof(cwd_text), "%d", directory);
        snprintf(target_text, sizeof(target_text), "%d", target);
        char *argv[] = {helper, broker_text, cwd_text, target_text, "0", library, (char *) self, "--",
                        (char *) self, "--loaded", library, NULL};
        char *envp[] = {"SBX_EXEC_TEST=kept", "SBX_TOKEN=must-not-pass", "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};
        execve(helper, argv, envp);
        _exit(126);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    /*
     * The image comes up with libsbx_child.so first and SBX_ADOPT set, but no
     * filter behind it: the child library's probe gets the kernel's answer,
     * so it refuses to call the image confined and ends it before main.
     */
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 127;
    if (WIFSIGNALED(status)) printf("FAIL exec: the loaded image died by signal %d\n", WTERMSIG(status));
    EXPECT(ok, "exec: sbx-exec loaded the test, whose child library would not adopt without a filter (127)");
    pid_t bad = fork();
    if (bad == 0) {
        char *argv[] = {helper, "nonsense", NULL};
        execve(helper, argv, (char *[]) {NULL});
        _exit(126);
    }
    waitpid(bad, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 127, "exec: sbx-exec with bad arguments ends with 127");
    return !ok;
}

/* ---- SBX_LOCK_EXEC: a confined process execs, and the new image is confined the same. ---- */

/* sbx-exec and libsbx_child.so, beside the test; 0 when they are there. */
static int exec_files(const char *self, char *helper, char *library, size_t size) {
    snprintf(helper, size, "%s", self);
    char *slash = strrchr(helper, '/');
    if (!slash) return -1;
    snprintf(slash + 1, size - (size_t) (slash + 1 - helper), "sbx-exec");
    snprintf(library, size, "%s", helper);
    slash = strrchr(library, '/');
    snprintf(slash + 1, size - (size_t) (slash + 1 - library), "libsbx_child.so");
    return access(helper, X_OK) == 0 && access(library, R_OK) == 0 ? 0 : -1;
}

static char *exec_environment[] = {"SBX_EXEC_TEST=kept", "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};

/*
 * Runs in each image of the chain: argv is self, "--exec-child", the
 * generations left, the library, the secret folder and the first pid.
 */
static int exec_child_main(int argc, char **argv) {
    if (argc < 7) return 2;
    const char *self = argv[0], *library = argv[3], *secret_folder = argv[4], *not_executable = argv[6];
    int left = atoi(argv[2]);
    char name[160];
    snprintf(name, sizeof(name), "exec %d: the same process (pid)", left);
    EXPECT(getpid() == (pid_t) atol(argv[5]), name);
    const char *preload = getenv("LD_PRELOAD");
    snprintf(name, sizeof(name), "exec %d: libsbx_child.so first on LD_PRELOAD, once", left);
    EXPECT(preload && strncmp(preload, library, strlen(library)) == 0 && !strstr(preload + 1, library), name);
    snprintf(name, sizeof(name), "exec %d: the adoption names are gone", left);
    EXPECT(!getenv("SBX_ADOPT") && !getenv("SBX_EXEC_HELPER_FD") && !getenv("SBX_CHILD_LIBRARY"), name);
    snprintf(name, sizeof(name), "exec %d: the program's own environment kept", left);
    EXPECT(getenv("SBX_EXEC_TEST") && strcmp(getenv("SBX_EXEC_TEST"), "kept") == 0, name);
    char path[600];
    snprintf(path, sizeof(path), "%s/key", secret_folder);
    errno = 0;
    snprintf(name, sizeof(name), "exec %d: a file outside the rules refused", left);
    EXPECT(refused(open(path, O_RDONLY)), name);
    /* As bionic's linker does for debuggerd: a program's own SIGSYS handler is refused, and ours stays. */
    struct sigaction theirs;
    memset(&theirs, 0, sizeof(theirs));
    theirs.sa_handler = SIG_DFL;
    errno = 0;
    snprintf(name, sizeof(name), "exec %d: a program's own SIGSYS handler refused (EPERM)", left);
    EXPECT(sigaction(SIGSYS, &theirs, NULL) < 0 && errno == EPERM, name);
    int fd = open(self, O_RDONLY);
    snprintf(name, sizeof(name), "exec %d: a file the rules allow opens, through the broker", left);
    EXPECT(fd >= 0, name);
    if (fd >= 0) close(fd);
    char exe[600];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    exe[n > 0 ? n : 0] = 0;
    snprintf(name, sizeof(name), "exec %d: /proc/self/exe is the program, not sbx-exec", left);
    EXPECT(n > 0 && strcmp(exe, self) == 0, name);
    errno = 0;
    snprintf(name, sizeof(name), "exec %d: exec of a file outside the rules refused", left);
    EXPECT(execl(path, path, (char *) NULL) < 0 && errno == EACCES, name);
    errno = 0;
    snprintf(name, sizeof(name), "exec %d: exec of a file with no execute bit refused", left);
    EXPECT(execl(not_executable, not_executable, (char *) NULL) < 0 && errno == EACCES, name);
    errno = 0;
    snprintf(name, sizeof(name), "exec %d: a direct execveat through no trampoline still traps (missing file)", left);
    EXPECT(syscall(__NR_execveat, AT_FDCWD, "/nonexistent-sbx-exec-test", (char *[]) {NULL}, (char *[]) {NULL}, 0) < 0 &&
               errno == ENOENT, name);
    /*
     * Code that jumps to the fixed trampoline gets only the helper's form of
     * execveat (a descriptor, AT_EMPTY_PATH): a path is still trapped and
     * decided by the broker.
     */
#if defined(__x86_64__)
    long (*trampoline)(long, long, long, long, long, long, long) = (void *) (0x200000000000UL + 64);
#else
    long (*trampoline)(long, long, long, long, long, long, long) = (void *) (0x5b0000000UL + 64);
#endif
    char *no_args[] = {path, NULL};
    snprintf(name, sizeof(name), "exec %d: execveat of a path through the trampoline is still decided (refused)", left);
    EXPECT(trampoline(__NR_execveat, AT_FDCWD, (long) path, (long) no_args, (long) no_args + sizeof(char *), 0, 0) == -EACCES,
           name);
    fflush(stdout);
    if (left > 0 && failures == 0) {
        char next[12];
        snprintf(next, sizeof(next), "%d", left - 1);
        char *args[] = {(char *) self, "--exec-child", next, (char *) library, (char *) secret_folder, argv[5],
                        (char *) not_executable, NULL};
        execve(self, args, exec_environment);
        printf("FAIL exec %d: the next exec (errno %d %s)\n", left, errno, strerror(errno));
        return 1;
    }
    return failures ? 1 : 0;
}

static int exec_check(const char *self) {
#if !defined(__x86_64__) && !defined(__aarch64__)
    (void) self;
    return 0;
#else
    char helper[600], library[600];
    if (exec_files(self, helper, library, sizeof(helper)) != 0) {
        printf("FAIL exec: sbx-exec or libsbx_child.so is not beside the test\n");
        return 1;
    }
    char not_executable[400];
    snprintf(not_executable, sizeof(not_executable), "%s/data.txt", game);
    struct sbx_lockdown_options bad = {.flags = SBX_LOCK_EXEC};
    EXPECT(sbx_lockdown(0, &bad) == -EINVAL, "exec: SBX_LOCK_EXEC without the helper and library refused");
    bad.exec_helper = helper;
    bad.child_library = library;
    bad.flags = SBX_LOCK_EXEC | SBX_LOCK_PASSTHROUGH;
    EXPECT(sbx_lockdown(0, &bad) == -EINVAL, "exec: SBX_LOCK_EXEC with passthrough refused");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, "/", SBX_READ);
    sbx_policy_add(policy, secret, SBX_DENY);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_EXEC, .exec_helper = helper, .child_library = library};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "exec: lockdown with SBX_LOCK_EXEC");
        if (locked != 0) _exit(1);
        char pid_text[16];
        snprintf(pid_text, sizeof(pid_text), "%d", (int) getpid());
        char *args[] = {(char *) self, "--exec-child", "2", library, secret, pid_text, not_executable, NULL};
        execve(self, args, exec_environment);
        printf("FAIL exec: the first exec (errno %d %s)\n", errno, strerror(errno));
        _exit(1);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) printf("FAIL exec: the chain died by signal %d\n", WTERMSIG(status));
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    EXPECT(ok, "exec: three images in a row, each confined as the first");
    return !ok || failures;
#endif
}

/*
 * A-04: sbx_spawn_confined installs the lockdown and execs the program
 * through sbx-exec, so it is confined before its own loader runs. The spawned
 * program never locks itself down, yet a file outside the rules is refused and
 * one inside it opens -- proof the confinement was already in place. The
 * control is spawn_check above, where a plain sbx_spawn leaves the program
 * unconfined.
 */
static int spawn_confined_check(const char *self) {
#if !defined(__x86_64__) && !defined(__aarch64__)
    (void) self;
    return 0;
#else
    char helper[600], library[600];
    if (exec_files(self, helper, library, sizeof(helper)) != 0) {
        printf("FAIL spawn confined: sbx-exec or libsbx_child.so is not beside the test\n");
        return 1;
    }
    int before = failures;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, "/", SBX_READ);     /* the loader, libc and the image itself are read to run it */
    sbx_policy_add(policy, secret, SBX_DENY);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char granted[400], secret_path[400];
    snprintf(granted, sizeof(granted), "%s/data.txt", game);
    snprintf(secret_path, sizeof(secret_path), "%s/key", secret);
    int report[2];
    if (pipe(report) != 0) return 1;
    char *argv[] = {(char *) self, "--spawned-confined", granted, secret_path, NULL};
    int handed = report[1];
    struct sbx_spawn_spec spec = {self, argv, exec_environment, &handed, 1, NULL, 0};
    struct sbx_lockdown_options options = {.exec_helper = helper, .child_library = library};

    /* Missing pieces are refused before anything is started. */
    struct sbx_lockdown_options no_helper = {0};
    EXPECT(sbx_spawn_confined(&spec, pair[1], &no_helper, NULL) == -EINVAL,
           "spawn confined: without the exec helper and library it is refused");
    EXPECT(sbx_spawn_confined(&spec, -1, &options, NULL) == -EINVAL, "spawn confined: without a broker it is refused");

    pid_t pid = 0;
    int started = sbx_spawn_confined(&spec, pair[1], &options, &pid);
    close(report[1]);
    errno = -started;
    EXPECT(started == 0 && pid > 0, "spawn confined: the program starts");
    char word[16] = {0};
    ssize_t n = started == 0 ? read(report[0], word, sizeof(word) - 1) : 0;
    close(report[0]);
    int status = 0;
    if (started == 0 && pid > 0) waitpid(pid, &status, 0);
    if (n > 0) word[n] = 0;
    EXPECT(started == 0 && strcmp(word, "confined") == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "spawn confined: the program is confined before its own code runs (granted opens, secret refused)");
    if (started == 0 && strcmp(word, "confined") != 0) printf("info spawn confined: reported '%s'\n", word[0] ? word : "(nothing)");
    close(pair[1]);
    return failures != before;
#endif
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SBX_TEST_CLANG_ASAN 1
#endif
#endif
#ifndef SBX_TEST_CLANG_ASAN
#define SBX_TEST_CLANG_ASAN 0
#endif

/* ---- A program tree under SBX_LOCK_CONTAIN: the system shell and what it runs, as Wine's tree would. ---- */

struct tree_seen {
    int execs;   /* exec decisions the broker allowed */
    int refused; /* refusals the learning decider let through */
};

static void tree_audit(void *context, const struct sbx_access *access, int result) {
    struct tree_seen *seen = context;
    if (strcmp(access->op, "exec") == 0 && result == 0) __atomic_add_fetch(&seen->execs, 1, __ATOMIC_RELAXED);
}

static int tree_learn(void *context, const struct sbx_access *access) {
    struct tree_seen *seen = context;
    (void) access;
    __atomic_add_fetch(&seen->refused, 1, __ATOMIC_RELAXED);
    return 0;
}

/*
 * The shell's script: each step that fails exits with its own number. With
 * STRICT=1 the secret must be refused in every image; a learning run lets
 * it through and records it.
 */
static void tree_script(char *out, size_t size, const char *shell) {
    snprintf(out, size,
             "cat %s/data.txt >/dev/null || exit 11\n"
             "if [ \"$STRICT\" = 1 ]; then cat %s/key >/dev/null 2>&1 && exit 12; "
             "else cat %s/key >/dev/null || exit 17; fi\n"
             "ls %s >/dev/null || exit 13\n"
             "%s -c 'cat %s/data.txt >/dev/null || exit 1; [ \"$STRICT\" = 1 ] && cat %s/key >/dev/null 2>&1 && exit 2; exit 0' "
             "|| exit 14\n"
             "echo through | cat | grep through >/dev/null || exit 15\n"
             "%s/tree.sh || exit 16\n"
             "exit 0\n",
             game, secret, secret, game, shell, game, secret, game);
}

/* Runs the tree in a child: locked down here (attach == NULL), or attached by libsbx_child.so from the environment. */
static int run_tree(const char *shell, const char *helper, const char *library, int pair_fd, unsigned flags, int strict,
                    const char *attach_path) {
    static char script[4096];
    tree_script(script, sizeof(script), shell);
    char path_env[64], strict_env[16], helper_env[700], library_env[700], preload_env[700], broker_env[500],
        flags_env[32];
    snprintf(path_env, sizeof(path_env), "PATH=%s", access("/system/bin/sh", X_OK) == 0 ? "/system/bin" : "/usr/bin:/bin");
    snprintf(strict_env, sizeof(strict_env), "STRICT=%d", strict);
    snprintf(helper_env, sizeof(helper_env), "SBX_EXEC_HELPER=%s", helper);
    snprintf(library_env, sizeof(library_env), "SBX_CHILD_LIBRARY=%s", library);
    snprintf(preload_env, sizeof(preload_env), "LD_PRELOAD=%s", library);
    snprintf(broker_env, sizeof(broker_env), "SBX_BROKER=%s", attach_path ? attach_path : "");
    snprintf(flags_env, sizeof(flags_env), "SBX_FLAGS=%u", flags);
    char *plain[] = {path_env, strict_env, NULL};
    char *attached[] = {path_env, strict_env, helper_env, library_env, preload_env, broker_env,
                        "SBX_TOKEN=" TEST_TOKEN, flags_env, NULL};
    char *argv[] = {"sh", "-c", script, NULL};
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (!attach_path) {
            struct sbx_lockdown_options options = {.flags = flags, .exec_helper = helper, .child_library = library};
            int locked = sbx_lockdown(pair_fd, &options);
            if (locked != 0) {
                printf("FAIL tree: lockdown (%s)\n", strerror(-locked));
                _exit(120);
            }
        }
        execve(shell, argv, attach_path ? attached : plain);
        _exit(121);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int program_tree_check(const char *self) {
#if !defined(__x86_64__) && !defined(__aarch64__)
    (void) self;
    return 0;
#else
#if defined(__SANITIZE_ADDRESS__) || SBX_TEST_CLANG_ASAN
    /* The shell is not sanitized, and the child library of a sanitized build cannot load into it. */
    (void) self;
    printf("skip tree: a sanitized libsbx_child.so cannot load into the system shell\n");
    return 0;
#endif
    char helper[600], library[600];
    if (exec_files(self, helper, library, sizeof(helper)) != 0) {
        printf("FAIL tree: sbx-exec or libsbx_child.so is not beside the test\n");
        return 1;
    }
    const char *shell = access("/system/bin/sh", X_OK) == 0 ? "/system/bin/sh" : "/bin/sh";
    char script_path[400], body[1200];
    snprintf(script_path, sizeof(script_path), "%s/tree.sh", game);
    snprintf(body, sizeof(body),
             "#!%s\ncat %s/data.txt >/dev/null || exit 1\n[ \"$STRICT\" = 1 ] && cat %s/key >/dev/null 2>&1 && exit 2\nexit 0\n",
             shell, game, secret);
    write_file(script_path, body);
    chmod(script_path, 0755);
    int failed = 0;
    static const char *const meanings[] = {
        [11] = "an allowed file", [12] = "the secret refused", [13] = "ls", [14] = "a nested shell",
        [15] = "a pipe", [16] = "a #! script", [17] = "the secret read while learning", [120] = "lockdown",
        [121] = "the first exec",
    };
    for (int learn = 0; learn <= 1; learn++) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
        static struct tree_seen seen[2];
        struct sbx_policy *policy = sbx_policy_new();
        sbx_policy_add(policy, "/", SBX_READ);
        sbx_policy_add(policy, "/dev/null", SBX_READ | SBX_WRITE);
        sbx_policy_add(policy, secret, SBX_DENY);
        sbx_policy_set_audit(policy, tree_audit, &seen[learn]);
        if (learn) sbx_policy_set_decider(policy, tree_learn, &seen[learn]);
        if (sbx_broker_start(policy, pair[0]) != 0) return 1;
        unsigned flags = SBX_LOCK_CONTAIN | (learn ? SBX_LOCK_LEARN : 0);
        int code = run_tree(shell, helper, library, pair[1], flags, !learn, NULL);
        close(pair[1]);
        char name[200];
        const char *meaning = code > 0 && code < (int) (sizeof(meanings) / sizeof(meanings[0])) && meanings[code]
                                  ? meanings[code] : "";
        snprintf(name, sizeof(name), "tree%s: %s runs cat, ls, a nested shell, a pipe and a #! script, confined (exit %d%s%s)",
                 learn ? " (learning)" : "", shell, code, *meaning ? ": " : "", meaning);
        EXPECT(code == 0, name);
        int execs = __atomic_load_n(&seen[learn].execs, __ATOMIC_RELAXED);
        snprintf(name, sizeof(name), "tree%s: every exec went through the broker (%d decided)", learn ? " (learning)" : "",
                 execs);
        EXPECT(execs >= 6, name);
        if (learn) {
            snprintf(name, sizeof(name), "tree (learning): the secret was read, and recorded (%d records)",
                     seen[1].refused);
            EXPECT(seen[1].refused >= 1, name);
        }
        failed |= code != 0 || execs < 6;
    }
    /* The first process attached by libsbx_child.so from the environment, as a host starts Wine. */
    char broker_path[400];
    snprintf(broker_path, sizeof(broker_path), "%s/tree.sock", root);
    int files_error = host_socket_files(root);
    if (files_error != 0) {
        printf("skip tree: attached from the environment (the host refuses socket files unconfined: %s)\n",
               strerror(files_error));
        return failed;
    }
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, "/", SBX_READ);
    sbx_policy_add(policy, "/dev/null", SBX_READ | SBX_WRITE);
    sbx_policy_add(policy, secret, SBX_DENY);
    struct sbx_listener *listener = NULL;
    if (sbx_broker_listen(policy, broker_path, TEST_TOKEN, &listener) != 0) return 1;
    int code = run_tree(shell, helper, library, -1, SBX_LOCK_CONTAIN, 1, broker_path);
    char name[200];
    snprintf(name, sizeof(name), "tree: the same, its first process attached by libsbx_child.so from the environment (exit %d)",
             code);
    EXPECT(code == 0, name);
    sbx_listener_close(listener);
    return failed || code != 0;
#endif
}

/* ---- The GPU proxy (sbx_policy_add_gpu_proxy; Droidtop/tracker#815): a vtest renderer of each client's own. ---- */

#define GPU_VTEST_PATH "/run/sbx-test/vtest"

static int gpu_renderer_requests;
static void gpu_renderer_audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    (void) access;
    (void) result;
    __atomic_add_fetch(&gpu_renderer_requests, 1, __ATOMIC_ACQ_REL);
}

/*
 * Mesa's own GL client, confined, through the proxy: eglinfo started with
 * sbx_spawn_confined, its output read back; 1 when it reports virgl, 0 when
 * not, -1 when eglinfo is not here.
 */
static int gpu_mesa_client(const char *helper, const char *library, struct sbx_policy *client_policy,
                           const char *program, char *const *argv, char *const *env, const char *expect) {
    if (access(program, X_OK) != 0) return -1;
    int out[2], pair[2];
    if (pipe(out) != 0 || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 0;
    if (sbx_broker_start(client_policy, pair[0]) != 0) return 0;
    fflush(stdout);
    pid_t runner = fork();
    if (runner == 0) {
        dup2(out[1], 1);
        dup2(out[1], 2);
        close(out[0]);
        struct sbx_spawn_spec spec = {program, argv, env, NULL, 0, NULL, 0};
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNIX, .exec_helper = helper, .child_library = library};
        pid_t pid = 0;
        if (sbx_spawn_confined(&spec, pair[1], &options, &pid) != 0) _exit(2);
        int status = 0;
        waitpid(pid, &status, 0);
        _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 3);
    }
    close(out[1]);
    close(pair[1]);
    char text[16384];
    size_t used = 0;
    ssize_t r;
    while (used + 1 < sizeof(text) && (r = read(out[0], text + used, sizeof(text) - 1 - used)) > 0) used += (size_t) r;
    text[used] = '\0';
    close(out[0]);
    int status = 0;
    waitpid(runner, &status, 0);
    char *found = strstr(text, expect);
    if (found) {
        char *end = strchr(found, '\n');
        printf("info gpu proxy: confined %s says %.*s\n", argv[0], end ? (int) (end - found) : 80, found);
    } else {
        printf("info gpu proxy: confined %s said: %.400s\n", argv[0], text);
    }
    return found != NULL;
}

/* vtest's opening: create a renderer, then ping; 1 when the renderer answers the ping, 0 when not. */
static int gpu_vtest_ping(int fd) {
    static const char name[] = "sbx-test";
    uint32_t create[2] = {sizeof(name), 8 /* VCMD_CREATE_RENDERER */};
    uint32_t ping[2] = {0, 10 /* VCMD_PING_PROTOCOL_VERSION */};
    uint32_t answer[2] = {0, 0};
    if (write(fd, create, sizeof(create)) != (ssize_t) sizeof(create) || write(fd, name, sizeof(name)) != (ssize_t) sizeof(name) ||
        write(fd, ping, sizeof(ping)) != (ssize_t) sizeof(ping)) {
        return 0;
    }
    struct timeval wait = {.tv_sec = 20};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait));
    size_t got = 0;
    while (got < sizeof(answer)) {
        ssize_t r = read(fd, (char *) answer + got, sizeof(answer) - got);
        if (r <= 0) return 0;
        got += (size_t) r;
    }
    return answer[0] == 0 && answer[1] == 10;
}

static int gpu_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un at;
    unix_at(&at, GPU_VTEST_PATH);
    if (fd < 0 || connect(fd, (struct sockaddr *) &at, sizeof(at)) != 0) {
        int error = errno;
        if (fd >= 0) close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int gpu_proxy_check(const char *self) {
#if defined(__SANITIZE_ADDRESS__) || SBX_TEST_CLANG_ASAN
    /* The renderer and Mesa's tools are not sanitized, and the child library of a sanitized build cannot load into them. */
    (void) self;
    printf("skip gpu proxy: a sanitized libsbx_child.so cannot load into the system's renderer and tools\n");
    return 0;
#endif
    const char *server = "/usr/bin/virgl_test_server";
    if (access(server, X_OK) != 0) {
        printf("skip gpu proxy: no %s here (the virgl-server package)\n", server);
        return 0;
    }
#if !defined(__x86_64__) && !defined(__aarch64__)
    (void) self;
    return 0;
#else
    char helper[600], library[600];
    if (exec_files(self, helper, library, sizeof(helper)) != 0) {
        printf("FAIL gpu proxy: sbx-exec or libsbx_child.so is not beside the test\n");
        return 1;
    }
    char folder[400];
    snprintf(folder, sizeof(folder), "%s/gpu", root);
    mkdir(folder, 0700);
    int before = failures;
    struct sbx_policy *renderer_policy = sbx_policy_new();
    sbx_policy_add(renderer_policy, "/", SBX_READ);  /* its libraries, the driver and the software renderer */
    sbx_policy_set_audit(renderer_policy, gpu_renderer_audit, NULL);
    static struct sbx_lockdown_options renderer_options;
    renderer_options.exec_helper = helper;
    renderer_options.child_library = library;
    static char *renderer_args[] = {"--use-egl-surfaceless", NULL};
    static char *renderer_env[] = {"MESA_SHADER_CACHE_DISABLE=true", "EGL_PLATFORM=surfaceless",
                                   "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};
    struct sbx_policy *policy = sbx_policy_new();
    struct sbx_gpu_proxy proxy = {.vtest_path = GPU_VTEST_PATH, .renderer = server, .renderer_args = renderer_args,
                                  .renderer_envp = renderer_env, .folder = folder, .renderer_policy = renderer_policy,
                                  .renderer_options = &renderer_options};
    EXPECT(sbx_policy_add_gpu_proxy(policy, &proxy) == 0, "gpu proxy: added to the client's policy");
    EXPECT(sbx_policy_add_gpu_proxy(policy, &proxy) == -EEXIST, "gpu proxy: one per policy");
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0 || sbx_broker_prepare(pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(120);
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNIX};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "gpu proxy: the client locks down");
        if (locked == 0) {
            int first = gpu_connect();
            EXPECT(first >= 0, "gpu proxy: the client's connect to its vtest path is answered");
            EXPECT(first >= 0 && gpu_vtest_ping(first), "gpu proxy: a confined renderer of its own speaks vtest to it");
            int second = gpu_connect();
            EXPECT(second >= 0 && gpu_vtest_ping(second), "gpu proxy: a second connection gets a second renderer");
            if (second >= 0) close(second);
            /* A malformed stream: the renderer refuses it and ends; nothing else is affected. */
            int third = gpu_connect();
            uint32_t junk[4] = {0x7fffffff, 0xdeadbeef, 0, 0};
            char byte;
            int refused_junk = third >= 0 && write(third, junk, sizeof(junk)) == (ssize_t) sizeof(junk) &&
                               read(third, &byte, 1) <= 0;
            EXPECT(refused_junk, "gpu proxy: a malformed command stream ends that renderer's connection");
            if (third >= 0) close(third);
            int fourth = gpu_connect();
            EXPECT(fourth >= 0 && gpu_vtest_ping(fourth), "gpu proxy: and the next connection is served as before");
            if (fourth >= 0) close(fourth);
            errno = 0;
            int node = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
            EXPECT(node < 0 && errno == EACCES, "gpu proxy: the client cannot open a GPU node");
            if (node >= 0) close(node);
            if (first >= 0) close(first);
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    /* The renderers' paths were removed once the broker had connected: nothing else can reach them. */
    DIR *dir = opendir(folder);
    int left = 0;
    struct dirent *entry;
    while (dir && (entry = readdir(dir))) {
        if (strncmp(entry->d_name, "vtest-", 6) == 0) left++;
    }
    if (dir) closedir(dir);
    EXPECT(left == 0, "gpu proxy: no renderer's socket is left to connect to");
    EXPECT(__atomic_load_n(&gpu_renderer_requests, __ATOMIC_ACQUIRE) > 0,
           "gpu proxy: each renderer is confined, its file access decided by its own broker");
    /* Mesa's GL driver itself, in a confined process, through the proxy. */
    struct sbx_policy *client_policy = sbx_policy_new();
    sbx_policy_add(client_policy, "/", SBX_READ);
    sbx_policy_add_gpu_proxy(client_policy, &proxy);
    static char *gl_argv[] = {"eglinfo", "-B", "-p", "surfaceless", NULL};
    static char *gl_env[] = {"GALLIUM_DRIVER=virpipe", "VTEST_SOCKET_NAME=" GPU_VTEST_PATH, "EGL_PLATFORM=surfaceless",
                             "MESA_SHADER_CACHE_DISABLE=true", "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};
    int mesa = gpu_mesa_client(helper, library, client_policy, "/usr/bin/eglinfo", gl_argv, gl_env, "renderer: virgl");
    if (mesa < 0) printf("skip gpu proxy: no eglinfo here (mesa-utils) for the Mesa client check\n");
    else EXPECT(mesa == 1, "gpu proxy: Mesa's GL driver, confined, renders through a confined renderer (virgl)");
    /* Vulkan: Mesa's venus driver, through a renderer started with --venus (it runs virgl_render_server itself). */
    const char *icd = "/usr/share/vulkan/icd.d/virtio_icd.json";
    if (access("/usr/bin/vulkaninfo", X_OK) == 0 && access(icd, R_OK) == 0 && access("/usr/libexec/virgl_render_server", X_OK) == 0) {
        static char *venus_args[] = {"--venus", "--use-egl-surfaceless", NULL};
        struct sbx_gpu_proxy venus = proxy;
        venus.renderer_args = venus_args;
        struct sbx_policy *vk_policy = sbx_policy_new();
        sbx_policy_add(vk_policy, "/", SBX_READ);
        sbx_policy_add_gpu_proxy(vk_policy, &venus);
        static char *vk_argv[] = {"vulkaninfo", "--summary", NULL};
        static char *vk_env[] = {"VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/virtio_icd.json", "VN_DEBUG=vtest",
                                 "VTEST_SOCKET_NAME=" GPU_VTEST_PATH, "MESA_SHADER_CACHE_DISABLE=true",
                                 "ASAN_OPTIONS=detect_leaks=0:verify_asan_link_order=0", NULL};
        int vk = gpu_mesa_client(helper, library, vk_policy, "/usr/bin/vulkaninfo", vk_argv, vk_env, "driverName");
        EXPECT(vk == 1, "gpu proxy: Mesa's Vulkan driver (venus), confined, through a confined renderer");
    } else {
        printf("skip gpu proxy: no vulkaninfo, venus ICD or virgl_render_server here for the Vulkan check\n");
    }
    sbx_policy_free(renderer_policy);
    return (failures != before) | (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
#endif
}

/* ---- #767: sbx-exec's handler routes only calls the library's filter sends to the broker. ---- */

static int helper_routes_check(void) {
#define NAME_OF(name) #name,
    static const char *const library[] = {SBX_BROKERED_CALLS(NAME_OF) "renameat", SBX_BROKERED_LEGACY_CALLS(NAME_OF)};
    static const char *const helper[] = {SBXE_HELPER_CALLS(NAME_OF) SBXE_HELPER_LEGACY_CALLS(NAME_OF)};
#undef NAME_OF
    int missing = 0;
    for (size_t i = 0; i < sizeof(helper) / sizeof(helper[0]); i++) {
        int found = 0;
        for (size_t k = 0; k < sizeof(library) / sizeof(library[0]); k++) found |= strcmp(helper[i], library[k]) == 0;
        if (!found) {
            printf("FAIL helper routes: sbx-exec routes %s, which the library's filter does not broker\n", helper[i]);
            missing++;
        }
    }
    if (!missing) printf("ok   helper routes: every call sbx-exec routes is one the library brokers (#767)\n");
    return missing != 0;
}

/* ---- sbx_spawn: a program starts with only what it was handed. ---- */

extern char **environ;

/* Runs in the spawned program (argv[1] == "--spawned"). */
static int spawned_main(void) {
    int bad = 0;
    if (sbx_spawned_init() != 0) bad |= 1;
    struct stat st;
    if (fstat(3, &st) != 0 || !S_ISFIFO(st.st_mode)) bad |= 2;
    DIR *fds = opendir("/proc/self/fd");
    if (!fds) {
        bad |= 4;
    } else {
        struct dirent *entry;
        while ((entry = readdir(fds))) {
            if (entry->d_name[0] == '.') continue;
            int fd = atoi(entry->d_name);
            if (fd > 3 && fd != dirfd(fds)) bad |= 8;
        }
        closedir(fds);
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur != 64) bad |= 16;
    if (environ && environ[0]) bad |= 32;
    if (prctl(PR_GET_DUMPABLE) != 0) bad |= 64;
    char word[8];
    snprintf(word, sizeof(word), "ok%d", bad);
    ssize_t ignored = write(3, word, strlen(word));
    (void) ignored;
    return bad ? 1 : 0;
}

/*
 * Runs in a program started by sbx_spawn_confined (argv[1] == "--spawned-confined").
 * It never locks itself down: sbx_spawn_confined did that before this code
 * ran. So if the granted file opens and the secret is refused, the program
 * was already confined from its first instruction. Reports on descriptor 3.
 */
static int spawned_confined_main(int argc, char **argv) {
    if (argc < 4) return 2;
    int ok = 1;
    int granted = open(argv[2], O_RDONLY);
    ok &= granted >= 0;
    if (granted >= 0) close(granted);
    errno = 0;
    int secret_fd = open(argv[3], O_RDONLY);
    ok &= secret_fd < 0 && errno == EACCES;
    if (secret_fd >= 0) close(secret_fd);
    const char *word = ok ? "confined" : "leak";
    ssize_t ignored = write(3, word, strlen(word));
    (void) ignored;
    return ok ? 0 : 1;
}

static int spawn_check(const char *self) {
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) return 1;
    int leak = open("/dev/null", O_RDONLY);  /* inheritable, and must not be inherited */
    char *argv[] = {(char *) self, "--spawned", NULL};
    struct sbx_limit limit = {RLIMIT_NOFILE, 64};
    struct sbx_spawn_spec spec = {self, argv, NULL, &pipe_fds[1], 1, &limit, 1};
    pid_t pid = 0;
    int started = sbx_spawn(&spec, &pid);
    close(pipe_fds[1]);
    close(leak);
    errno = -started;
    EXPECT(started == 0 && pid > 0, "sbx_spawn starts the program");
    char word[16] = {0};
    ssize_t n = read(pipe_fds[0], word, sizeof(word) - 1);
    close(pipe_fds[0]);
    int status = 0;
    if (pid > 0) waitpid(pid, &status, 0);
    if (n > 0) word[n] = 0;
    EXPECT(strcmp(word, "ok0") == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "the spawned program holds only 0-3, its limit, an empty environment and is not dumpable");
    if (strcmp(word, "ok0") != 0) printf("info spawned program reported %s\n", word);
    char *missing_argv[] = {"/nonexistent", NULL};
    struct sbx_spawn_spec missing = {"/nonexistent/program", missing_argv, NULL, NULL, 0, NULL, 0};
    errno = 0;
    started = sbx_spawn(&missing, NULL);
    errno = -started;
    EXPECT(started == -ENOENT, "sbx_spawn reports the child's exec error");
    return failures ? 1 : 0;
}
