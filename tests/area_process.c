/*
 * sbx_test, area "process": confinement of the process itself: sealing, SIGSYS, learning and its trace, the signal tree, limits, terminal ioctls, the ioctl allowlist.
 * Included by tests/sbx_test.c, one translation unit with the harness (tests/sbx_test.h);
 * SBX_TEST_AREA=process runs this area alone (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

/* ---- Sealed descriptors, in a process of their own. ---- */

static int sealed_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int fd = open("/dev/null", O_RDWR);
        int keep = open("/dev/zero", O_RDONLY);
        struct sbx_lockdown_options options = {.sealed_fds = &fd, .sealed_count = 1};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "lockdown with a sealed descriptor");
        if (locked != 0) _exit(1);
        int n = 0;
        errno = 0;
        EXPECT(ioctl(fd, FIONREAD, &n) < 0 && errno == EPERM, "sealed: ioctl refused");
        errno = 0;
        EXPECT(dup(fd) < 0 && errno == EPERM, "sealed: dup refused");
        errno = 0;
        EXPECT(dup3(fd, 100, 0) < 0 && errno == EPERM, "sealed: dup3 refused");
        errno = 0;
        EXPECT(fcntl(fd, F_DUPFD_CLOEXEC, 0) < 0 && errno == EPERM, "sealed: fcntl(F_DUPFD) refused");
        errno = 0;
        EXPECT(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == EPERM, "sealed: mmap refused");
        EXPECT(ioctl(keep, FIONREAD, &n) >= 0 || errno != EPERM, "an unsealed descriptor keeps its ioctl");
        void *mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, keep, 0);
        EXPECT(mapped != MAP_FAILED, "an unsealed descriptor keeps its mmap");
        EXPECT(close(fd) == 0, "sealed: close allowed");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/*
 * ---- readlink of the process's own descriptor link, answered in the process. ----
 * The broker would read /proc/<pid>/fd of a process that is not dumpable, which
 * the kernel refuses a broker without CAP_SYS_PTRACE; bionic's realpath()
 * depends on this readlink. Run unprivileged, as CI does, this fails without
 * the process answering it.
 */
static int own_fd_link_check(void) {
    char data[400], real[PATH_MAX];
    snprintf(data, sizeof(data), "%s/data.txt", game);
    if (!realpath(data, real)) return 1;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        int locked = sbx_lockdown(pair[1], NULL);
        errno = -locked;
        EXPECT(locked == 0, "own fd link: lockdown");
        if (locked != 0) _exit(1);
        int fd = open(data, O_PATH | O_CLOEXEC);
        EXPECT(fd >= 0, "own fd link: open of a granted file");
        char link[64], target[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n >= 0) target[n] = '\0';
        EXPECT(n >= 0 && strcmp(target, real) == 0, "own fd link: readlink of /proc/self/fd/<n> names the file");
        snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
        n = readlinkat(AT_FDCWD, link, target, sizeof(target) - 1);
        if (n >= 0) target[n] = '\0';
        EXPECT(n >= 0 && strcmp(target, real) == 0, "own fd link: readlinkat of /proc/thread-self/fd/<n> names the file");
        /*
         * The O_PATH open came back readable: a received descriptor with neither read nor
         * write is checked as ioctl by SELinux, which an Android app may not do on a system
         * file, so the broker answers a readable regular file with a read-only descriptor.
         */
        int got = fcntl(fd, F_GETFL);
        EXPECT(got >= 0 && !(got & O_PATH) && (got & O_ACCMODE) == O_RDONLY, "O_PATH open of a readable file: a read-only descriptor");
        char byte;
        EXPECT(pread(fd, &byte, 1, 0) == 1, "O_PATH open of a readable file: it reads");
        int folder = open(game, O_PATH | O_DIRECTORY | O_CLOEXEC);
        got = folder >= 0 ? fcntl(folder, F_GETFL) : -1;
        EXPECT(got >= 0 && (got & O_PATH), "O_PATH open of a folder stays an O_PATH handle");
        if (folder >= 0) close(folder);
        /* A name past the number is not a descriptor link: it stays the broker's, which finds no link there. */
        snprintf(link, sizeof(link), "/proc/self/fd/%dx", fd);
        EXPECT(readlink(link, target, sizeof(target)) < 0, "own fd link: a name past the number is not answered as one");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- SIGSYS stays open: a blocked SIGSYS used to kill the process on its next trap. ---- */

/* A handler that makes trapped calls; installed with every signal masked. */
static const char *handler_file;
static volatile int handler_opened = -2;
static void open_in_handler(int signal_number) {
    (void) signal_number;
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_BLOCK, &none, NULL);
    handler_opened = open(handler_file, O_RDONLY | O_CLOEXEC);
}

static void install_masked(int signal_number) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = open_in_handler;
    sigfillset(&action.sa_mask);
    sigaction(signal_number, &action, NULL);
}

/* go[0]: set by the thread once SIGSYS is blocked; go[1]: set by the test to let it end. */
long sbx_learn_call(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

static void *block_sigsys_and_wait(void *arg) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSYS);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    volatile int *go = (volatile int *) arg;
    go[0] = 1;
    while (!go[1]) usleep(1000);
    return NULL;
}

static int sigsys_check(void) {
    /* A file of the test's own: /etc/hostname and /etc/passwd are missing on Android 9's emulator. */
    const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char folder[PATH_MAX], file[PATH_MAX + 16];
    snprintf(folder, sizeof(folder), "%s/sbx-sigsys-XXXXXX", tmp);
    if (!mkdtemp(folder)) return 1;
    snprintf(file, sizeof(file), "%s/allowed", folder);
    int made = open(file, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (made < 0) return 1;
    close(made);
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, folder, SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        /* A thread that blocked SIGSYS before lockdown: refused, not half-installed. */
        /* Waited for, not slept for: a slow emulator may not have run the thread after 50 ms. */
        static volatile int go[2] = {0, 0};
        pthread_t blocker;
        pthread_create(&blocker, NULL, block_sigsys_and_wait, (void *) go);
        while (!go[0]) usleep(1000);
        EXPECT(sbx_lockdown(pair[1], NULL) == -EDEADLK, "sigsys: lockdown refused while a thread has SIGSYS blocked");
        go[1] = 1;
        pthread_join(blocker, NULL);
        handler_file = file;
        install_masked(SIGUSR1);
        int locked_down = sbx_lockdown(pair[1], NULL);
        errno = locked_down < 0 ? -locked_down : 0;  /* EXPECT prints errno: make it the result */
        EXPECT(locked_down == 0, "sigsys: lockdown once no thread blocks SIGSYS");
        raise(SIGUSR1);
        EXPECT(handler_opened >= 0, "sigsys: a handler installed before lockdown with every signal masked makes trapped calls");
        install_masked(SIGUSR2);
        handler_opened = -2;
        raise(SIGUSR2);
        EXPECT(handler_opened >= 0, "sigsys: one installed after lockdown with every signal masked makes them too");
        struct sigaction now_action;
        sigaction(SIGUSR2, NULL, &now_action);
        EXPECT(!sigismember(&now_action.sa_mask, SIGSYS) && sigismember(&now_action.sa_mask, SIGTERM),
               "sigsys: its mask is the one asked, with SIGSYS left out");
        struct sigaction sys_action;
        memset(&sys_action, 0, sizeof(sys_action));
        sys_action.sa_handler = SIG_IGN;
        errno = 0;
        EXPECT(sigaction(SIGSYS, &sys_action, NULL) < 0 && errno == EPERM, "sigsys: a new SIGSYS handler is still refused");
        EXPECT(sbx_learn_call(__NR_rt_sigaction, SIGSYS, (long) &sys_action, 0, 8, 0, 0) == -EPERM,
               "sigsys: and refused through the trampoline too");
        sigset_t set, old, now;
        sigemptyset(&set);
        sigaddset(&set, SIGSYS);
        sigaddset(&set, SIGUSR1);
        EXPECT(pthread_sigmask(SIG_BLOCK, &set, &old) == 0, "sigsys: blocking SIGSYS and SIGUSR1 answers success");
        EXPECT(!sigismember(&old, SIGUSR1), "sigsys: the old mask comes back");
        pthread_sigmask(SIG_BLOCK, NULL, &now);
        EXPECT(sigismember(&now, SIGUSR1), "sigsys: SIGUSR1 is blocked as asked");
        EXPECT(!sigismember(&now, SIGSYS), "sigsys: SIGSYS stays open");
        EXPECT(open(file, O_RDONLY) >= 0, "sigsys: a trapped open after trying to block SIGSYS still works");
        sigfillset(&set);
        EXPECT(pthread_sigmask(SIG_SETMASK, &set, NULL) == 0, "sigsys: setting a full mask answers success");
        pthread_sigmask(SIG_BLOCK, NULL, &now);
        EXPECT(sigismember(&now, SIGUSR1) && !sigismember(&now, SIGSYS), "sigsys: a full mask leaves SIGSYS out");
        EXPECT(open(file, O_RDONLY) >= 0, "sigsys: and a trapped open still works");
        errno = 0;
        EXPECT(syscall(__NR_rt_sigprocmask, 99, &set, NULL, 8) < 0 && errno == EINVAL, "sigsys: a bad how is EINVAL");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) printf("FAIL sigsys: the confined process died by signal %d\n", WTERMSIG(status));
    unlink(file);
    rmdir(folder);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- Learning: nothing refused, everything that would have been recorded. ---- */

long sbx_learn_call(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

struct learned {
    int syscalls;      /* "syscall" records */
    int socket_eacces; /* socket, recorded with EACCES */
    int kill_eperm;    /* kill of another process, recorded with EPERM */
    int unshare_eperm;
    int named_flags;   /* socket naming SBX_LOCK_INET, kill SBX_LOCK_SIGNALS, unshare no flag */
    int path_refused;  /* a path the rules refused, which the decider let through */
};

static void learn_audit(void *context, const struct sbx_access *access, int result) {
    struct learned *seen = context;
    (void) result;
    if (strcmp(access->op, "syscall") == 0) {
        seen->syscalls++;
        if (strncmp(access->asked, "socket(", 7) == 0 && access->rule_verdict == -EACCES) seen->socket_eacces++;
        if (strncmp(access->asked, "kill(", 5) == 0 && access->rule_verdict == -EPERM) seen->kill_eperm++;
        if (strncmp(access->asked, "unshare(", 8) == 0 && access->rule_verdict == -EPERM) seen->unshare_eperm++;
        const char *by = access->allowed_by;
        if (strncmp(access->asked, "socket(", 7) == 0 && by && strcmp(by, "SBX_LOCK_INET") == 0) seen->named_flags |= 1;
        if (strncmp(access->asked, "kill(", 5) == 0 && by && strcmp(by, "SBX_LOCK_SIGNALS") == 0) seen->named_flags |= 2;
        if (strncmp(access->asked, "unshare(", 8) == 0 && !by) seen->named_flags |= 4;
    }
}

/* A learning host's decider: record what the rules refused, allow it. */
static int learn_decide(void *context, const struct sbx_access *access) {
    struct learned *seen = context;
    if (access->rule_verdict < 0) seen->path_refused++;
    return 0;
}

/* Answers one path slowly, so a signal can arrive while the handler waits for the broker. */
static int slow_decide(void *context, const struct sbx_access *access) {
    (void) context;
    if (strcmp(access->asked, "/sbx-trace-slow") == 0) usleep(1000000);
    return access->rule_verdict;
}

static void open_during_sigsys(int signal_number) {
    (void) signal_number;
    int opened = open("/sbx-trace-in-handler", O_RDONLY);
    if (opened >= 0) close(opened);
}

/* The trace ring: each trapped call noted entered, then left, in a file another process reads. */
static int trace_check(void) {
    const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char ring_file[PATH_MAX];
    snprintf(ring_file, sizeof(ring_file), "%s/sbx-trace-XXXXXX", tmp);
    int ring_fd = mkstemp(ring_file);
    if (ring_fd < 0) return 1;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    if (sbx_broker_start(sbx_policy_new(), pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        EXPECT(sbx_trace(ring_fd, 8) == -EINVAL, "trace: too few slots refused");
        EXPECT(sbx_trace(ring_fd, 64) == 0, "trace: ring set up");
        EXPECT(sbx_trace(ring_fd, 64) == -EALREADY, "trace: only once");
        close(ring_fd);
        struct sbx_lockdown_options audited = {.flags = SBX_LOCK_AUDIT};
        int locked_down = sbx_lockdown(pair[1], &audited);
        if (locked_down == -EINVAL) {
            /* Before Linux 4.14 there is no SECCOMP_FILTER_FLAG_LOG; the ring does not need it. */
            printf("info trace: this kernel has no seccomp audit flag; locking down without it\n");
            locked_down = sbx_lockdown(pair[1], NULL);
        }
        EXPECT(locked_down == 0, "trace: lockdown (with the kernel's audit where it has one)");
        int opened = open("/sbx-trace-no-such-file", O_RDONLY);
        if (opened >= 0) close(opened);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    int failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    struct sbx_trace_header header;
    int got = pread(ring_fd, &header, sizeof(header), 0) == (ssize_t) sizeof(header);
    int header_ok = got && header.magic == SBX_TRACE_MAGIC && header.version == SBX_TRACE_VERSION &&
                    header.slots == 64 && header.pid == child && header.locked == 1 && header.next >= 1;
    printf("%s trace: the header names the process, locked, with %u entries\n", header_ok ? "ok  " : "FAIL",
           got ? header.next : 0);
    int found = 0;
    for (uint32_t i = 0; header_ok && i < header.next && i < header.slots; i++) {
        struct sbx_trace_entry entry;
        if (pread(ring_fd, &entry, sizeof(entry), (off_t) (sizeof(header) + i * sizeof(entry))) != (ssize_t) sizeof(entry)) break;
#ifdef __NR_open
        int is_open = entry.nr == __NR_openat || entry.nr == __NR_open;
#else
        int is_open = entry.nr == __NR_openat;
#endif
        if (is_open && entry.seq != 0 && (entry.state & 0xff) == SBX_TRACE_LEFT && entry.tid == child &&
            entry.ip != 0 && (entry.state >> 8) == 0x5b0)
            found = 1;
    }
    printf("%s trace: the open was noted, entered and left, with its thread, address and trap data\n",
           found ? "ok  " : "FAIL");

    /*
     * A trapped call made while the handler waits for the broker, by another
     * signal's handler on the same thread (ART's signal chain does this with
     * sigprocmask). With SIGSYS blocked for the handler's duration the
     * kernel ended the process with signal 31; the handler now takes it as a
     * nested entry. Meanwhile another process reading the ring sees the
     * waiting call marked entered and not left, which is what a death in the
     * handler leaves behind.
     */
    int slow_pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, slow_pair) != 0) return 1;
    struct sbx_policy *slow = sbx_policy_new();
    sbx_policy_set_decider(slow, slow_decide, NULL);
    if (sbx_broker_start(slow, slow_pair[0]) != 0) return 1;
    fflush(stdout);
    child = fork();
    if (child == 0) {
        signal(SIGUSR1, open_during_sigsys);
        if (sbx_trace(ring_fd, 64) != 0 || sbx_lockdown(slow_pair[1], NULL) != 0) _exit(2);
        int opened = open("/sbx-trace-slow", O_RDONLY);
        if (opened >= 0) close(opened);
        _exit(3);
    }
    close(slow_pair[1]);
    usleep(300000);
    int waiting = 0;
    got = pread(ring_fd, &header, sizeof(header), 0) == (ssize_t) sizeof(header);
    for (uint32_t i = 0; got && i < header.next && i < header.slots; i++) {
        struct sbx_trace_entry entry;
        if (pread(ring_fd, &entry, sizeof(entry), (off_t) (sizeof(header) + i * sizeof(entry))) != (ssize_t) sizeof(entry)) break;
        if (entry.seq != 0 && (entry.state & 0xff) == SBX_TRACE_ENTERED && entry.tid == child) waiting++;
    }
    printf("%s trace: a call the handler is still handling is marked entered, not left (%d)\n",
           waiting == 1 ? "ok  " : "FAIL", waiting);
    kill(child, SIGUSR1);
    waitpid(child, &status, 0);
    int survived = WIFEXITED(status) && WEXITSTATUS(status) == 3;
    printf("%s trace: a trapped call from a signal handler that interrupted the handler is handled (status %#x)\n",
           survived ? "ok  " : "FAIL", status);
    int left = 0, open_left = 0;
    got = pread(ring_fd, &header, sizeof(header), 0) == (ssize_t) sizeof(header);
    for (uint32_t i = 0; got && i < header.next && i < header.slots; i++) {
        struct sbx_trace_entry entry;
        if (pread(ring_fd, &entry, sizeof(entry), (off_t) (sizeof(header) + i * sizeof(entry))) != (ssize_t) sizeof(entry)) break;
        if (entry.seq == 0 || entry.tid != child) continue;
        if ((entry.state & 0xff) == SBX_TRACE_LEFT) left++;
        else open_left++;
    }
    printf("%s trace: both the waiting call and the nested one were left (%d left, %d not)\n",
           left >= 2 && open_left == 0 ? "ok  " : "FAIL", left, open_left);
    int killed = !survived, stuck = waiting != 1 || left < 2 || open_left != 0;
    close(ring_fd);
    unlink(ring_file);
    return failed | !header_ok | !found | killed | stuck;
}

/* The fault test's handler: notes the fault, then lets the default action end the process. */
static void note_fault(int signal_number, siginfo_t *info, void *context) {
    sbx_trace_fault(signal_number, info, context);
    signal(signal_number, SIG_DFL);
}

/* Not inlined, so the unwind has a caller to find above it. */
__attribute__((noinline)) static void fault_here(volatile int *where) {
    *where = 1;
}

__attribute__((noinline)) static void fault_caller(volatile int *where) {
    fault_here(where);
    __asm__ volatile("" ::: "memory");
}

/* The recorder's frame-pointer walk alone, without the unwind (src/internal.h). */
extern int sbx_trace_fault_frame_pointers_only;

/*
 * A fatal signal in a locked-down process: its place and its callers noted
 * after the ring's entries. [frame_pointers] runs it with the walk of the
 * thread's frame records alone, which is what a device whose unwinder stops
 * at the signal chain gets.
 */
static int fault_check(const char *program_path, int frame_pointers) {
    const char *how = frame_pointers ? "fault (frame pointers)" : "fault";
    const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char ring_file[PATH_MAX];
    snprintf(ring_file, sizeof(ring_file), "%s/sbx-fault-XXXXXX", tmp);
    int ring_fd = mkstemp(ring_file);
    if (ring_fd < 0) return 1;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    if (sbx_broker_start(sbx_policy_new(), pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_sigaction = note_fault;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGSEGV, &action, NULL) != 0) _exit(2);
        sbx_trace_fault_frame_pointers_only = frame_pointers;
        if (sbx_trace(ring_fd, 16) != 0 || sbx_lockdown(pair[1], NULL) != 0) _exit(2);
        fault_caller((volatile int *) (uintptr_t) 0x10);
        _exit(3);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    int died = WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
    printf("%s %s: the process still dies of the signal (status %#x)\n", died ? "ok  " : "FAIL", how, status);
    struct sbx_trace_fault fault;
    memset(&fault, 0, sizeof(fault));
    int got = pread(ring_fd, &fault, sizeof(fault), (off_t) SBX_TRACE_FAULT_OFFSET(16)) == (ssize_t) sizeof(fault);
    int noted = got && fault.state == SBX_TRACE_LEFT && fault.signal == SIGSEGV && fault.tid == child &&
                fault.address == 0x10 && fault.pc != 0 && fault.frames >= 1 && fault.frame[0].pc == fault.pc;
    printf("%s %s: noted whole, with its signal, thread, address and place (%u frames)\n",
           noted ? "ok  " : "FAIL", how, got ? fault.frames : 0);
    const char *self = strrchr(program_path, '/') ? strrchr(program_path, '/') + 1 : program_path;
    int named = noted && fault.frame[0].base != 0 && strcmp(fault.frame[0].module, self) == 0;
    printf("%s %s: the place is named by its file (%s) and load address\n", named ? "ok  " : "FAIL", how,
           noted ? fault.frame[0].module : "");
    /* The caller: a return address inside fault_caller, below where fault_here starts. */
    int unwound = 0;
    for (uint32_t k = 1; noted && k < fault.frames; k++) {
        uint64_t pc = fault.frame[k].pc;
        if (pc > (uint64_t) (uintptr_t) fault_caller && pc < (uint64_t) (uintptr_t) fault_caller + 256) unwound = 1;
    }
    printf("%s %s: the record reaches past the signal into the caller\n", unwound ? "ok  " : "FAIL", how);
    for (uint32_t k = 0; !unwound && noted && k < fault.frames; k++)
        printf("info %s: #%u %#llx %s+%#llx (caller at %#llx)\n", how, k, (unsigned long long) fault.frame[k].pc,
               fault.frame[k].module, (unsigned long long) (fault.frame[k].pc - fault.frame[k].base),
               (unsigned long long) (uintptr_t) fault_caller);
    close(ring_fd);
    unlink(ring_file);
    return !died | !noted | !named | !unwound;
}

static int learn_check(void) {
    const char *tmp = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    char folder[PATH_MAX], file[PATH_MAX + 32];
    snprintf(folder, sizeof(folder), "%s/sbx-learn-XXXXXX", tmp);
    if (!mkdtemp(folder)) return 1;
    snprintf(file, sizeof(file), "%s/not-in-the-rules", folder);
    int made = open(file, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (made < 0) return 1;
    close(made);
    int failed = 0;
    static struct learned seen;
    memset(&seen, 0, sizeof(seen));
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_set_audit(policy, learn_audit, &seen);
    sbx_policy_set_decider(policy, learn_decide, &seen);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) {
        struct sbx_lockdown_options learning = {.flags = SBX_LOCK_LEARN | SBX_LOCK_UNBROKERED};
        EXPECT(sbx_lockdown(-1, &learning) == -EINVAL, "learn: not without the broker");
        learning.flags = SBX_LOCK_LEARN;
        EXPECT(sbx_lockdown(pair[1], &learning) == 0, "learn: lockdown");
        int s = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT(s >= 0 || errno == EAFNOSUPPORT, "learn: socket made, not refused");
        if (s >= 0) close(s);
        EXPECT(kill(parent, 0) == 0, "learn: a signal to another process is sent");
        EXPECT(unshare(0) == 0, "learn: unshare made");
        EXPECT(open(file, O_RDONLY) >= 0, "learn: a path the rules refuse is opened (the decider allowed it)");
        char *const no_arguments[] = {"true", NULL};
        errno = 0;
        EXPECT(execve("/bin/true", no_arguments, NULL) < 0 && errno == EACCES,
               "learn: exec is recorded and still refused (the new program would have no handler)");
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_IGN;
        errno = 0;
        EXPECT(sigaction(SIGSYS, &action, NULL) < 0 && errno == EPERM, "learn: a new SIGSYS handler is still refused");
        errno = 0;
        EXPECT(syscall(__NR_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0) < 0 && errno == EPERM,
               "learn: clone into a new namespace is still refused");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failed = 1;
    if (WIFSIGNALED(status)) printf("FAIL learn: the learning process died by signal %d\n", WTERMSIG(status));
    usleep(100000);  /* the broker's thread audits each record before it answers; let the last land */
    int socket_ok = seen.socket_eacces >= 1;
    printf("%s learn: socket recorded with EACCES (%d)\n", socket_ok ? "ok  " : "FAIL", seen.socket_eacces);
    printf("%s learn: kill of another process recorded with EPERM (%d)\n", seen.kill_eperm >= 1 ? "ok  " : "FAIL", seen.kill_eperm);
    printf("%s learn: unshare recorded with EPERM (%d)\n", seen.unshare_eperm >= 1 ? "ok  " : "FAIL", seen.unshare_eperm);
    printf("%s learn: the refused path reached the decider (%d)\n", seen.path_refused >= 1 ? "ok  " : "FAIL", seen.path_refused);
    int named = seen.named_flags == 7;
    printf("%s learn: the records name the flag that allows each call (socket SBX_LOCK_INET, kill SBX_LOCK_SIGNALS, "
           "unshare none: %#x)\n", named ? "ok  " : "FAIL", (unsigned) seen.named_flags);
    failed |= !socket_ok || seen.kill_eperm < 1 || seen.unshare_eperm < 1 || seen.path_refused < 1 || !named;

    /* A real lockdown refuses the same calls, and does not let the trampoline through. */
    int real_pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, real_pair) != 0) return 1;
    if (sbx_broker_start(sbx_policy_new(), real_pair[0]) != 0) return 1;
    fflush(stdout);
    child = fork();
    if (child == 0) {
        EXPECT(sbx_lockdown(real_pair[1], NULL) == 0, "learn control: a real lockdown");
        errno = 0;
        EXPECT(socket(AF_INET, SOCK_STREAM, 0) < 0 && errno == EACCES, "learn control: socket refused");
        errno = 0;
        EXPECT(unshare(0) < 0 && errno == EPERM, "learn control: unshare refused");
        EXPECT(sbx_learn_call(__NR_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0) == -EACCES,
               "learn control: the trampoline is refused like any other call");
        _exit(failures ? 1 : 0);
    }
    close(real_pair[1]);
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failed = 1;
    unlink(file);
    rmdir(folder);
    return failed;
}

/* ---- SBX_LOCK_SIGNAL_TREE: signals judged by the broker, within the tree it serves. ---- */

static int signal_tree_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    pid_t outside = getpid();
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_SIGNAL_TREE | SBX_LOCK_SIGNALS};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "signal tree: not with SBX_LOCK_SIGNALS");
        options.flags = SBX_LOCK_SIGNAL_TREE;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "signal tree: lockdown");
        if (locked != 0) _exit(1);
        /* A request of its own makes this process a member of the tree. */
        char data[400];
        snprintf(data, sizeof(data), "%s/data.txt", game);
        int fd = open(data, O_RDONLY);
        if (fd >= 0) close(fd);
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = on_usr1;
        sigaction(SIGUSR1, &action, NULL);
        pid_t member = getpid();
        int ready[2];
        if (pipe(ready) != 0) _exit(1);
        fflush(stdout);
        pid_t grandchild = fork();
        if (grandchild == 0) {
            close(ready[0]);
            usr1_seen = 0;
            errno = 0;
            EXPECT(kill(getpid(), SIGUSR1) == 0 && usr1_seen, "signal tree: a forked child signals itself");
            errno = 0;
            EXPECT(kill(member, 0) == 0, "signal tree: and the process it came from (a member)");
            errno = 0;
            EXPECT(kill(outside, 0) < 0 && errno == EPERM, "signal tree: a process outside the tree refused (EPERM)");
            errno = 0;
            EXPECT(kill(0, 0) < 0 && errno == EPERM, "signal tree: its process group refused (EPERM)");
            errno = 0;
            EXPECT(syscall(__NR_tkill, (pid_t) syscall(__NR_gettid), 0) == 0, "signal tree: tkill of its own thread");
            fflush(stdout);
            (void) !write(ready[1], "r", 1);
            pause();
            _exit(failures ? 1 : 0);
        }
        close(ready[1]);
        char byte;
        (void) !read(ready[0], &byte, 1);
        errno = 0;
        EXPECT(kill(grandchild, SIGTERM) == 0, "signal tree: a member signals its own child (a descendant)");
        int status = 0;
        waitpid(grandchild, &status, 0);
        EXPECT(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "signal tree: and the child got it");
        errno = 0;
        EXPECT(kill(1, 0) < 0 && errno == EPERM, "signal tree: init refused (EPERM)");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (WIFSIGNALED(status)) printf("FAIL signal tree: the child died by signal %d\n", WTERMSIG(status));
    EXPECT(ok, "signal tree: the checks in the confined tree passed");
    return !ok;
}

/* ---- Resource budgets on the lockdown path (review A-18): rlimits set before the filter. ---- */

static int limits_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sbx_limit lim = {RLIMIT_NOFILE, 64};
        /* Validated before anything is installed: too many budgets is refused (checked while still unlocked). */
        struct sbx_lockdown_options toomany = {.flags = SBX_LOCK_UNBROKERED, .limits = &lim, .limit_count = SBX_LIMITS_MAX + 1};
        EXPECT(sbx_lockdown(-1, &toomany) == -EINVAL, "limits: too many budgets is refused");
        /* Before this change sbx_lockdown set no limits (only sbx_spawn did); now the options carry them (A-18). */
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED, .limits = &lim, .limit_count = 1};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "limits: unbrokered lockdown carrying an rlimit");
        if (locked != 0) _exit(1);
        struct rlimit got;
        EXPECT(getrlimit(RLIMIT_NOFILE, &got) == 0 && got.rlim_cur == 64 && got.rlim_max == 64,
               "limits: RLIMIT_NOFILE is set to the budget, soft and hard");
        /* The budget bites: once the open descriptors reach the limit, a further open answers EMFILE. */
        int hit_emfile = 0;
        for (int i = 0; i < 256 && !hit_emfile; i++) {
            int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fd < 0) hit_emfile = (errno == EMFILE);
        }
        EXPECT(hit_emfile, "limits: opening past RLIMIT_NOFILE answers EMFILE");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int tiocsti_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30);
        int fds[2];
        if (pipe(fds) != 0) _exit(70);
        char c = 'x';
        /* Control: unconfined, a pipe is not a tty, so TIOCSTI fails but not with EPERM. */
        errno = 0;
        EXPECT(ioctl(fds[0], TIOCSTI, &c) < 0 && errno != EPERM, "tiocsti: unconfined TIOCSTI is not EPERM");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "tiocsti: lockdown");
        if (locked != 0) _exit(1);
        errno = 0;
        EXPECT(ioctl(fds[0], TIOCSTI, &c) < 0 && errno == EPERM, "tiocsti: TIOCSTI refused with EPERM");
        errno = 0;
        EXPECT(ioctl(fds[0], TIOCLINUX, &c) < 0 && errno == EPERM, "tiocsti: TIOCLINUX refused with EPERM");
        /* A harmless ioctl still reaches the kernel: FIONREAD on the pipe succeeds. */
        int pending = -1;
        errno = 0;
        EXPECT(ioctl(fds[0], FIONREAD, &pending) == 0, "tiocsti: a harmless ioctl still works");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- The ioctl allowlist (sbx_lockdown_options.ioctl_allow; Droidtop/tracker#815). ---- */

static int ioctl_learned;
static void ioctl_audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    (void) result;
    if (access->allowed_by && strcmp(access->allowed_by, "ioctl_allow") == 0) __atomic_add_fetch(&ioctl_learned, 1, __ATOMIC_ACQ_REL);
}

/* Sends fd over a socketpair and back: the same open file under a new number (review A-24). */
static int ioctl_reimport(int fd) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) return -1;
    char byte = 'x';
    struct iovec part = {&byte, 1};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &part;
    m.msg_iovlen = 1;
    m.msg_control = control.buffer;
    m.msg_controllen = sizeof(control.buffer);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    int copy = -1;
    if (sendmsg(pair[0], &m, 0) == 1) {
        m.msg_controllen = sizeof(control.buffer);
        if (recvmsg(pair[1], &m, MSG_CMSG_CLOEXEC) == 1) {
            c = CMSG_FIRSTHDR(&m);
            if (c && c->cmsg_type == SCM_RIGHTS) memcpy(&copy, CMSG_DATA(c), sizeof(int));
        }
    }
    close(pair[0]);
    close(pair[1]);
    return copy;
}

static int ioctl_run(int learn) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_set_audit(policy, ioctl_audit, NULL);
    sbx_broker_prepare(pair[0]);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30);
        close(pair[0]);
        int sock[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sock) != 0) _exit(2);
        int on = 1, queued = -1;
        if (!learn) {
            EXPECT(ioctl(sock[0], FIONREAD, &queued) == 0 && ioctl(sock[0], FIONBIO, &on) == 0,
                   "ioctl allow control: FIONREAD and FIONBIO work unconfined");
            uint32_t too_many[SBX_IOCTL_ALLOW_MAX + 1] = {0};
            struct sbx_lockdown_options bad = {.flags = 0, .ioctl_allow = too_many, .ioctl_allow_count = SBX_IOCTL_ALLOW_MAX + 1};
            EXPECT(sbx_lockdown(pair[1], &bad) == -EINVAL, "ioctl allow: more than SBX_IOCTL_ALLOW_MAX requests is refused");
        }
        static const uint32_t allow[] = {FIONREAD, TIOCSTI};
        struct sbx_lockdown_options options = {.flags = learn ? SBX_LOCK_LEARN : 0, .ioctl_allow = allow, .ioctl_allow_count = 2};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, learn ? "ioctl allow, learning: lockdown" : "ioctl allow: lockdown");
        if (locked == 0 && !learn) {
            EXPECT(ioctl(sock[0], FIONREAD, &queued) == 0, "ioctl allow: a listed request works");
            errno = 0;
            EXPECT(ioctl(sock[0], FIONBIO, &on) < 0 && errno == EPERM, "ioctl allow: a request not listed is refused");
            int copy = ioctl_reimport(sock[0]);
            errno = 0;
            EXPECT(copy >= 0 && ioctl(copy, FIONBIO, &on) < 0 && errno == EPERM,
                   "ioctl allow: the same descriptor under a new number (SCM_RIGHTS) is refused too");
            char c = 'x';
            errno = 0;
            EXPECT(ioctl(sock[0], TIOCSTI, &c) < 0 && errno == EPERM, "ioctl allow: TIOCSTI stays refused even when listed");
        }
        if (locked == 0 && learn) {
            EXPECT(ioctl(sock[0], FIONBIO, &on) == 0, "ioctl allow, learning: a request not listed is let through");
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

static int ioctl_allow_check(void) {
    struct sbx_report report;
    memset(&report, 0, sizeof(report));
    report.size = sizeof(report);
    static const uint32_t one[] = {FIONREAD};
    struct sbx_lockdown_options listed = {.flags = 0, .ioctl_allow = one, .ioctl_allow_count = 1};
    struct sbx_requirements need = {.size = sizeof(need), .required = SBX_G_IOCTL_ALLOWLIST};
    EXPECT(sbx_negotiate(NULL, &listed, &need, &report) == 0 && (report.effective & SBX_G_IOCTL_ALLOWLIST),
           "ioctl allow: the contract reports the allowlist");
    struct sbx_lockdown_options none = {.flags = 0};
    memset(&report, 0, sizeof(report));
    report.size = sizeof(report);
    EXPECT(sbx_negotiate(NULL, &none, &need, &report) == -EPERM, "ioctl allow: without one, a requirement for it is refused");
    int result = ioctl_run(0) | ioctl_run(1);
    int learned = __atomic_load_n(&ioctl_learned, __ATOMIC_ACQUIRE);
    printf("%s ioctl allow, learning: the request was recorded with allowed_by \"ioctl_allow\" (%d)\n",
           learned >= 1 ? "ok  " : "FAIL", learned);
    return result | (learned >= 1 ? 0 : 1);
}
