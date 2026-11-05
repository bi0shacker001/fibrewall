/*
 * SBX_LOCK_COMPUTE (Droidtop/tracker#906): a process that only computes over the descriptors it keeps.
 * Each check runs in a child of its own, which locks down and exits with what it saw (0: as expected),
 * or is ended by the filter; nothing in it prints, since its standard streams are closed.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

#define COMPUTE_KILLED (-1000)

struct compute_case {
    unsigned flags;
    const int *keep;
    unsigned keep_count;
    const struct sbx_limit *limits;
    unsigned limit_count;
};

/* Runs action(arg) in a child locked down as c says: its exit code, COMPUTE_KILLED - signal if a signal ended it. */
static int compute_run(const struct compute_case *c, int (*action)(void *), void *arg) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(20);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_COMPUTE | c->flags, .keep_fds = c->keep,
                                               .keep_count = c->keep_count, .limits = c->limits,
                                               .limit_count = c->limit_count};
        int locked = sbx_lockdown(-1, &options);
        if (locked != 0) _exit(100);
        _exit(action(arg));
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -1;
    if (WIFSIGNALED(status)) return COMPUTE_KILLED - WTERMSIG(status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int c_open(void *arg) {
    (void) arg;
    int fd = open("/etc/hostname", O_RDONLY | O_CLOEXEC);
    return fd < 0 && errno == EACCES ? 0 : 1;
}
static int c_stat(void *arg) {
    (void) arg;
    struct stat st;
    return stat("/", &st) < 0 && errno == EACCES ? 0 : 1;
}
static int c_ioctl(void *arg) {
    int fd = *(int *) arg;
    int n = 0;
    return ioctl(fd, FIONREAD, &n) < 0 && errno == EACCES ? 0 : 1;
}
static int c_socket(void *arg) {
    (void) arg;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    return fd >= 0 ? 0 : 2;  /* reached only when the call is let through (learning) */
}
static int c_exec(void *arg) {
    (void) arg;
    char *argv[] = {(char *) "true", NULL};
    execve("/bin/true", argv, NULL);
    return 1;
}
static int c_fork(void *arg) {
    (void) arg;
    pid_t pid = (pid_t) syscall(__NR_clone, SIGCHLD, 0, 0, 0, 0);
    if (pid == 0) _exit(0);
    return 1;
}
static void *c_thread_body(void *arg) {
    *(int *) arg = 42;
    return NULL;
}
static int c_thread(void *arg) {
    (void) arg;
    pthread_t thread;
    int value = 0;
    if (pthread_create(&thread, NULL, c_thread_body, &value) != 0) return 1;
    pthread_join(thread, NULL);
    return value == 42 ? 0 : 1;
}
static int c_exec_memory(void *arg) {
    (void) arg;
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page != MAP_FAILED || errno != EPERM) return 1;
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 2;
    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) == 0 || errno != EPERM) return 3;
    return mprotect(page, 4096, PROT_READ) == 0 ? 0 : 4;
}
static int c_signal_other(void *arg) {
    pid_t parent = *(pid_t *) arg;
    kill(parent, 0);
    return 1;
}
static volatile sig_atomic_t c_usr1;
static void c_on_usr1(int signal_number) {
    (void) signal_number;
    c_usr1 = 1;
}
static int c_signal_self(void *arg) {
    (void) arg;
    signal(SIGUSR1, c_on_usr1);
    raise(SIGUSR1);
    return c_usr1 ? 0 : 1;
}
/* The kept descriptor works; the other one was closed before the filter went on. */
static int c_kept(void *arg) {
    int *fds = arg;
    if (fcntl(fds[1], F_GETFD) >= 0 || errno != EBADF) return 1;
    return write(fds[0], "k", 1) == 1 ? 0 : 2;
}
#if !(defined(__SANITIZE_ADDRESS__) || SBX_TEST_CLANG_ASAN)
static int c_memory(void *arg) {
    (void) arg;
    void *big = malloc((size_t) 1 << 30);
    return big == NULL ? 0 : 1;
}
#endif
static int c_spin(void *arg) {
    (void) arg;
    for (volatile unsigned long i = 0;; i++) {}
    return 1;
}
/* A descriptor received over the kept socket after lockdown: read from it. */
static int c_receive(void *arg) {
    int sock = *(int *) arg;
    char byte;
    struct iovec part = {&byte, 1};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    struct msghdr message = {.msg_iov = &part, .msg_iovlen = 1, .msg_control = control.buffer,
                             .msg_controllen = sizeof(control.buffer)};
    if (recvmsg(sock, &message, 0) != 1) return 1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    if (!c || c->cmsg_type != SCM_RIGHTS) return 2;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    char text[16] = {0};
    if (pread(fd, text, sizeof(text) - 1, 0) != 6) return 3;
    return strcmp(text, "frames") == 0 ? 0 : 4;
}

static int compute_check(void) {
    const char *name = "compute";
    int before = failures;
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) return 1;
    struct compute_case plain = {0, pipe_fds, 1, NULL, 0};
    struct compute_case learning = {SBX_LOCK_LEARN, NULL, 0, NULL, 0};
    int killed = COMPUTE_KILLED - SIGSYS;

    EXPECT(compute_run(&plain, c_open, NULL) == 0, "compute: an open is refused (EACCES), the process goes on");
    EXPECT(compute_run(&plain, c_stat, NULL) == 0, "compute: a stat is refused (EACCES)");
    EXPECT(compute_run(&plain, c_ioctl, &pipe_fds[0]) == 0, "compute: ioctl is refused (EACCES), even on a kept descriptor");
    EXPECT(compute_run(&plain, c_socket, NULL) == killed, "compute: socket ends the process (SIGSYS)");
    EXPECT(compute_run(&plain, c_exec, NULL) == killed, "compute: exec ends the process");
    EXPECT(compute_run(&plain, c_fork, NULL) == killed, "compute: a fork ends the process");
    pid_t self = getpid();
    EXPECT(compute_run(&plain, c_signal_other, &self) == killed, "compute: a signal to another process ends it");
    EXPECT(compute_run(&plain, c_signal_self, NULL) == 0, "compute: a signal to itself is delivered");
    EXPECT(compute_run(&plain, c_thread, NULL) == 0, "compute: threads start and join (clone3 refused, clone with CLONE_THREAD)");
    EXPECT(compute_run(&plain, c_exec_memory, NULL) == 0, "compute: no executable memory: mmap or mprotect with PROT_EXEC is refused (EPERM)");
    int both[2] = {pipe_fds[1], pipe_fds[0]};
    struct compute_case one_end = {0, &both[0], 1, NULL, 0};
    char got = 0;
    EXPECT(compute_run(&one_end, c_kept, both) == 0 && read(pipe_fds[0], &got, 1) == 1 && got == 'k',
           "compute: a kept descriptor works; every other one was closed");
    EXPECT(compute_run(&learning, c_socket, NULL) != killed,
           "compute: learning lets a call that would end the process through, with a kernel log record");

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0) {
        int memfd = (int) syscall(__NR_memfd_create, "frames", 0);
        if (memfd >= 0 && write(memfd, "frames", 6) == 6) {
            /* Queued before the child starts: it receives it after lockdown. */
            char byte = 'f';
            struct iovec part = {&byte, 1};
            union {
                char buffer[CMSG_SPACE(sizeof(int))];
                struct cmsghdr align;
            } control;
            memset(&control, 0, sizeof(control));
            struct msghdr message = {.msg_iov = &part, .msg_iovlen = 1, .msg_control = control.buffer,
                                     .msg_controllen = sizeof(control.buffer)};
            struct cmsghdr *c = CMSG_FIRSTHDR(&message);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(c), &memfd, sizeof(int));
            ssize_t sent = sendmsg(pair[0], &message, 0);
            struct compute_case control_socket = {0, &pair[1], 1, NULL, 0};
            EXPECT(sent == 1 && compute_run(&control_socket, c_receive, &pair[1]) == 0,
                   "compute: a descriptor sent over the kept socket after lockdown is read (shared memory)");
        }
        if (memfd >= 0) close(memfd);
        close(pair[0]);
        close(pair[1]);
    }

#if defined(__SANITIZE_ADDRESS__) || SBX_TEST_CLANG_ASAN
    printf("skip compute: the memory limit under a sanitizer (its shadow memory is the address space)\n");
#else
    struct sbx_limit memory[] = {{RLIMIT_AS, 256ul << 20}};
    struct compute_case capped = {0, NULL, 0, memory, 1};
    /* glibc's malloc answers NULL; bionic's allocator aborts the process: either way the cap holds. */
    int capped_result = compute_run(&capped, c_memory, NULL);
    EXPECT(capped_result == 0 || capped_result == COMPUTE_KILLED - SIGABRT,
           "compute: the memory limit: a 1 GiB allocation fails (or the allocator aborts) under a 256 MiB cap");
#endif
    struct sbx_limit cpu[] = {{RLIMIT_CPU, 1}};
    struct compute_case timed = {0, NULL, 0, cpu, 1};
    int spun = compute_run(&timed, c_spin, NULL);
    EXPECT(spun == COMPUTE_KILLED - SIGXCPU || spun == COMPUTE_KILLED - SIGKILL,
           "compute: the CPU limit ends a process that spins (SIGXCPU)");

    struct sbx_lockdown_options bad = {.flags = SBX_LOCK_COMPUTE | SBX_LOCK_PASSTHROUGH};
    EXPECT(sbx_lockdown(-1, &bad) == -EINVAL, "compute: with another mode's flag, refused (EINVAL)");
    struct sbx_lockdown_options with_broker = {.flags = SBX_LOCK_COMPUTE};
    EXPECT(sbx_lockdown(pipe_fds[0], &with_broker) == -EINVAL, "compute: with a broker descriptor, refused (EINVAL)");
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    (void) name;
    return failures != before;
}
