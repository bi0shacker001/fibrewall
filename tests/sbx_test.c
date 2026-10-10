/*
 * sbx end to end, on the build host's kernel: a child process locks itself
 * down against a broker in the parent and tries what confined code would,
 * allowed and not.
 *
 * Three parts:
 *   1. Escape attempts, each run once BEFORE lockdown as a control. An
 *      attempt whose control fails on this host proves nothing about the
 *      sandbox, so it is reported as "skip" unless it is marked as one the
 *      host may refuse on its own (then only the confined result counts).
 *   2. What must keep working under lockdown (files in the rules, chdir,
 *      getcwd, aliases, case folding, the host's decider, threads).
 *   3. The same escape attempts again, confined: each must fail, with the
 *      named errno where one is given. Then a symlink race against the
 *      broker; the parent checks afterwards that the file outside the
 *      rules was never truncated.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_statx
#define __NR_statx 332
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static int failures;

#define EXPECT(condition, what)                                                                    \
    do {                                                                                           \
        int saved_ = errno;                                                                        \
        if (condition) printf("ok   %s\n", what);                                                  \
        else { printf("FAIL %s (errno %d %s)\n", what, saved_, strerror(saved_)); failures++; }    \
    } while (0)

static char root[256], game[300], save[300], secret[300], mountpoint[300];
static const char *exec_path = "/bin/true";
static pid_t parent_pid;

static int refused(int result) { return result < 0 && errno == EACCES; }

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(2); }
    fputs(text, f);
    fclose(f);
}

/* ---- Part 1 and 3: escape attempts. Each returns 0 when it succeeded, else the errno. ---- */

static int result_of(long r) { return r < 0 ? errno : 0; }

static int try_socket(int family, int type, int protocol) {
    int fd = socket(family, type, protocol);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}
static int a_inet(void) { return try_socket(AF_INET, SOCK_STREAM, 0); }
static int a_inet6(void) { return try_socket(AF_INET6, SOCK_DGRAM, 0); }
static int a_netlink(void) { return try_socket(AF_NETLINK, SOCK_RAW, 0); }
static int a_unix_stream(void) { return try_socket(AF_UNIX, SOCK_STREAM, 0); }
static int a_unix_dgram(void) { return try_socket(AF_UNIX, SOCK_DGRAM, 0); }

static int try_open(const char *path, int flags) {
    int fd = open(path, flags, 0600);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}
static int a_secret(void) {
    char p[400];
    snprintf(p, sizeof(p), "%s/key", secret);
    return try_open(p, O_RDONLY);
}
static int a_dotdot(void) {
    char p[400];
    snprintf(p, sizeof(p), "%s/../secret/key", game);
    return try_open(p, O_RDONLY);
}
static int a_symlink(void) {
    char p[400];
    snprintf(p, sizeof(p), "%s/escape", game);
    return try_open(p, O_RDONLY);
}
static int a_proc_root(void) {
    char p[500];
    snprintf(p, sizeof(p), "/proc/self/root%s/key", secret);
    return try_open(p, O_RDONLY);
}
static int a_proc_cwd(void) { return try_open("/proc/self/cwd/../secret/key", O_RDONLY); }
static int a_proc_parent(void) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/status", (int) parent_pid);
    return try_open(p, O_RDONLY);
}
static int a_relative_dirfd(void) {
    int dir = open(game, O_RDONLY | O_DIRECTORY);
    if (dir < 0) return errno;
    int fd = openat(dir, "../secret/key", O_RDONLY);
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    close(dir);
    return error;
}
static int a_etc(void) { return try_open("/etc/hostname", O_RDONLY); }
static int a_write_game(void) {
    char p[400];
    snprintf(p, sizeof(p), "%s/data.txt", game);
    return try_open(p, O_WRONLY | O_APPEND);
}
static int a_rename_out(void) {
    char from[400], to[400];
    snprintf(from, sizeof(from), "%s/out.txt", save);
    snprintf(to, sizeof(to), "%s/moved", secret);
    write_file(from, "x");
    int error = result_of(rename(from, to));
    if (error == 0) rename(to, from);
    unlink(from);
    return error;
}
static int a_exec(void) {
    pid_t child = fork();
    if (child < 0) return errno;
    if (child == 0) {
        char *argv[] = {(char *) exec_path, NULL};
        execve(exec_path, argv, NULL);
        _exit(errno);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : EINTR;
}
/* Runs fn in a child process, so what it changes (a namespace, a tracer) does not outlive it. */
static int in_child(int (*fn)(void)) {
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return errno;
    if (child == 0) _exit(fn());
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : EINTR;
}
/* Attaching to the broker itself would stop it, so the target is a short-lived child of ours. */
static int a_ptrace(void) {
    pid_t target = fork();
    if (target < 0) return errno;
    if (target == 0) {
        sleep(2);
        _exit(0);
    }
    long attached = ptrace(PTRACE_ATTACH, target, NULL, NULL);
    int error = attached < 0 ? errno : 0;
    if (attached == 0) {
        waitpid(target, NULL, 0);
        ptrace(PTRACE_DETACH, target, NULL, NULL);
    }
    waitpid(target, NULL, 0);
    return error;
}
static int a_vm_read(void) {
    char local[8], remote[8];
    struct iovec l = {local, sizeof(local)}, r = {remote, sizeof(remote)};
    return result_of(process_vm_readv(parent_pid, &l, 1, &r, 1, 0));
}
static int a_kill_parent(void) { return result_of(kill(parent_pid, 0)); }
static int a_kill_group(void) { return result_of(kill(0, 0)); }
static int a_io_uring(void) {
    char params[120];
    memset(params, 0, sizeof(params));
    long fd = syscall(__NR_io_uring_setup, 1, params);
    if (fd < 0) return errno;
    close((int) fd);
    return 0;
}
static int a_bpf(void) {
    char attr[128];
    memset(attr, 0, sizeof(attr));
    long fd = syscall(__NR_bpf, 0 /* BPF_MAP_CREATE */, attr, sizeof(attr));
    if (fd < 0) return errno;
    close((int) fd);
    return 0;
}
static int do_unshare(void) { return result_of(unshare(CLONE_NEWUSER)); }
static int a_unshare(void) { return in_child(do_unshare); }
static int clone_child(void *argument) { (void) argument; return 0; }
static int a_clone_newns(void) {
    static char stack[64 * 1024];
    pid_t child = clone(clone_child, stack + sizeof(stack), CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD, NULL);
    if (child < 0) return errno;
    waitpid(child, NULL, 0);
    return 0;
}
static int do_mount(void) { return result_of(mount("none", mountpoint, "tmpfs", 0, NULL)); }
static int a_mount(void) { return in_child(do_mount); }
static int a_keyctl(void) { return result_of(syscall(__NR_keyctl, 0 /* GET_KEYRING_ID */, -3 /* SESSION */, 0)); }
static int a_sigsys(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    struct sigaction old;
    if (sigaction(SIGSYS, &action, &old) != 0) return errno;
    sigaction(SIGSYS, &old, NULL);
    return 0;
}
static int a_permissive_filter(void) {
    /* A filter that allows everything can be added, but it cannot widen the one below it. */
    struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog program = {.len = 1, .filter = &allow};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return errno;
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) return errno;
    return a_secret();
}
#ifdef __x86_64__
static int a_x32(void) { return result_of(syscall(__NR_getpid | 0x40000000)); }
static int a_int80(void) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(20L /* i386 getpid */) : "memory");
    return r < 0 && r > -4096 ? (int) -r : 0;
}
#endif

struct attempt {
    const char *name;
    int (*run)(void);
    int expect;          /* the errno when confined; 0 means any failure */
    int host_may_refuse; /* the control may fail on a host that forbids it anyway */
    int control;         /* filled in: the unconfined result */
};

static struct attempt attempts[] = {
    {"socket(AF_INET)", a_inet, EACCES, 0, 0},
    {"socket(AF_INET6)", a_inet6, EACCES, 0, 0},
    {"socket(AF_NETLINK)", a_netlink, EACCES, 0, 0},
    {"socket(AF_UNIX, SOCK_STREAM)", a_unix_stream, EACCES, 0, 0},
    {"socket(AF_UNIX, SOCK_DGRAM) without SBX_LOCK_LOG_SOCKET", a_unix_dgram, EACCES, 0, 0},
    {"open a file outside the rules", a_secret, EACCES, 0, 0},
    {"open through \"..\" out of a rule", a_dotdot, EACCES, 0, 0},
    {"open through a symlink out of a rule", a_symlink, EACCES, 0, 0},
    {"open through /proc/self/root", a_proc_root, EACCES, 0, 0},
    {"open through /proc/self/cwd/..", a_proc_cwd, 0, 0, 0},
    {"open another process's /proc entry", a_proc_parent, EACCES, 0, 0},
    {"openat \"..\" from a directory descriptor", a_relative_dirfd, EACCES, 0, 0},
    {"open /etc/hostname", a_etc, EACCES, 1, 0},
    {"open a read-only file for writing", a_write_game, EACCES, 0, 0},
    {"rename out of a writable rule", a_rename_out, EACCES, 0, 0},
    {"execve", a_exec, EACCES, 0, 0},
    {"ptrace(ATTACH) a child", a_ptrace, EACCES, 1, 0},
    {"process_vm_readv the parent", a_vm_read, EACCES, 1, 0},
    {"kill the parent", a_kill_parent, EPERM, 0, 0},
    {"kill the process group", a_kill_group, EPERM, 0, 0},
    {"io_uring_setup", a_io_uring, EACCES, 1, 0},
    {"bpf", a_bpf, EACCES, 1, 0},
    {"unshare(CLONE_NEWUSER)", a_unshare, EPERM, 1, 0},
    {"clone(CLONE_NEWUSER|CLONE_NEWNS)", a_clone_newns, EPERM, 1, 0},
    {"mount", a_mount, EPERM, 1, 0},
    {"keyctl", a_keyctl, EPERM, 1, 0},
    {"replace the SIGSYS handler", a_sigsys, EPERM, 0, 0},
#ifdef __x86_64__
    {"x32 system call", a_x32, EACCES, 1, 0},
    {"int 0x80 (i386 entry)", a_int80, EACCES, 1, 0},
#endif
    /* Last: it adds a filter for good. */
    {"a permissive filter on top, then a file outside the rules", a_permissive_filter, EACCES, 0, 0},
};
#define ATTEMPTS (sizeof(attempts) / sizeof(attempts[0]))

static void controls(void) {
    /* The permissive-filter attempt would stay installed, so its control is the plain open. */
    for (size_t i = 0; i < ATTEMPTS; i++) {
        attempts[i].control = attempts[i].run == a_permissive_filter ? a_secret() : attempts[i].run();
    }
}

static void confined_attempts(void) {
    for (size_t i = 0; i < ATTEMPTS; i++) {
        struct attempt *a = &attempts[i];
        if (a->control != 0 && !a->host_may_refuse) {
            printf("skip %s (the host refuses it unconfined: %s)\n", a->name, strerror(a->control));
            continue;
        }
        int result = a->run();
        char what[200];
        snprintf(what, sizeof(what), "confined: %s refused%s%s", a->name, a->expect ? " with " : "",
                 a->expect ? strerror(a->expect) : "");
        errno = result;
        EXPECT(result != 0 && (a->expect == 0 || result == a->expect), what);
    }
}

/* ---- Part 2: what must keep working. ---- */

static void *thread_open(void *argument) {
    char path[400];
    snprintf(path, sizeof(path), "%s/data.txt", game);
    int fd = open(path, O_RDONLY);
    *(int *) argument = fd >= 0;
    if (fd >= 0) close(fd);
    return NULL;
}

static void working(void) {
    char path[512], path2[512], buffer[512];
    struct stat st;

    snprintf(path, sizeof(path), "%s/data.txt", game);
    int fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "game file opens for reading");
    if (fd >= 0) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        EXPECT(n == 5 && memcmp(buffer, "hello", 5) == 0, "game file reads through the brokered descriptor");
        close(fd);
    }
    EXPECT(stat(path, &st) == 0 && st.st_size == 5, "stat of a game file");
    fd = open("data.txt", O_RDONLY);
    EXPECT(fd >= 0, "relative path from the starting directory");
    if (fd >= 0) close(fd);
    int dir = open(game, O_RDONLY | O_DIRECTORY);
    EXPECT(dir >= 0, "game folder opens as a directory");
    if (dir >= 0) {
        fd = openat(dir, "data.txt", O_RDONLY);
        EXPECT(fd >= 0, "openat relative to a brokered directory");
        if (fd >= 0) close(fd);
        EXPECT(fstat(dir, &st) == 0 && S_ISDIR(st.st_mode), "fstat on a descriptor is untouched");
        close(dir);
    }
    DIR *listing = opendir(game);
    int seen = 0;
    if (listing) {
        struct dirent *entry;
        while ((entry = readdir(listing))) if (strcmp(entry->d_name, "data.txt") == 0) seen = 1;
        closedir(listing);
    }
    EXPECT(seen, "game folder lists");
    EXPECT(stat(root, &st) == 0, "an ancestor of a rule can be stat()ed");
    errno = 0;
    EXPECT(opendir(root) == NULL && errno == EACCES, "an ancestor of a rule cannot be listed");

    /* Case folding (the game folder's rule is case-insensitive). */
    snprintf(path, sizeof(path), "%s/DATA.TXT", game);
    fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "a name differing only in case opens under a case-insensitive rule");
    if (fd >= 0) close(fd);

    /* Aliases. */
    fd = open("/sandbox-test/game/data.txt", O_RDONLY);
    EXPECT(fd >= 0, "a file opens under its alias");
    if (fd >= 0) close(fd);

    /* Writes. */
    snprintf(path, sizeof(path), "%s/s.txt", save);
    FILE *f = fopen(path, "w");
    EXPECT(f != NULL, "save file created");
    if (f) {
        fputs("saved", f);
        fclose(f);
    }
    snprintf(path2, sizeof(path2), "%s/t.txt", save);
    EXPECT(rename(path, path2) == 0, "rename inside the save folder");
    snprintf(path, sizeof(path), "%s/d", save);
    EXPECT(mkdir(path, 0700) == 0 && rmdir(path) == 0, "mkdir and rmdir inside the save folder");
    EXPECT(unlink(path2) == 0, "unlink inside the save folder");
    snprintf(path, sizeof(path), "%s/new.txt", game);
    EXPECT(refused(open(path, O_WRONLY | O_CREAT, 0600)), "create in the read-only game folder refused");

    /* The host's decider: a grant beyond the rules, a revocation inside them. */
    snprintf(path, sizeof(path), "%s/granted.txt", secret);
    fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "the decider grants one file the rules refuse");
    if (fd >= 0) close(fd);
    snprintf(path, sizeof(path), "%s/revoked.txt", save);
    EXPECT(refused(open(path, O_RDONLY)), "the decider refuses one file the rules allow");

    /* chdir, fchdir, getcwd. */
    EXPECT(chdir(save) == 0, "chdir into the save folder");
    EXPECT(getcwd(buffer, sizeof(buffer)) && strcmp(buffer, save) == 0, "getcwd names it");
    write_file("here.txt", "x");
    snprintf(path, sizeof(path), "%s/here.txt", save);
    EXPECT(access(path, F_OK) == 0 && unlink("here.txt") == 0, "relative paths follow the new directory");
    EXPECT(refused(chdir(secret)), "chdir outside the rules refused");
    dir = open(game, O_RDONLY | O_DIRECTORY);
    EXPECT(dir >= 0 && fchdir(dir) == 0, "fchdir to a brokered directory");
    if (dir >= 0) close(dir);
    fd = open("data.txt", O_RDONLY);
    EXPECT(fd >= 0, "relative paths follow fchdir");
    if (fd >= 0) close(fd);
    EXPECT(chdir("/sandbox-test/game") == 0 && getcwd(buffer, sizeof(buffer)) &&
               strcmp(buffer, "/sandbox-test/game") == 0,
           "getcwd under an alias names the alias");
    EXPECT(getcwd(buffer, 3) == NULL && errno == ERANGE, "getcwd with a short buffer answers ERANGE");

    ssize_t n = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    EXPECT(n > 0, "readlink /proc/self/exe");
    fd = open("/proc/self/status", O_RDONLY);
    EXPECT(fd >= 0, "own /proc/self/status");
    if (fd >= 0) close(fd);
    fd = open("/dev/null", O_WRONLY);
    EXPECT(fd >= 0, "an allowed device opens read-write");
    if (fd >= 0) close(fd);
    int pair[2];
    EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair still works");
    errno = 0;
    EXPECT(syscall(__NR_statx, AT_FDCWD, "data.txt", 0, 0x7ff, buffer) < 0 && errno == ENOSYS,
           "statx answers ENOSYS so callers fall back");
    EXPECT(kill(getpid(), 0) == 0, "a signal to itself");

    int from_thread = 0;
    pthread_t thread;
    pthread_create(&thread, NULL, thread_open, &from_thread);
    pthread_join(thread, NULL);
    EXPECT(from_thread, "a thread started after lockdown is confined and brokered too");
}

/* ---- The race: swap a directory and a symlink out of the rules while opening for truncation. ---- */

/*
 * The swapper runs in the parent, unconfined: one broker thread serves the
 * confined process's own renames in turn with its opens, so the confined
 * side alone could never land a swap inside a request. Another process
 * sharing the folder can, and that is what this plays.
 */
static volatile int racing;

static void *swapper(void *argument) {
    (void) argument;
    char a[400], b[400];
    snprintf(a, sizeof(a), "%s/dir", save);
    snprintf(b, sizeof(b), "%s/link", save);
    while (racing) syscall(__NR_renameat2, AT_FDCWD, a, AT_FDCWD, b, RENAME_EXCHANGE);
    return NULL;
}

static void race(void) {
    char path[400];
    snprintf(path, sizeof(path), "%s/dir/key", save);
    int opened = 0;
    for (int i = 0; i < 5000; i++) {
        int fd = open(path, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            opened++;
            close(fd);
        }
    }
    printf("info race: %d of 5000 opens reached the real directory\n", opened);
}

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
        struct sbx_lockdown_options options = {0, &fd, 1};
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

/* ---- Unbrokered: paths go to the kernel, the rest of the wall stands. ---- */

static int unbrokered_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sbx_lockdown_options options = {SBX_LOCK_UNBROKERED | SBX_LOCK_LOG_SOCKET, NULL, 0};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "unbrokered lockdown without a broker");
        if (locked != 0) _exit(1);
        char path[400];
        snprintf(path, sizeof(path), "%s/key", secret);
        int fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "unbrokered: paths go to the kernel");
        if (fd >= 0) close(fd);
        char buffer[512];
        EXPECT(getcwd(buffer, sizeof(buffer)) != NULL, "unbrokered: getcwd is the kernel's");
        errno = 0;
        EXPECT(refused(socket(AF_INET, SOCK_STREAM, 0)), "unbrokered: socket(AF_INET) refused");
        int log_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
        EXPECT(log_socket >= 0, "unbrokered: a Unix datagram socket for the log");
        if (log_socket >= 0) close(log_socket);
        errno = 0;
        EXPECT(a_exec() == EACCES, "unbrokered: execve refused");
        errno = 0;
        EXPECT(kill(getppid(), 0) < 0 && errno == EPERM, "unbrokered: a signal to the parent refused");
        errno = 0;
        EXPECT(a_unshare() == EPERM, "unbrokered: unshare refused");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
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

/* ---- The parent: the broker, with a decider and an audit. ---- */

static int refusals;

static int decider(void *context, const struct sbx_access *access) {
    (void) context;
    const char *slash = strrchr(access->resolved, '/');
    if (slash && strcmp(slash, "/granted.txt") == 0 && access->need == SBX_READ) return 0;
    if (slash && strcmp(slash, "/revoked.txt") == 0) return -EACCES;
    return SBX_KEEP;
}

static void audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    (void) access;
    if (result < 0) refusals++;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "--spawned") == 0) return spawned_main();
    char self[512];
    ssize_t self_len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (self_len <= 0) { perror("readlink"); return 2; }
    self[self_len] = 0;
    int spawn_failures = spawn_check(self);
    snprintf(root, sizeof(root), "%s/sbx-test-XXXXXX", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }
    snprintf(game, sizeof(game), "%s/game", root);
    snprintf(save, sizeof(save), "%s/save", root);
    snprintf(secret, sizeof(secret), "%s/secret", root);
    snprintf(mountpoint, sizeof(mountpoint), "%s/mnt", root);
    mkdir(mountpoint, 0700);
    if (access(exec_path, X_OK) != 0) exec_path = "/system/bin/true";
    mkdir(game, 0700);
    mkdir(save, 0700);
    mkdir(secret, 0700);
    char path[400], link[400];
    snprintf(path, sizeof(path), "%s/data.txt", game);
    write_file(path, "hello");
    snprintf(path, sizeof(path), "%s/key", secret);
    write_file(path, "secret");
    snprintf(path, sizeof(path), "%s/granted.txt", secret);
    write_file(path, "granted");
    snprintf(path, sizeof(path), "%s/revoked.txt", save);
    write_file(path, "revoked");
    snprintf(path, sizeof(path), "%s/key", secret);
    snprintf(link, sizeof(link), "%s/escape", game);
    if (symlink(path, link) != 0) { perror("symlink"); return 2; }
    /* For the race: a real directory and a symlink out of the rules, side by side in the writable folder. */
    snprintf(path, sizeof(path), "%s/dir", save);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/dir/key", save);
    write_file(path, "inside");
    snprintf(link, sizeof(link), "%s/link", save);
    if (symlink(secret, link) != 0) { perror("symlink"); return 2; }

    int sealed_failures = sealed_check() | unbrokered_check();

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) { perror("socketpair"); return 2; }
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ | SBX_CASE_INSENSITIVE);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE | SBX_DECIDE);
    sbx_policy_add(policy, "/proc", SBX_READ);
    sbx_policy_add(policy, "/dev/null", SBX_READ | SBX_WRITE);
    sbx_policy_alias(policy, "/sandbox-test/game", game);
    sbx_policy_set_decider(policy, decider, NULL);
    sbx_policy_set_audit(policy, audit, NULL);
    if (sbx_broker_prepare(pair[0]) != 0) { perror("prepare"); return 2; }
    parent_pid = getpid();

    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        if (chdir(game) != 0) _exit(2);
        controls();
        int locked = sbx_lockdown(pair[1], NULL);
        errno = -locked;
        EXPECT(locked == 0, "lockdown installed on every thread");
        if (locked == 0) {
            working();
            confined_attempts();
            race();
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    racing = 1;
    pthread_t thread;
    pthread_create(&thread, NULL, swapper, NULL);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    racing = 0;
    pthread_join(thread, NULL);

    char content[32] = {0};
    snprintf(path, sizeof(path), "%s/key", secret);
    FILE *f = fopen(path, "r");
    if (f) {
        if (!fgets(content, sizeof(content), f)) content[0] = '\0';
        fclose(f);
    }
    int parent_failures = sealed_failures || spawn_failures ? 1 : 0;
    if (strcmp(content, "secret") == 0) {
        printf("ok   the file outside the rules was never truncated by the race\n");
    } else {
        printf("FAIL the file outside the rules was truncated by the race\n");
        parent_failures++;
    }
    if (refusals > 0) {
        printf("ok   the audit saw %d refusals\n", refusals);
    } else {
        printf("FAIL the audit saw no refusals\n");
        parent_failures++;
    }
    if (WIFSIGNALED(status)) {
        printf("FAIL confined process died with signal %d\n", WTERMSIG(status));
        return 1;
    }
    return WEXITSTATUS(status) || parent_failures ? 1 : 0;
}
