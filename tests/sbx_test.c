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
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
/* Refused unless SBX_LOCK_PATHOPS (link, symlink, truncate) or SBX_LOCK_INOTIFY. */
static int a_link(void) {
    char from[400], to[400];
    snprintf(from, sizeof(from), "%s/data.txt", game);
    snprintf(to, sizeof(to), "%s/linked", save);
    int error = result_of(link(from, to));
    if (error == 0) unlink(to);
    return error;
}
static int a_make_symlink(void) {
    char to[400];
    snprintf(to, sizeof(to), "%s/made-link", save);
    int error = result_of(symlink("anything", to));
    if (error == 0) unlink(to);
    return error;
}
static int a_truncate(void) {
    char p[400];
    snprintf(p, sizeof(p), "%s/trunc.txt", save);
    return result_of(truncate(p, 0));
}
static int a_inotify(void) {
    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) return errno;
    int error = result_of(inotify_add_watch(fd, save, IN_CREATE));
    close(fd);
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
    {"link without SBX_LOCK_PATHOPS", a_link, EACCES, 0, 0},
    {"symlink without SBX_LOCK_PATHOPS", a_make_symlink, EACCES, 0, 0},
    {"truncate without SBX_LOCK_PATHOPS", a_truncate, EACCES, 0, 0},
    {"inotify_add_watch without SBX_LOCK_INOTIFY", a_inotify, EACCES, 0, 0},
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
    sbx_handle handle = -1;
    EXPECT(sbx_open(path, SBX_OPEN_READ, &handle) == 0 && handle >= 0, "sbx_open of a game file goes through the broker");
    if (handle >= 0) close(handle);
    snprintf(path2, sizeof(path2), "%s/key", secret);
    EXPECT(sbx_open(path2, SBX_OPEN_READ, &handle) == -EACCES, "sbx_open outside the rules is refused");
    EXPECT(sbx_open(path, SBX_OPEN_WRITE, &handle) == -EACCES, "sbx_open for writing in a read-only rule is refused");
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

    /* Aliases: the policy's, and one the filesystem makes (a symlink to a folder in the rules). */
    fd = open("/sandbox-test/game/data.txt", O_RDONLY);
    EXPECT(fd >= 0, "a file opens under its alias");
    if (fd >= 0) close(fd);
    snprintf(path, sizeof(path), "%s/game-link/data.txt", root);
    fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "a file opens through a symlink that resolves into the rules");
    if (fd >= 0) close(fd);

    /* An own-opened device: answered with a duplicate, with no broker rule for it. */
    fd = open("/dev/zero", O_RDONLY);
    EXPECT(fd >= 0, "an own-opened device opens after lockdown");
    if (fd >= 0) {
        char zero = 1;
        EXPECT(read(fd, &zero, 1) == 1 && zero == 0, "and reads as itself");
        close(fd);
    }
    EXPECT(access("/dev/zero", R_OK | W_OK) == 0, "access of an own-opened device answers from its descriptor");
    EXPECT(stat("/dev/zero", &st) == 0 && S_ISCHR(st.st_mode), "and stat sees the device");
    errno = 0;
    EXPECT(refused(access("/dev/full", F_OK)), "access of a device outside the rules is still refused");
    errno = 0;
    EXPECT(refused(open("/dev/full", O_RDONLY)), "a device that is neither own-opened nor in the rules is refused");

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
        EXPECT(sbx_lockdown(pair[1], NULL) == 0, "sigsys: lockdown once no thread blocks SIGSYS");
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
    }
}

/* A learning host's decider: record what the rules refused, allow it. */
static int learn_decide(void *context, const struct sbx_access *access) {
    struct learned *seen = context;
    if (access->rule_verdict < 0) seen->path_refused++;
    return 0;
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
    failed |= !socket_ok || seen.kill_eperm < 1 || seen.unshare_eperm < 1 || seen.path_refused < 1;

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

/* ---- SBX_LOCK_PATHOPS and SBX_LOCK_INOTIFY: link, symlink and truncate through the broker, marks allowed. ---- */

static int pathops_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char source[400], hard[400], stolen[400], from_secret[400], sym[400], game_sym[400], followed[400];
    char data[400], key[400];
    snprintf(source, sizeof(source), "%s/p-source", save);
    snprintf(hard, sizeof(hard), "%s/p-hard", save);
    snprintf(stolen, sizeof(stolen), "%s/p-stolen", save);
    snprintf(from_secret, sizeof(from_secret), "%s/p-secret", save);
    snprintf(sym, sizeof(sym), "%s/p-sym", save);
    snprintf(game_sym, sizeof(game_sym), "%s/p-sym", game);
    snprintf(followed, sizeof(followed), "%s/p-followed", save);
    snprintf(data, sizeof(data), "%s/data.txt", game);
    snprintf(key, sizeof(key), "%s/key", secret);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_PATHOPS | SBX_LOCK_INOTIFY};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "pathops: lockdown");
        if (locked != 0) _exit(1);
        int fd = open(source, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
        EXPECT(fd >= 0 && write(fd, "four", 4) == 4, "pathops: a file in the writable rule");
        if (fd >= 0) close(fd);
        EXPECT(link(source, hard) == 0, "pathops: link between two writable names");
        struct stat a, b;
        EXPECT(stat(source, &a) == 0 && stat(hard, &b) == 0 && a.st_ino == b.st_ino, "pathops: and both name one file");
        errno = 0;
        EXPECT(refused(link(data, stolen)), "pathops: link of a read-only file into a writable rule is refused");
        errno = 0;
        EXPECT(refused(link(key, from_secret)), "pathops: link of a file outside the rules is refused");
        EXPECT(symlink("../secret/key", sym) == 0, "pathops: symlink in the writable rule, target stored as given");
        char target[64] = {0};
        EXPECT(readlink(sym, target, sizeof(target) - 1) > 0 && strcmp(target, "../secret/key") == 0,
               "pathops: readlink gives the target back unchanged");
        errno = 0;
        EXPECT(refused(open(sym, O_RDONLY)), "pathops: following it out of the rules is refused");
        errno = 0;
        EXPECT(refused(linkat(AT_FDCWD, sym, AT_FDCWD, followed, AT_SYMLINK_FOLLOW)),
               "pathops: linkat following it out of the rules is refused");
        errno = 0;
        EXPECT(refused(symlink("anything", game_sym)), "pathops: symlink in a read-only rule is refused");
        EXPECT(truncate(source, 2) == 0 && stat(source, &a) == 0 && a.st_size == 2, "pathops: truncate in the writable rule");
        errno = 0;
        EXPECT(refused(truncate(data, 0)), "pathops: truncate in a read-only rule is refused");
        errno = 0;
        EXPECT(refused(truncate(key, 0)), "pathops: truncate outside the rules is refused");
        int watcher = inotify_init1(IN_CLOEXEC);
        EXPECT(watcher >= 0 && inotify_add_watch(watcher, save, IN_CREATE) >= 0, "inotify: a mark with SBX_LOCK_INOTIFY");
        if (watcher >= 0) close(watcher);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    char content[16] = {0};
    FILE *f = fopen(key, "r");
    if (f) {
        if (!fgets(content, sizeof(content), f)) content[0] = 0;
        fclose(f);
    }
    int failed = !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (strcmp(content, "secret") != 0) {
        printf("FAIL pathops: the file outside the rules was changed\n");
        failed = 1;
    }
    unlink(source);
    unlink(hard);
    unlink(sym);
    return failed;
}

/* ---- Unbrokered: paths go to the kernel, the rest of the wall stands. ---- */

static int unbrokered_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_LOG_SOCKET};
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

/* ---- Inet: inet sockets and nothing else that reaches out. ---- */

static int inet_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30); /* A hang (a blocked accept) fails the check instead of the run. */
        struct sbx_lockdown_options both = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_INET | SBX_LOCK_LOG_SOCKET};
        EXPECT(sbx_lockdown(-1, &both) == -EINVAL, "inet: not with the log socket, whose bind it cannot tell apart");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_INET};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "inet lockdown");
        if (locked != 0) _exit(1);
        errno = 0;
        EXPECT(a_inet6() != EACCES, "inet: socket(AF_INET6) not refused by the filter");
        errno = 0;
        EXPECT(a_unix_dgram() == EACCES, "inet: socket(AF_UNIX, SOCK_DGRAM) refused");
        errno = 0;
        EXPECT(a_unix_stream() == EACCES, "inet: socket(AF_UNIX, SOCK_STREAM) refused");
        errno = 0;
        EXPECT(a_netlink() == EACCES, "inet: socket(AF_NETLINK) refused");
        errno = 0;
        EXPECT(try_socket(AF_INET, SOCK_RAW, IPPROTO_UDP) == EACCES, "inet: socket(AF_INET, SOCK_RAW) refused");

        /*
         * A loopback round trip: bind, listen, connect, accept. connect and
         * accept go to the kernel directly: bionic's report each inet socket
         * to netd over a Unix socket (/dev/socket/fwmarkd), which this flag
         * refuses, and the filter is what is tested here.
         */
        int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(server >= 0, "inet: socket(AF_INET, SOCK_STREAM)");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t length = sizeof(address);
        EXPECT(server >= 0 && bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "inet: bind");
        EXPECT(server >= 0 && listen(server, 1) == 0, "inet: listen");
        EXPECT(server >= 0 && getsockname(server, (struct sockaddr *) &address, &length) == 0, "inet: getsockname");
        int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int connected = client >= 0 && syscall(__NR_connect, client, &address, sizeof(address)) == 0;
        EXPECT(connected, "inet: connect");
        /* Only with a connection waiting, so a failed connect cannot leave accept blocked. */
        int accepted = connected ? (int) syscall(__NR_accept4, server, NULL, NULL, SOCK_CLOEXEC) : -1;
        EXPECT(accepted >= 0, "inet: accept");
        char byte = 0;
        EXPECT(accepted >= 0 && write(client, "x", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'x',
               "inet: bytes cross the loopback connection");
        if (accepted >= 0) close(accepted);
        if (client >= 0) close(client);
#ifdef __ANDROID__
        /* A measurement, not a gate: what C code that uses bionic's connect gets under this flag. */
        int through_libc = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (through_libc >= 0) {
            errno = 0;
            int r = connect(through_libc, (struct sockaddr *) &address, sizeof(address));
            printf("info inet: bionic connect %s (%s)\n", r == 0 ? "succeeded" : "failed", r == 0 ? "-" : strerror(errno));
            close(through_libc);
        }
#endif
        if (server >= 0) close(server);
        int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        EXPECT(udp >= 0, "inet: socket(AF_INET, SOCK_DGRAM)");
        if (udp >= 0) close(udp);

        errno = 0;
        EXPECT(a_exec() == EACCES, "inet: execve refused");
        errno = 0;
        EXPECT(kill(getppid(), 0) < 0 && errno == EPERM, "inet: a signal to the parent refused");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- Passthrough: claimed folders through the broker, every other path to the kernel, local files. ---- */

static int read_word(int fd, char *out, size_t size) {
    ssize_t n = read(fd, out, size - 1);
    if (n < 0) n = 0;
    out[n] = '\0';
    return (int) n;
}

static int passthrough_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    sbx_policy_alias(policy, "/sandbox-test/data", save);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char real_game[PATH_MAX];
    if (!realpath(game, real_game)) return 1;
    char local_path[400];
    snprintf(local_path, sizeof(local_path), "%s/local.txt", root);
    write_file(local_path, "local");
    char rw_seed[500];
    snprintf(rw_seed, sizeof(rw_seed), "%s/rw.txt", root);
    write_file(rw_seed, "old contents");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        /* The broker's folders: an alias, the real folder it names, and one with no rule at all. */
        const char *claims[] = {"/sandbox-test", save, secret};
        struct sbx_lockdown_options options = {
            .flags = SBX_LOCK_PASSTHROUGH | SBX_LOCK_LOG_SOCKET, .claims = claims, .claim_count = 3};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "passthrough lockdown");
        if (locked != 0) _exit(1);
        char path[600], word[16];

        snprintf(path, sizeof(path), "%s/data.txt", game);
        int fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "passthrough: an unclaimed path goes to the kernel (no rule needed)");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "hello") == 0, "passthrough: and reads");
            close(fd);
        }
        struct stat st;
        EXPECT(stat("/proc/self/status", &st) == 0, "passthrough: the process's own /proc from the kernel");
        char target[512];
        EXPECT(readlink("/proc/self/exe", target, sizeof(target)) > 0, "passthrough: readlink from the kernel");
        snprintf(path, sizeof(path), "%s/key", secret);
        errno = 0;
        EXPECT(refused(open(path, O_RDONLY)), "passthrough: a claimed path the broker has no rule for is refused");

        fd = open("/sandbox-test/data/p.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
        EXPECT(fd >= 0, "passthrough: a claimed alias goes to the broker and creates a file");
        if (fd >= 0) {
            EXPECT(write(fd, "put", 3) == 3, "passthrough: writes through the brokered descriptor");
            close(fd);
        }
        snprintf(path, sizeof(path), "%s/p.txt", save);
        fd = open(path, O_RDONLY);
        EXPECT(fd >= 0, "passthrough: the real claimed folder holds it");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "put") == 0, "passthrough: with what was written");
            close(fd);
        }

        /* chmod and utimensat: a claimed path goes to the broker, any other to the kernel. */
        EXPECT(chmod("/sandbox-test/data/p.txt", 0640) == 0, "passthrough: chmod of a claimed alias");
        snprintf(path, sizeof(path), "%s/p.txt", save);
        EXPECT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640, "passthrough: the real file has the mode");
        EXPECT(fchmodat(AT_FDCWD, "/sandbox-test/data/p.txt", 04755, 0) == 0 && stat(path, &st) == 0 &&
                   (st.st_mode & 07777) == 0755,
               "passthrough: the broker keeps permission bits only");
        struct timespec times[2] = {{1000, 0}, {2000, 0}};
        EXPECT(utimensat(AT_FDCWD, "/sandbox-test/data/p.txt", times, 0) == 0, "passthrough: utimensat of a claimed alias");
        EXPECT(stat(path, &st) == 0 && st.st_mtime == 2000 && st.st_atime == 1000, "passthrough: the real file has the times");
        EXPECT(utimensat(AT_FDCWD, "/sandbox-test/data/p.txt", NULL, 0) == 0 && stat(path, &st) == 0 && st.st_mtime > 2000,
               "passthrough: utimensat to now");
        fd = open("/sandbox-test/data/p.txt", O_RDONLY);
        EXPECT(fd >= 0 && futimens(fd, times) == 0, "passthrough: futimens on a descriptor");
        if (fd >= 0) close(fd);
        snprintf(path, sizeof(path), "%s/data.txt", game);
        EXPECT(chmod(path, 0644) == 0, "passthrough: chmod of an unclaimed path from the kernel");
        snprintf(path, sizeof(path), "%s/key", secret);
        errno = 0;
        EXPECT(refused(chmod(path, 0666)), "passthrough: chmod of a claimed path with no rule is refused");
        errno = 0;
        EXPECT(refused(utimensat(AT_FDCWD, path, NULL, 0)), "passthrough: utimensat of a claimed path with no rule is refused");

        /* Listing: getdents64 traps in passthrough; the handler's own call lists what the kernel lets it. */
        DIR *listing = opendir("/sandbox-test/data");
        int seen = 0;
        if (listing) {
            struct dirent *entry;
            while ((entry = readdir(listing)) != NULL) seen |= strcmp(entry->d_name, "p.txt") == 0;
            rewinddir(listing);
            int again = 0;
            while ((entry = readdir(listing)) != NULL) again |= strcmp(entry->d_name, "p.txt") == 0;
            seen &= again;
            closedir(listing);
        }
        EXPECT(seen, "passthrough: a claimed folder lists, and lists again after rewinddir");
        listing = opendir(game);
        seen = 0;
        if (listing) {
            struct dirent *entry;
            while ((entry = readdir(listing)) != NULL) seen |= strcmp(entry->d_name, "data.txt") == 0;
            closedir(listing);
        }
        EXPECT(seen, "passthrough: an unclaimed folder lists");

        EXPECT(chdir(game) == 0, "passthrough: chdir into an unclaimed folder");
        fd = open("data.txt", O_RDONLY);
        EXPECT(fd >= 0, "passthrough: a relative path from there goes to the kernel");
        if (fd >= 0) close(fd);
        char cwd[PATH_MAX];
        EXPECT(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, real_game) == 0, "passthrough: getcwd names it");
        EXPECT(chdir("/sandbox-test/data") == 0, "passthrough: chdir into a claimed folder");
        fd = open("p.txt", O_RDONLY);
        EXPECT(fd >= 0, "passthrough: a relative path from there goes to the broker");
        if (fd >= 0) close(fd);
        int dir = open(game, O_RDONLY | O_DIRECTORY);
        EXPECT(dir >= 0, "passthrough: an unclaimed folder opens as a directory");
        if (dir >= 0) {
            fd = openat(dir, "data.txt", O_RDONLY);
            EXPECT(fd >= 0, "passthrough: openat relative to it");
            if (fd >= 0) close(fd);
            close(dir);
        }
        struct statfs fs;
        EXPECT(statfs(game, &fs) == 0, "passthrough: statfs from the kernel");

        /* A local file, given after the lockdown under a name nothing else has. */
        fd = open(local_path, O_RDONLY);
        int added = fd >= 0 ? sbx_local_add("/sandbox-local/lib.so", fd) : -EBADF;
        errno = -added;
        EXPECT(added == 0, "sbx_local_add after lockdown");
        fd = open("/sandbox-local/lib.so", O_RDONLY);
        EXPECT(fd >= 0, "a local file opens by its name");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "local") == 0, "and reads from its start");
            close(fd);
        }
        EXPECT(stat("/sandbox-local/lib.so", &st) == 0 && st.st_size == 5, "stat of a local file");
        EXPECT(access("/sandbox-local/lib.so", R_OK) == 0, "access of a local file");
        errno = 0;
        EXPECT(refused(access("/sandbox-local/lib.so", W_OK)), "a local file is not writable (access)");
        errno = 0;
        EXPECT(refused(open("/sandbox-local/lib.so", O_RDWR)), "a local file is not writable (open)");

        /* A writable local file (sbx_local_add_mode), as droidtop hands over a file it opened for writing. */
        char rw_path[500];
        snprintf(rw_path, sizeof(rw_path), "%s/rw.txt", root);
        int rw = open(rw_path, O_RDWR);
        added = rw >= 0 ? sbx_local_add_mode("/sandbox-local/rw.txt", rw, SBX_READ | SBX_WRITE) : -EBADF;
        errno = -added;
        EXPECT(added == 0, "sbx_local_add_mode read and write");
        fd = open("/sandbox-local/rw.txt", O_WRONLY | O_TRUNC);
        EXPECT(fd >= 0, "a writable local file opens for writing");
        if (fd >= 0) {
            EXPECT(write(fd, "new", 3) == 3, "and writes");
            close(fd);
        }
        fd = open("/sandbox-local/rw.txt", O_RDONLY);
        EXPECT(fd >= 0, "and opens again for reading");
        if (fd >= 0) {
            read_word(fd, word, sizeof(word));
            EXPECT(strcmp(word, "new") == 0, "O_TRUNC emptied it and the write is there");
            close(fd);
        }
        fd = open(local_path, O_RDONLY);
        EXPECT(sbx_local_add_mode("/sandbox-local/rw.txt", fd, SBX_WRITE) == -EINVAL, "sbx_local_add_mode: write alone is no mode");
        fd = open(local_path, O_RDONLY);
        EXPECT(sbx_local_add_mode("/sandbox-local/rw.txt", fd, SBX_READ) == 0, "a local file replaced read only");
        errno = 0;
        EXPECT(refused(open("/sandbox-local/rw.txt", O_WRONLY)), "takes the new mode: no longer writable");

        errno = 0;
        EXPECT(refused(socket(AF_INET, SOCK_STREAM, 0)), "passthrough: socket(AF_INET) refused");
        errno = 0;
        EXPECT(a_exec() == EACCES, "passthrough: execve refused");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/*
 * SBX_LIST, asked of the broker directly, as the handler asks it for a
 * folder the kernel would not list for the confined process (which this
 * test, one user throughout, cannot make happen).
 */
static long ask_list(int broker_fd, int dir, char *out, size_t out_len) {
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, answer) != 0) return -errno;
    struct {
        uint16_t version, op;
        int32_t flags;
        uint32_t mode, path_len, path2_len;
        int32_t tid;
        uint8_t dirfd_sent, dirfd2_sent, reserved[6];
    } request = {.version = 1, .op = 11 /* SBX_LIST */, .mode = (uint32_t) out_len, .path_len = 1,
                 .tid = (int32_t) syscall(__NR_gettid), .dirfd_sent = 1};
    struct iovec parts[2] = {{&request, sizeof(request)}, {(void *) ".", 1}};
    int fds[2] = {answer[1], dir};
    union {
        char buffer[CMSG_SPACE(sizeof(fds))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = parts, .msg_iovlen = 2, .msg_control = control.buffer,
                             .msg_controllen = sizeof(control.buffer)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(header), fds, sizeof(fds));
    long sent = sendmsg(broker_fd, &message, 0);
    close(answer[1]);
    if (sent < 0) { close(answer[0]); return -errno; }
    struct { int64_t result; uint32_t data_len, reserved; } reply;
    struct iovec back[2] = {{&reply, sizeof(reply)}, {out, out_len}};
    struct msghdr answer_message = {.msg_iov = back, .msg_iovlen = 2};
    long got = recvmsg(answer[0], &answer_message, 0);
    close(answer[0]);
    if (got < (long) sizeof(reply)) return -EIO;
    return (long) reply.result;
}

static int names(const char *records, long n, const char *name) {
    for (long at = 0; at < n;) {
        const struct { uint64_t ino; int64_t off; unsigned short reclen; unsigned char type; char name[]; } *d =
            (const void *) (records + at);
        if (strcmp(d->name, name) == 0) return 1;
        if (d->reclen == 0) break;
        at += d->reclen;
    }
    return 0;
}

static int list_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ);
    if (sbx_broker_prepare(pair[0]) != 0 || sbx_broker_start(policy, pair[0]) != 0) return 1;
    char records[4096];
    int dir = open(save, O_RDONLY | O_DIRECTORY);
    long n = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    EXPECT(n > 0 && names(records, n, "revoked.txt"), "SBX_LIST: the broker lists a folder under a read rule");
    long more = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    EXPECT(more == 0, "SBX_LIST: from the same position, so the next read is the end");
    if (dir >= 0) {
        lseek(dir, 0, SEEK_SET);
        n = ask_list(pair[1], dir, records, sizeof(records));
        EXPECT(n > 0 && names(records, n, "revoked.txt"), "SBX_LIST: and again after a rewind");
        close(dir);
    }
    dir = open(secret, O_RDONLY | O_DIRECTORY);
    n = dir >= 0 ? ask_list(pair[1], dir, records, sizeof(records)) : -EBADF;
    errno = n < 0 ? (int) -n : 0;
    EXPECT(n == -EACCES, "SBX_LIST: a folder outside the rules is refused");
    if (dir >= 0) close(dir);
    close(pair[1]);
    return failures ? 1 : 0;
}

/* ---- The network through the broker (SBX_LOCK_NET_BROKERED). ---- */

/* A Unix socket address for path (cut to fit; the test's paths are short). */
static void unix_at(struct sockaddr_un *address, const char *path) {
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof(address->sun_path)) n = sizeof(address->sun_path) - 1;
    memcpy(address->sun_path, path, n);
}

static int net_decider(void *context, const struct sbx_access *access) {
    (void) context;
    /* The host's own word on one destination: port 9 is refused even with SBX_NET_CONNECT. */
    size_t n = strlen(access->asked);
    if (strcmp(access->op, "connect") == 0 && n > 2 && strcmp(access->asked + n - 2, ":9") == 0) return -EACCES;
    return SBX_KEEP;
}

static void *net_accept_thread(void *argument) {
    int server = *(int *) argument;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    long accepted = accept4(server, (struct sockaddr *) &peer, &length, SOCK_CLOEXEC);
    return (void *) accepted;
}

static void net_granted(const char *resolver) {
    errno = 0;
    EXPECT(a_netlink() == EACCES, "net: socket(AF_NETLINK) refused");
    int pair[2];
    EXPECT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "net: a socketpair of the process's own");
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    EXPECT(udp >= 0, "net: socket(AF_INET, SOCK_DGRAM) from the broker");
    if (udp >= 0) close(udp);
    errno = 0;
    /* A machine without IPv6 answers EAFNOSUPPORT from the broker's own socket(); the grant is what is tested. */
    EXPECT(a_inet6() != EACCES, "net: socket(AF_INET6) not refused");

    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(server >= 0 && (fcntl(server, F_GETFD) & FD_CLOEXEC), "net: socket(AF_INET, SOCK_STREAM) from the broker, close-on-exec kept");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    EXPECT(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "net: bind a port of the system's choosing");
    EXPECT(listen(server, 4) == 0, "net: listen, by the broker");
    EXPECT(getsockname(server, (struct sockaddr *) &address, &length) == 0 && address.sin_port != 0, "net: getsockname");

    /* A blocking accept waits in the broker on a thread of its own: the connect below still gets through. */
    pthread_t waiter;
    pthread_create(&waiter, NULL, net_accept_thread, &server);
    usleep(100 * 1000);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(client >= 0 && connect(client, (struct sockaddr *) &address, sizeof(address)) == 0,
           "net: connect while an accept waits in the broker");
    void *accepted_value = NULL;
    pthread_join(waiter, &accepted_value);
    int accepted = (int) (long) accepted_value;
    EXPECT(accepted >= 0, "net: accept, by the broker");
    char byte = 0;
    EXPECT(accepted >= 0 && write(client, "x", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'x',
           "net: bytes cross the connection, in the process itself");
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);

    struct sockaddr_in peer;
    socklen_t peer_length = sizeof(peer);
    int nonblocking = fcntl(server, F_GETFL);
    fcntl(server, F_SETFL, nonblocking | O_NONBLOCK);
    errno = 0;
    EXPECT(accept4(server, (struct sockaddr *) &peer, &peer_length, 0) < 0 && errno == EAGAIN,
           "net: a non-blocking accept with nothing waiting answers EAGAIN");
    int second = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(second >= 0 && connect(second, (struct sockaddr *) &address, sizeof(address)) == 0, "net: a second connect");
    usleep(50 * 1000);
    peer_length = sizeof(peer);
    int third = accept4(server, (struct sockaddr *) &peer, &peer_length, SOCK_CLOEXEC);
    EXPECT(third >= 0 && peer_length == sizeof(peer) && peer.sin_family == AF_INET &&
               peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "net: accept4 gives the peer's address");
    if (third >= 0) close(third);
    if (second >= 0) close(second);

    struct sockaddr_in discard = address;
    discard.sin_port = htons(9);
    int refused_socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    errno = 0;
    EXPECT(refused_socket >= 0 && connect(refused_socket, (struct sockaddr *) &discard, sizeof(discard)) < 0 && errno == EACCES,
           "net: the decider refuses one destination");
    if (refused_socket >= 0) close(refused_socket);
    close(server);

    int named = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un local;
    char mine[400];
    snprintf(mine, sizeof(mine), "%s/mine.sock", root);
    unix_at(&local, mine);
    errno = 0;
    EXPECT(named >= 0 && bind(named, (struct sockaddr *) &local, sizeof(local)) < 0 && errno == EACCES, "net: a Unix bind refused");
    errno = 0;
    EXPECT(named >= 0 && listen(named, 1) < 0 && errno == EACCES, "net: a Unix listen refused (no abstract name)");
    if (named >= 0) close(named);

    struct sockaddr_un target;
    if (resolver[0]) {
        int resolver_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        unix_at(&target, resolver);
        EXPECT(resolver_client >= 0 && connect(resolver_client, (struct sockaddr *) &target, sizeof(target)) == 0,
               "net: the resolver's socket, connected by the broker");
        EXPECT(resolver_client >= 0 && (fcntl(resolver_client, F_GETFD) & FD_CLOEXEC), "net: the resolver's socket keeps close-on-exec");
        EXPECT(resolver_client >= 0 && write(resolver_client, "q", 1) == 1, "net: the resolver's socket carries bytes");
        if (resolver_client >= 0) close(resolver_client);
    }

    int elsewhere = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    char none[400];
    snprintf(none, sizeof(none), "%s/none.sock", root);
    unix_at(&target, none);
    errno = 0;
    EXPECT(elsewhere >= 0 && connect(elsewhere, (struct sockaddr *) &target, sizeof(target)) < 0 && errno == ENOENT,
           "net: any other Unix connect is the kernel's");
    if (elsewhere >= 0) close(elsewhere);
    close(pair[0]);
    close(pair[1]);
}

static void net_refused(const char *resolver) {
    errno = 0;
    EXPECT(a_inet() == EACCES, "net, no grant: socket(AF_INET) refused by the broker");
    if (!resolver[0]) return;
    int resolver_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un target;
    unix_at(&target, resolver);
    errno = 0;
    EXPECT(resolver_client >= 0 && connect(resolver_client, (struct sockaddr *) &target, sizeof(target)) < 0 && errno == EACCES,
           "net, no grant: the resolver refused");
    if (resolver_client >= 0) close(resolver_client);
}

static int net_check(unsigned grants) {
    char resolver[400];
    snprintf(resolver, sizeof(resolver), "%s/resolver-%u.sock", root, grants);
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un at;
    unix_at(&at, resolver);
    if (listener < 0 || bind(listener, (struct sockaddr *) &at, sizeof(at)) != 0 || listen(listener, 8) != 0) {
        /* Android's shell may not make a socket file under /data/local/tmp: the system-socket checks are skipped, the rest run. */
        printf("info net: no stand-in resolver socket here (%s); its checks are skipped\n", strerror(errno));
        if (listener >= 0) close(listener);
        listener = -1;
        resolver[0] = '\0';
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) { printf("FAIL net: socketpair (%s)\n", strerror(errno)); return 1; }
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_set_net(policy, grants);
    if (resolver[0]) sbx_policy_add_system_socket(policy, resolver, SBX_NET_RESOLVE);
    sbx_policy_set_decider(policy, net_decider, NULL);
    if (sbx_broker_prepare(pair[0]) != 0) { printf("FAIL net: broker prepare\n"); return 1; }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30);
        close(pair[0]);
        struct sbx_lockdown_options bad = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_INET};
        EXPECT(sbx_lockdown(pair[1], &bad) == -EINVAL, "net: not with SBX_LOCK_INET");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_UNBROKERED};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "net: not without a broker");
        options.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_PASSTHROUGH;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "net: lockdown");
        if (locked == 0) {
            if (grants) net_granted(resolver);
            else net_refused(resolver);
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (listener >= 0) {
        close(listener);
        unlink(resolver);
    }
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
    snprintf(path, sizeof(path), "%s/trunc.txt", save);
    write_file(path, "keep");
    snprintf(path, sizeof(path), "%s/key", secret);
    snprintf(link, sizeof(link), "%s/escape", game);
    if (symlink(path, link) != 0) { perror("symlink"); return 2; }
    snprintf(link, sizeof(link), "%s/game-link", root);
    if (symlink(game, link) != 0) { perror("symlink"); return 2; }
    /* For the race: a real directory and a symlink out of the rules, side by side in the writable folder. */
    snprintf(path, sizeof(path), "%s/dir", save);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/dir/key", save);
    write_file(path, "inside");
    snprintf(link, sizeof(link), "%s/link", save);
    if (symlink(secret, link) != 0) { perror("symlink"); return 2; }

    int sealed_failures = sealed_check() | sigsys_check() | learn_check() | pathops_check() | unbrokered_check() | inet_check() | passthrough_check() | list_check() |
                          net_check(SBX_NET_CONNECT | SBX_NET_LISTEN | SBX_NET_RESOLVE | SBX_NET_DECIDE) | net_check(0);

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
        static const char *const devices[] = {"/dev/zero", "/dev/does-not-exist"};
        struct sbx_lockdown_options options = {.own_opens = devices, .own_open_count = 2};
        int locked = sbx_lockdown(pair[1], &options);
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
