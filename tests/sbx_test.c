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
#include "sbx_contract.h"
#include "protocol.h"

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
#include <sys/time.h>
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

    /* An own-opened device: each open its own open file, as binder needs (a duplicate would share flags). */
    {
        int first = open("/dev/zero", O_RDWR | O_CLOEXEC), second = open("/dev/zero", O_RDWR | O_CLOEXEC);
        EXPECT(first >= 0 && second >= 0, "an own-opened device opens twice");
        if (first >= 0 && second >= 0) {
            fcntl(first, F_SETFL, fcntl(first, F_GETFL) | O_NONBLOCK);
            EXPECT((fcntl(second, F_GETFL) & O_NONBLOCK) == 0, "each open of an own-opened device is an open file of its own");
        }
        int more[4];
        int opened = 0;
        for (int k = 0; k < 4; k++) {
            more[k] = open("/dev/zero", O_RDONLY);
            if (more[k] >= 0) opened++;
        }
        EXPECT(opened == 4, "past its spares, an own-opened device still opens (as a duplicate)");
        EXPECT(first < 0 || (fcntl(first, F_GETFD) & FD_CLOEXEC), "a spare keeps the close-on-exec it was asked for");
        EXPECT(more[0] < 0 || !(fcntl(more[0], F_GETFD) & FD_CLOEXEC), "a spare opened without O_CLOEXEC has it cleared");
        for (int k = 0; k < 4; k++) if (more[k] >= 0) close(more[k]);
        if (first >= 0) close(first);
        if (second >= 0) close(second);
    }

    /* ART's SafeCopy: its own memory through process_vm_readv on getpid() (the parent's stays refused, above). */
    {
        char from[8] = "own mem", to[8] = {0};
        struct iovec l = {to, sizeof(to)}, r = {from, sizeof(from)};
        EXPECT(process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t) sizeof(from) && memcmp(from, to, sizeof(to)) == 0,
               "process_vm_readv of its own memory (ART's SafeCopy)");
    }

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

/* ---- SBX_LOCK_PATHOPS and SBX_LOCK_INOTIFY: link, symlink and truncate through the broker, marks allowed. ---- */

/*
 * The broker's wire protocol, driven directly. A test (unconfined) builds a
 * request and sends it to a broker thread, then reads the reply, so a
 * malformed or hostile message can be tested without a confined child making
 * it -- the handler would only ever send well-formed ones. The broker learns
 * the sender's pid from SO_PASSCRED, which it sets itself. The first
 * descriptor is the socket the broker answers on; any others follow it.
 * Returns the reply's result, or -EIO if no reply arrived.
 */
static int64_t broker_request(int to, const struct sbx_request *request, const void *body, size_t body_len,
                              const int *extra, int extra_count) {
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, answer) != 0) return -EIO;
    struct timeval timeout = {10, 0};
    setsockopt(answer[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int fds[4];
    int n = 0;
    fds[n++] = answer[1];
    for (int i = 0; i < extra_count && n < 4; i++) fds[n++] = extra[i];
    struct iovec parts[2] = {{(void *) request, sizeof(*request)}, {(void *) body, body_len}};
    union {
        char buffer[CMSG_SPACE(sizeof(int) * 4)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = parts;
    message.msg_iovlen = body_len ? 2 : 1;
    message.msg_control = control.buffer;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * n);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&message);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int) * n);
    memcpy(CMSG_DATA(cm), fds, sizeof(int) * n);
    int64_t result = -EIO;
    if (sendmsg(to, &message, MSG_NOSIGNAL) >= 0) {
        struct sbx_reply header;
        char data[512];
        struct iovec rparts[2] = {{&header, sizeof(header)}, {data, sizeof(data)}};
        struct msghdr rmsg;
        memset(&rmsg, 0, sizeof(rmsg));
        rmsg.msg_iov = rparts;
        rmsg.msg_iovlen = 2;
        ssize_t got = recvmsg(answer[0], &rmsg, 0);
        if (got >= (ssize_t) sizeof(header)) result = header.result;
    }
    close(answer[0]);
    close(answer[1]);
    return result;
}

/* The broker refuses malformed requests rather than misreading or dropping them. */
static int harness_check(void) {
    int before = failures;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    int client = pair[1];
    char path[400];
    int plen = snprintf(path, sizeof(path), "%s/data.txt", game);

    /* Sanity: a well-formed stat of a granted path answers 0, proving the harness itself works. */
    struct sbx_request good = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = (uint32_t) plen};
    EXPECT(broker_request(client, &good, path, (size_t) plen, NULL, 0) == 0, "harness: a well-formed stat answers 0");

    /*
     * dirfd_sent is a count of 0 or 1. A request claiming 2 (with two extra
     * descriptors so the fd count still adds up) must be refused, not read as
     * if one of them were the directory.
     */
    int dir = open(game, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int two[2] = {dir, dir};
    struct sbx_request bad_dirfd = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT,
                                    .path_len = (uint32_t) plen, .dirfd_sent = 2};
    EXPECT(broker_request(client, &bad_dirfd, path, (size_t) plen, two, 2) == -EINVAL,
           "harness: dirfd_sent > 1 is refused with EINVAL");
    if (dir >= 0) close(dir);

    /* A wrong protocol version is refused. */
    struct sbx_request bad_version = {.version = SBX_PROTOCOL_VERSION + 1, .op = SBX_STAT, .path_len = (uint32_t) plen};
    EXPECT(broker_request(client, &bad_version, path, (size_t) plen, NULL, 0) == -EINVAL,
           "harness: a wrong protocol version is refused");

    /* A zero-length path is refused. */
    struct sbx_request empty = {.version = SBX_PROTOCOL_VERSION, .op = SBX_STAT, .path_len = 0};
    EXPECT(broker_request(client, &empty, "", 0, NULL, 0) == -EINVAL, "harness: a zero-length path is refused");

    close(client);
    return failures != before;
}

/*
 * A FIFO in a writable rule must not stall the broker. The broker opens it
 * non-blocking, so a plain open of a FIFO with no writer returns a descriptor
 * instead of holding the broker's one serve thread. An alarm turns a stall
 * (a regression) into a failed child rather than a hung run.
 */
static int fifo_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    char fifo[400], regular[400];
    snprintf(fifo, sizeof(fifo), "%s/f-fifo", save);
    snprintf(regular, sizeof(regular), "%s/f-regular", save);
    unlink(fifo);
    unlink(regular);
    int made = mkfifo(fifo, 0600);
    write_file(regular, "ok");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        alarm(20);
        struct sbx_lockdown_options options = {0};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "fifo: lockdown");
        if (locked != 0) _exit(1);
        if (made == 0) {
            int fd = open(fifo, O_RDONLY);
            EXPECT(fd >= 0, "fifo: a FIFO in a rule opens without stalling the broker");
            if (fd >= 0) close(fd);
            /* Non-blocking at the broker: O_WRONLY with no reader is ENXIO, where unconfined it would wait. */
            errno = 0;
            EXPECT(open(fifo, O_WRONLY) < 0 && errno == ENXIO, "fifo: O_WRONLY with no reader answers ENXIO, not a stall");
        }
        int rf = open(regular, O_RDONLY);
        EXPECT(rf >= 0, "fifo: an ordinary file still opens");
        if (rf >= 0) close(rf);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    unlink(fifo);
    unlink(regular);
    if (made != 0) printf("skip fifo: the host refused mkfifo in the writable folder\n");
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

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
    /* The control: some hosts refuse hard links to everyone (Android's SELinux for the shell and apps). */
    write_file(source, "probe");
    int host_links = link(source, hard) == 0;
    int link_error = errno;
    unlink(hard);
    unlink(source);
    if (!host_links) printf("skip pathops: link between writable names (the host refuses it unconfined: %s)\n", strerror(link_error));
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
        struct stat a, b;
        if (host_links) {
            EXPECT(link(source, hard) == 0, "pathops: link between two writable names");
            EXPECT(stat(source, &a) == 0 && stat(hard, &b) == 0 && a.st_ino == b.st_ino, "pathops: and both name one file");
        }
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

/* ---- SBX_LOCK_WATCH: inotify marks decided and added by the broker. ---- */

/* The mask the kernel holds for watch wd on inotify descriptor fd, from /proc/self/fdinfo; 0 when it is not there. */
static unsigned watch_mask(int fd, int wd) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned mask = 0;
    while (fgets(line, sizeof(line), f)) {
        int found;
        const char *m = strstr(line, " mask:");
        if (sscanf(line, "inotify wd:%x", (unsigned *) &found) == 1 && found == wd && m) {
            mask = (unsigned) strtoul(m + 6, NULL, 16);
        }
    }
    fclose(f);
    return mask;
}

static int watch_check(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    char hidden[400], visible[400], made[500], link_out[400], data[400];
    snprintf(hidden, sizeof(hidden), "%s/w-hidden", game);
    snprintf(visible, sizeof(visible), "%s/w-visible", save);
    snprintf(made, sizeof(made), "%s/w-made", visible);
    snprintf(link_out, sizeof(link_out), "%s/w-link", save);
    snprintf(data, sizeof(data), "%s/data.txt", game);
    mkdir(hidden, 0700);
    mkdir(visible, 0700);
    unlink(link_out);
    if (symlink(secret, link_out) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, hidden, SBX_DENY);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_WATCH | SBX_LOCK_INOTIFY};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "watch: not with SBX_LOCK_INOTIFY");
        options.flags = SBX_LOCK_WATCH | SBX_LOCK_UNBROKERED;
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "watch: not without the broker");
        options.flags = SBX_LOCK_WATCH;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "watch: lockdown");
        if (locked != 0) _exit(1);
        int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        EXPECT(fd >= 0, "watch: an inotify descriptor");

        int wd = inotify_add_watch(fd, visible, IN_CREATE | IN_DELETE);
        EXPECT(wd >= 0, "watch: a folder whose names are all readable");
        unsigned mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT((mask & (IN_CREATE | IN_DELETE)) == (IN_CREATE | IN_DELETE), "watch: keeps the events asked for");
        int made_fd = open(made, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (made_fd >= 0) close(made_fd);
        char events[4096];
        ssize_t got = read(fd, events, sizeof(events));
        const struct inotify_event *event = (const struct inotify_event *) events;
        EXPECT(got >= (ssize_t) sizeof(*event) && event->wd == wd && (event->mask & IN_CREATE) && event->len > 0 &&
                   strcmp(event->name, "w-made") == 0,
               "watch: the event names the file made there");

        wd = inotify_add_watch(fd, game, IN_CREATE | IN_DELETE_SELF);
        EXPECT(wd >= 0, "watch: a folder holding a name it may not read is still watched");
        mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT(!(mask & IN_CREATE) && (mask & IN_DELETE_SELF), "watch: but only for the folder's own events");
        wd = inotify_add_watch(fd, game, IN_CREATE);
        mask = wd >= 0 ? watch_mask(fd, wd) : 0;
        EXPECT(wd >= 0 && !(mask & IN_CREATE) && (mask & IN_DELETE_SELF),
               "watch: one asking only for named events watches for the folder's deletion");

        EXPECT(inotify_add_watch(fd, data, IN_MODIFY) >= 0, "watch: a readable file");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, secret, IN_CREATE)), "watch: a folder outside the rules is refused");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, hidden, IN_CREATE)), "watch: a folder a narrower rule denies is refused");
        errno = 0;
        EXPECT(refused(inotify_add_watch(fd, link_out, IN_CREATE)), "watch: a link out of the rules is refused");
        EXPECT(inotify_add_watch(fd, link_out, IN_ATTRIB | IN_DONT_FOLLOW) >= 0,
               "watch: with IN_DONT_FOLLOW, the link itself is watched");
        errno = 0;
        EXPECT(inotify_add_watch(fd, save, IN_ISDIR | IN_CREATE) < 0 && errno == EINVAL,
               "watch: a flag outside the standard ones is refused");
        int not_inotify[2];
        errno = 0;
        EXPECT(pipe(not_inotify) == 0 && inotify_add_watch(not_inotify[0], save, IN_CREATE) < 0 && errno == EINVAL,
               "watch: a descriptor that is not inotify is refused");
        EXPECT(chdir(save) == 0 && inotify_add_watch(fd, "w-visible", IN_CREATE) >= 0, "watch: a relative path");
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    unlink(made);
    rmdir(visible);
    rmdir(hidden);
    unlink(link_out);
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

/* ---- SBX_LOCK_UNIX: Unix sockets of the process's own, bound and connected by the broker. ---- */

/* A path into sun_path, cut to fit (the test's paths are short). */
static void sun_path_set(struct sockaddr_un *address, const char *path) {
    size_t n = strnlen(path, sizeof(address->sun_path) - 1);
    memcpy(address->sun_path, path, n);
    address->sun_path[n] = '\0';
}

static int unix_listener(const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    sun_path_set(&address, path);
    unlink(path);
    if (s < 0 || bind(s, (struct sockaddr *) &address, sizeof(address)) != 0 || listen(s, 8) != 0) {
        if (s >= 0) close(s);
        return -1;
    }
    return s;
}

static int unix_try(int bind_it, const char *path, int abstract) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -errno;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    socklen_t length;
    if (abstract) {
        size_t n = strlen(path);
        memcpy(address.sun_path + 1, path, n);
        length = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + n);
    } else {
        sun_path_set(&address, path);
        length = sizeof(address);
    }
    int r = bind_it ? bind(s, (struct sockaddr *) &address, length) : connect(s, (struct sockaddr *) &address, length);
    int error = r == 0 ? 0 : -errno;
    close(s);
    return error;
}

/* The control for socket files: 0 when the host lets this process make one in folder, else the errno. */
static int host_socket_files(const char *folder) {
    char path[400];
    snprintf(path, sizeof(path), "%s/probe.sock", folder);
    int s = unix_listener(path);
    int error = s >= 0 ? 0 : errno;
    if (s >= 0) close(s);
    unlink(path);
    return error;
}

static int unix_check(void) {
    char inside[400], outside[400], sock_link[400], made[400];
    /* Some hosts let no one make socket files here (Android's shell in /data/local/tmp): those checks are skipped. */
    int files_error = host_socket_files(save);
    int files = files_error == 0;
    if (!files) printf("skip unix: socket files (the host refuses them unconfined: %s)\n", strerror(files_error));
    snprintf(inside, sizeof(inside), "%s/server.sock", game);
    snprintf(outside, sizeof(outside), "%s/server.sock", secret);
    snprintf(sock_link, sizeof(sock_link), "%s/sock-link", save);
    snprintf(made, sizeof(made), "%s/child.sock", save);
    int inside_server = files ? unix_listener(inside) : -1, outside_server = files ? unix_listener(outside) : -1;
    unlink(sock_link);
    if (files && (inside_server < 0 || outside_server < 0 || symlink(outside, sock_link) != 0)) {
        printf("FAIL unix: could not set up the servers (%s)\n", strerror(errno));
        return 1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    EXPECT(sbx_policy_add_unix_name(policy, "sbx-test-name", SBX_READ | SBX_WRITE) == 0, "unix: an abstract name in the policy");
    EXPECT(sbx_policy_add_unix_name(policy, "", SBX_READ) == -EINVAL, "unix: an empty abstract name is refused");
    sbx_policy_set_net(policy, SBX_NET_CONNECT | SBX_NET_LISTEN);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNIX | SBX_LOCK_UNBROKERED};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "unix: not without the broker");
        options.flags = SBX_LOCK_UNIX | SBX_LOCK_NET_BROKERED;
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "unix: not with the brokered network");
        options.flags = SBX_LOCK_UNIX | SBX_LOCK_INET;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "unix: lockdown with SBX_LOCK_INET as well");
        if (locked != 0) _exit(1);
        errno = 0;
        EXPECT(refused(socket(AF_UNIX, SOCK_DGRAM, 0)), "unix: a datagram socket is still refused");
        errno = 0;
        EXPECT(refused(socket(AF_NETLINK, SOCK_RAW, 0)), "unix: netlink is still refused");
        int seq = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        EXPECT(seq >= 0, "unix: a seqpacket socket");
        if (seq >= 0) close(seq);
        if (files) {
            EXPECT(unix_try(0, inside, 0) == 0, "unix: connect to a socket in a readable rule");
            EXPECT(unix_try(0, outside, 0) == -EACCES, "unix: connect to a socket outside the rules is refused");
            EXPECT(unix_try(0, sock_link, 0) == -EACCES, "unix: connect through a link leading out is refused");
        }
        EXPECT(unix_try(1, inside, 0) == -EACCES, "unix: bind in a read-only rule is refused");
        EXPECT(unix_try(1, "sbx-test-other", 1) == -EACCES, "unix: bind of an abstract name the policy lacks is refused");
        EXPECT(unix_try(0, "sbx-test-other", 1) == -EACCES, "unix: connect to one is refused");

        /* A server of its own in the writable rule, and a client of it. */
        int server = files ? socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) : -1;
        if (files) {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        sun_path_set(&address, made);
        EXPECT(server >= 0 && bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "unix: bind in the writable rule");
        EXPECT(listen(server, 4) == 0, "unix: listen on it");
        int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(client >= 0 && connect(client, (struct sockaddr *) &address, sizeof(address)) == 0, "unix: connect to it");
        int accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        char byte = 0;
        EXPECT(accepted >= 0 && write(client, "u", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'u',
               "unix: bytes cross it");
        if (accepted >= 0) close(accepted);
        if (client >= 0) close(client);
        if (server >= 0) close(server);
        EXPECT(chdir(save) == 0 && unix_try(1, "relative.sock", 0) == 0, "unix: bind of a relative path in the writable rule");
        }
        int named = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un abstract = {.sun_family = AF_UNIX};
        memcpy(abstract.sun_path + 1, "sbx-test-name", 13);
        socklen_t abstract_length = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + 13);
        EXPECT(named >= 0 && bind(named, (struct sockaddr *) &abstract, abstract_length) == 0 && listen(named, 2) == 0,
               "unix: bind and listen on an abstract name the policy lists");
        EXPECT(unix_try(0, "sbx-test-name", 1) == 0, "unix: connect to it");
        if (named >= 0) close(named);

        /* Inet, through the broker under its network grants. */
        int inet = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in loopback = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t loopback_length = sizeof(loopback);
        EXPECT(inet >= 0 && bind(inet, (struct sockaddr *) &loopback, sizeof(loopback)) == 0 && listen(inet, 2) == 0 &&
                   getsockname(inet, (struct sockaddr *) &loopback, &loopback_length) == 0,
               "unix+inet: bind and listen on 127.0.0.1 through the broker");
        int inet_client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(inet_client >= 0 && connect(inet_client, (struct sockaddr *) &loopback, sizeof(loopback)) == 0,
               "unix+inet: connect to it through the broker");
        if (inet_client >= 0) close(inet_client);
        if (inet >= 0) close(inet);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    if (inside_server >= 0) close(inside_server);
    if (outside_server >= 0) close(outside_server);
    unlink(inside);
    unlink(outside);
    unlink(sock_link);
    unlink(made);
    char relative[400];
    snprintf(relative, sizeof(relative), "%s/relative.sock", save);
    unlink(relative);
    if (WIFSIGNALED(status)) printf("FAIL unix: the child died by signal %d\n", WTERMSIG(status));
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

/* ---- SBX_LOCK_CONTAIN: the file system view restricted, sockets and signals left to the kernel. ---- */

static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal_number) { (void) signal_number; usr1_seen = 1; }

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

/* ---- The confinement contract: sbx_negotiate's report, and sbx_lockdown_checked's gate. ---- */

static int contract_check(void) {
    struct sbx_report r;
    struct sbx_requirements req;

    struct sbx_lockdown_options base = {.flags = 0};
    memset(&r, 0, sizeof(r));
    r.size = sizeof(r);
    EXPECT(sbx_negotiate(NULL, &base, NULL, &r) == 0, "contract: a plain lockdown negotiates");
    uint64_t want = SBX_G_FS_MEDIATED | SBX_G_NET_NONE | SBX_G_SIGNALS_SELF | SBX_G_EXEC_NONE | SBX_G_NOT_LEARNING |
                    SBX_G_NO_DEVICES;
    EXPECT((r.effective & want) == want, "contract: a plain lockdown's guarantees are effective");
    EXPECT(r.blocking & SBX_G_IPC_NONE, "contract: IPC-none is ruled out on this backend");
    EXPECT((r.residual & (SBX_R_HOST_UID | SBX_R_KERNEL_SURFACE)) == (SBX_R_HOST_UID | SBX_R_KERNEL_SURFACE),
           "contract: the host uid and kernel surface are residual");
    EXPECT(r.backend[0] != '\0' && r.backend_version != 0, "contract: the backend is named and versioned");

    memset(&req, 0, sizeof(req));
    req.size = sizeof(req);
    req.required = SBX_G_NET_NONE;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == 0, "contract: requiring no-network is met by a plain lockdown");
    req.required = SBX_G_IPC_NONE;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == -EPERM && r.reason[0], "contract: requiring no-IPC fails, with a reason");
    req.required = 0;
    req.forbidden = SBX_R_HOST_UID;
    EXPECT(sbx_negotiate(NULL, &base, &req, &r) == -EPERM, "contract: forbidding the host uid fails a same-uid lockdown");

    struct sbx_lockdown_options inet = {.flags = SBX_LOCK_INET};
    memset(&req, 0, sizeof(req));
    req.size = sizeof(req);
    req.required = SBX_G_NET_NONE;
    EXPECT(sbx_negotiate(NULL, &inet, &req, &r) == -EPERM, "contract: INET cannot satisfy no-network");
    EXPECT((r.blocking & SBX_G_NET_NONE) && (r.residual & SBX_R_NETWORK_ANY), "contract: INET blocks no-network, leaves network residual");

    struct sbx_lockdown_options contain = {.flags = SBX_LOCK_CONTAIN, .exec_helper = "h", .child_library = "/l"};
    EXPECT(sbx_negotiate(NULL, &contain, NULL, &r) == 0, "contract: the containment preset negotiates");
    EXPECT((r.effective & SBX_G_EXEC_CONFINED) && !(r.effective & SBX_G_SIGNALS_SELF), "contract: CONTAIN confines exec, opens signals");
    EXPECT((r.residual & SBX_R_UID_SIGNALS) && (r.residual & SBX_R_UID_SOCKETS), "contract: CONTAIN leaves uid signals and sockets residual");

    struct sbx_report r2;
    memset(&r2, 0, sizeof(r2));
    r2.size = sizeof(r2);
    sbx_negotiate(NULL, &base, NULL, &r);
    sbx_negotiate(NULL, &base, NULL, &r2);
    EXPECT(memcmp(r.policy_digest, r2.policy_digest, 32) == 0, "contract: the same policy digests the same");
    sbx_negotiate(NULL, &inet, NULL, &r2);
    EXPECT(memcmp(r.policy_digest, r2.policy_digest, 32) != 0, "contract: different flags digest differently");

    memset(&r, 0, sizeof(r));
    EXPECT(sbx_negotiate(NULL, &base, NULL, &r) == -EINVAL, "contract: a report without its size is refused");

    /* The gate installs or refuses, and nothing in between. */
    fflush(stdout);
    pid_t met = fork();
    if (met == 0) {
        struct sbx_lockdown_options o = {.flags = SBX_LOCK_UNBROKERED};
        struct sbx_requirements want_none = {.size = sizeof(want_none), .required = SBX_G_NET_NONE};
        struct sbx_report rep = {.size = sizeof(rep)};
        if (sbx_lockdown_checked(-1, &o, &want_none, &rep) != 0) _exit(1);
        _exit(socket(AF_INET, SOCK_STREAM, 0) < 0 && errno == EACCES ? 0 : 2);  /* locked: no sockets */
    }
    int status = 0;
    waitpid(met, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "contract: a met requirement locks down, and the filter holds");

    fflush(stdout);
    pid_t unmet = fork();
    if (unmet == 0) {
        struct sbx_lockdown_options o = {.flags = SBX_LOCK_UNBROKERED};
        struct sbx_requirements impossible = {.size = sizeof(impossible), .required = SBX_G_IPC_NONE};
        struct sbx_report rep = {.size = sizeof(rep)};
        if (sbx_lockdown_checked(-1, &o, &impossible, &rep) != -EPERM) _exit(1);
        int s = socket(AF_INET, SOCK_STREAM, 0);  /* not locked: a socket is still possible */
        if (s >= 0) close(s);
        _exit(s >= 0 ? 0 : 2);
    }
    waitpid(unmet, &status, 0);
    EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "contract: an unmet requirement installs nothing");

    return failures ? 1 : 0;
}

/*
 * A-02: ioctl(fd, TIOCSTI) and ioctl(fd, TIOCLINUX) push bytes into the
 * input queue of a terminal the process inherited, so a confined process
 * could plant a command the shell runs after it exits. The filter refuses
 * both on any descriptor; a harmless ioctl still reaches the kernel.
 */
#ifndef TIOCLINUX
#define TIOCLINUX 0x541c
#endif
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
    if (argc > 3 && strcmp(argv[1], "--attached") == 0) return attached_main(argv[2], argv[3]);
    if (argc > 1 && strcmp(argv[1], "--exec-child") == 0) return exec_child_main(argc, argv);
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

    int sealed_failures = sealed_check() | sigsys_check() | learn_check() | trace_check() | fault_check(self, 0) | fault_check(self, 1) | pathops_check() | fifo_check() | harness_check() | watch_check() | unix_check() | contain_check(self) | signal_tree_check() | listen_check(self) | exec_helper_check(self) | exec_check(self) | program_tree_check(self) | unbrokered_check() | inet_check() | contract_check() | tiocsti_check() | passthrough_check() | list_check() |
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
