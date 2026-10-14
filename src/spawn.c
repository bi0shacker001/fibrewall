/*
 * sbx_spawn: starts a program as a fresh process with exactly the
 * descriptors it is given, numbered from 3 in order, and limits set before
 * it runs. On Android this is how a native-kind sandbox starts: an app may
 * execute files in its own native-library directory, and the new process
 * has no ART, no binder and nothing of its parent's but what it was
 * handed. The program then sets itself up and calls sbx_lockdown().
 *
 * Between fork and exec only async-signal-safe calls are made, since the
 * parent may have other threads.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIRST_FD 3

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/*
 * Closes every descriptor from first up, listed through /proc/self/fd with
 * raw getdents64 (no allocation). Not close_range: older Android app
 * filters do not list it, and an unlisted call kills the process.
 */
static void close_from(int first) {
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) {
        struct rlimit limit;
        long top = 65536;
        if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < 1048576) {
            top = (long) limit.rlim_cur;
        }
        for (long fd = first; fd < top; fd++) close((int) fd);
        return;
    }
    char buffer[4096] __attribute__((aligned(8)));
    for (;;) {
        long n = syscall(SYS_getdents64, dir, buffer, sizeof(buffer));
        if (n <= 0) break;
        for (long offset = 0; offset < n;) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *) (buffer + offset);
            offset += entry->d_reclen;
            int fd = 0, digits = 0;
            for (const char *c = entry->d_name; *c >= '0' && *c <= '9'; c++, digits++) fd = fd * 10 + (*c - '0');
            if (digits > 0 && entry->d_name[digits] == 0 && fd >= first && fd != dir) close(fd);
        }
    }
    close(dir);
}

static void fail(int report, int error) {
    ssize_t ignored = write(report, &error, sizeof(error));
    (void) ignored;
    _exit(127);
}

int sbx_spawn(const struct sbx_spawn_spec *spec, pid_t *pid_out) {
    if (!spec || !spec->path || !spec->argv || spec->fd_count > SBX_SPAWN_FDS_MAX ||
        (spec->fd_count && !spec->fds) || spec->limit_count > SBX_SPAWN_LIMITS_MAX ||
        (spec->limit_count && !spec->limits)) {
        return -EINVAL;
    }
    int report[2];
    if (pipe2(report, O_CLOEXEC) != 0) return -errno;
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        int error = errno;
        close(report[0]);
        close(report[1]);
        return -error;
    }
    if (pid == 0) {
        close(report[0]);
        /* Out of the way first: every descriptor to keep goes above everything it could collide with. */
        int high = FIRST_FD + (int) spec->fd_count + 1;
        if (report[1] < high) {
            int moved = fcntl(report[1], F_DUPFD_CLOEXEC, high);
            if (moved < 0) _exit(127);
            report[1] = moved;
        }
        int staged[SBX_SPAWN_FDS_MAX];
        int floor = report[1] + 1;
        for (unsigned i = 0; i < spec->fd_count; i++) {
            staged[i] = fcntl(spec->fds[i], F_DUPFD_CLOEXEC, floor);
            if (staged[i] < 0) fail(report[1], errno);
            floor = staged[i] + 1;
        }
        for (unsigned i = 0; i < spec->fd_count; i++) {
            if (dup2(staged[i], FIRST_FD + (int) i) < 0) fail(report[1], errno);  /* dup2 leaves the copy inheritable */
        }
        /* Keep 0-2 (or /dev/null them, which needs an open the caller may not want), the handed ones, and the report pipe. */
        int keep_top = FIRST_FD + (int) spec->fd_count;
        for (int fd = keep_top; fd < report[1]; fd++) close(fd);
        close_from(report[1] + 1);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) fail(report[1], errno);
        if (getppid() != parent) _exit(127);  /* the parent is already gone */
        for (unsigned i = 0; i < spec->limit_count; i++) {
            struct rlimit limit = {spec->limits[i].value, spec->limits[i].value};
            if (setrlimit(spec->limits[i].resource, &limit) != 0) fail(report[1], errno);
        }
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        char *const empty[] = {NULL};
        execve(spec->path, spec->argv, spec->envp ? spec->envp : empty);
        fail(report[1], errno);
    }
    close(report[1]);
    int error = 0;
    ssize_t n;
    do n = read(report[0], &error, sizeof(error));
    while (n < 0 && errno == EINTR);
    close(report[0]);
    if (n == (ssize_t) sizeof(error)) {
        waitpid(pid, NULL, 0);
        return -error;
    }
    if (pid_out) *pid_out = pid;
    return 0;
}

int sbx_spawned_init(void) {
    /* exec made the process dumpable again; no other process of the same user may read its memory. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0) return -errno;
    return 0;
}
