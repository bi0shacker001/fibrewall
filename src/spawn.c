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

static int spec_invalid(const struct sbx_spawn_spec *spec) {
    return !spec || !spec->path || !spec->argv || spec->fd_count > SBX_SPAWN_FDS_MAX ||
           (spec->fd_count && !spec->fds) || spec->limit_count > SBX_SPAWN_LIMITS_MAX ||
           (spec->limit_count && !spec->limits);
}

/*
 * In the forked child: puts the handed descriptors at 3.., and, for a
 * confined spawn, the broker just above them (broker_in >= 0). Closes every
 * other descriptor, sets the limits and the parent-death signal, and clears
 * the signal mask. report is where failures are reported and is moved out of
 * the way first; it is updated to where it went. broker_out, when a broker
 * was staged, gets the broker's new number. On any failure the errno is
 * reported through report and the child _exits; this returns only on success.
 */
static void child_setup(const struct sbx_spawn_spec *spec, pid_t parent, int *report,
                        int broker_in, int *broker_out) {
    unsigned keep = spec->fd_count + (broker_in >= 0 ? 1u : 0u);
    /* Out of the way first: every descriptor to keep goes above everything it could collide with. */
    int high = FIRST_FD + (int) keep + 1;
    if (*report < high) {
        int moved = fcntl(*report, F_DUPFD_CLOEXEC, high);
        if (moved < 0) _exit(127);
        *report = moved;
    }
    int staged[SBX_SPAWN_FDS_MAX + 1];
    int floor = *report + 1;
    for (unsigned i = 0; i < spec->fd_count; i++) {
        staged[i] = fcntl(spec->fds[i], F_DUPFD_CLOEXEC, floor);
        if (staged[i] < 0) fail(*report, errno);
        floor = staged[i] + 1;
    }
    if (broker_in >= 0) {
        staged[spec->fd_count] = fcntl(broker_in, F_DUPFD_CLOEXEC, floor);
        if (staged[spec->fd_count] < 0) fail(*report, errno);
    }
    for (unsigned i = 0; i < keep; i++) {
        if (dup2(staged[i], FIRST_FD + (int) i) < 0) fail(*report, errno);  /* dup2 leaves the copy inheritable */
    }
    /* Keep 0-2, the handed ones, the broker (confined spawn) and the report pipe; close the rest. */
    int keep_top = FIRST_FD + (int) keep;
    for (int fd = keep_top; fd < *report; fd++) close(fd);
    close_from(*report + 1);
    if (broker_out) *broker_out = FIRST_FD + (int) spec->fd_count;
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) fail(*report, errno);
    if (getppid() != parent) _exit(127);  /* the parent is already gone */
    for (unsigned i = 0; i < spec->limit_count; i++) {
        struct rlimit limit = {spec->limits[i].value, spec->limits[i].value};
        if (setrlimit(spec->limits[i].resource, &limit) != 0) fail(*report, errno);
    }
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
}

/* Parent side: reads the child's report pipe. A reported errno means it failed before executing. */
static int reap_report(int report0, pid_t pid, pid_t *pid_out) {
    int error = 0;
    ssize_t n;
    do n = read(report0, &error, sizeof(error));
    while (n < 0 && errno == EINTR);
    close(report0);
    if (n == (ssize_t) sizeof(error)) {
        waitpid(pid, NULL, 0);
        return -error;
    }
    if (pid_out) *pid_out = pid;
    return 0;
}

int sbx_spawn(const struct sbx_spawn_spec *spec, pid_t *pid_out) {
    if (spec_invalid(spec)) return -EINVAL;
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
        int rep = report[1];
        child_setup(spec, parent, &rep, -1, NULL);
        char *const empty[] = {NULL};
        execve(spec->path, spec->argv, spec->envp ? spec->envp : empty);
        fail(rep, errno);
    }
    close(report[1]);
    return reap_report(report[0], pid, pid_out);
}

/*
 * Like sbx_spawn, but the program is confined before its first instruction
 * (A-04): the child installs the lockdown with SBX_LOCK_EXEC and the broker,
 * then execs the program through sbx-exec, so its loader, preinit array and
 * constructors already run under the filter. A plain sbx_spawn leaves the
 * program to lock itself down, which a loader or a static binary runs ahead
 * of. options must name the exec helper and child library (SBX_LOCK_EXEC
 * needs them) and is taken as given but for SBX_LOCK_EXEC, which is forced on.
 */
int sbx_spawn_confined(const struct sbx_spawn_spec *spec, int broker_fd,
                       const struct sbx_lockdown_options *options, pid_t *pid_out) {
    if (spec_invalid(spec) || broker_fd < 0 || !options || !options->exec_helper || !options->child_library) {
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
        int rep = report[1];
        int broker = -1;
        child_setup(spec, parent, &rep, broker_fd, &broker);
        struct sbx_lockdown_options confined = *options;
        confined.flags |= SBX_LOCK_EXEC;
        int locked = sbx_lockdown(broker, &confined);
        if (locked != 0) fail(rep, -locked);
        char *const empty[] = {NULL};
        execve(spec->path, spec->argv, spec->envp ? spec->envp : empty);
        fail(rep, errno);
    }
    close(report[1]);
    return reap_report(report[0], pid, pid_out);
}

int sbx_spawned_init(void) {
    /* exec made the process dumpable again; no other process of the same user may read its memory. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0) return -errno;
    return 0;
}
