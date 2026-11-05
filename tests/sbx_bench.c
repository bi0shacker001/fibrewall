/*
 * sbx_bench: what confinement costs, for Droidtop/tracker#791 (Syncthing
 * over a very large folder). Prints, for this machine:
 *   - the cost of one call, split: the native call; a trapped call answered
 *     in the process (the trap alone); a brokered call (trap, IPC and the
 *     broker's decision), and the broker's CPU per request;
 *   - a walk of a tree of N files (default 100000): stat each, then open and
 *     close each, natively and under lockdown;
 *   - the broker's CPU over the walk.
 * A measurement, not a test: it fails only when it cannot run.
 *
 *   sbx_bench [files] [directory]
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PER_DIRECTORY 1000
#define REPEAT 20000

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static double cpu_us(void) {
    struct rusage r;
    getrusage(RUSAGE_SELF, &r);
    return (r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1e6 + r.ru_utime.tv_usec + r.ru_stime.tv_usec;
}

static char root[512];
static long files;

static void file_name(long i, char *out, size_t size) {
    snprintf(out, size, "%s/d%04ld/f%06ld.dat", root, i / PER_DIRECTORY, i);
}

static int make_tree(void) {
    char path[600];
    for (long i = 0; i < files; i++) {
        if (i % PER_DIRECTORY == 0) {
            snprintf(path, sizeof(path), "%s/d%04ld", root, i / PER_DIRECTORY);
            if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
        }
        file_name(i, path, sizeof(path));
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0) return -1;
        close(fd);
    }
    return 0;
}

/* The measurements one process makes, natively or confined; microseconds per call. */
struct numbers {
    double readlink_self;  /* readlink of /proc/self/fd/N: native, or answered in the handler (the trap alone) */
    double stat_one;       /* stat of one file, over and over */
    double walk_stat;      /* stat of every file in the tree */
    double walk_open;      /* open and close of every file */
    double walk_list;      /* opendir, readdir and closedir of every folder */
    double walk_list_stat; /* every file's metadata a folder at a time: readdir and fstatat, or sbx_list_stat */
    long errors;
};

static void measure(struct numbers *n, int confined) {
    memset(n, 0, sizeof(*n));
    char link[64], target[600], path[600];
    struct stat st;
    snprintf(link, sizeof(link), "/proc/self/fd/%d", 1);
    double t = now_us();
    for (int i = 0; i < REPEAT; i++) {
        if (readlink(link, target, sizeof(target)) < 0) n->errors++;
    }
    n->readlink_self = (now_us() - t) / REPEAT;
    file_name(0, path, sizeof(path));
    t = now_us();
    for (int i = 0; i < REPEAT; i++) {
        if (stat(path, &st) != 0) n->errors++;
    }
    n->stat_one = (now_us() - t) / REPEAT;
    t = now_us();
    for (long i = 0; i < files; i++) {
        file_name(i, path, sizeof(path));
        if (stat(path, &st) != 0) n->errors++;
    }
    n->walk_stat = (now_us() - t) / files;
    t = now_us();
    for (long i = 0; i < files; i++) {
        file_name(i, path, sizeof(path));
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) n->errors++;
        else close(fd);
    }
    n->walk_open = (now_us() - t) / files;
    long folders = (files + PER_DIRECTORY - 1) / PER_DIRECTORY;
    t = now_us();
    for (long d = 0; d < folders; d++) {
        snprintf(path, sizeof(path), "%s/d%04ld", root, d);
        DIR *dir = opendir(path);
        if (!dir) { n->errors++; continue; }
        while (readdir(dir)) {}
        closedir(dir);
    }
    n->walk_list = (now_us() - t) / folders;
    static char records[32768];
    long seen = 0;
    t = now_us();
    for (long d = 0; d < folders; d++) {
        snprintf(path, sizeof(path), "%s/d%04ld", root, d);
        int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) { n->errors++; continue; }
        if (confined) {
            long got;
            while ((got = sbx_list_stat(fd, records, sizeof(records))) > 0) {
                for (long at = 0; at < got;) {
                    const struct sbx_list_stat_entry *e = (const void *) (records + at);
                    if (e->has_stat) seen++;
                    at += e->record_len;
                }
            }
            if (got < 0) n->errors++;
        } else {
            DIR *dir = fdopendir(fd);
            struct dirent *entry;
            while (dir && (entry = readdir(dir))) {
                if (entry->d_name[0] == '.') continue;
                if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) seen++;
            }
            if (dir) closedir(dir);
            fd = -1;
        }
        if (fd >= 0) close(fd);
    }
    n->walk_list_stat = (now_us() - t) / files;
    if (seen != files) n->errors++;
}

static long requests;
static void count(void *context, const struct sbx_access *access, int result) {
    (void) context;
    (void) access;
    (void) result;
    __atomic_add_fetch(&requests, 1, __ATOMIC_RELAXED);
}

int main(int argc, char **argv) {
    files = argc > 1 ? atol(argv[1]) : 100000;
    if (files < PER_DIRECTORY) files = PER_DIRECTORY;
    const char *tmp = argc > 2 ? argv[2] : getenv("TMPDIR");
    snprintf(root, sizeof(root), "%s/sbx-bench-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(root)) { perror("mkdtemp"); return 2; }
    double t = now_us();
    if (make_tree() != 0) { perror("tree"); return 2; }
    printf("tree: %ld files in %ld folders under %s, made in %.1f s\n", files, (files + PER_DIRECTORY - 1) / PER_DIRECTORY,
           root, (now_us() - t) / 1e6);

    struct numbers native;
    measure(&native, 0);

    int pair[2], report[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0 || pipe(report) != 0) { perror("socketpair"); return 2; }
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, root, SBX_READ);
    sbx_policy_add(policy, "/proc", SBX_READ);
    sbx_policy_set_audit(policy, count, NULL);
    sbx_broker_prepare(pair[0]);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        close(report[0]);
        struct sbx_lockdown_options options = {.flags = 0};
        int locked = sbx_lockdown(pair[1], &options);
        struct numbers confined;
        memset(&confined, 0, sizeof(confined));
        if (locked == 0) measure(&confined, 1);
        else confined.errors = -1;
        ssize_t w = write(report[1], &confined, sizeof(confined));
        _exit(w == (ssize_t) sizeof(confined) ? 0 : 1);
    }
    close(pair[1]);
    close(report[1]);
    double cpu_before = cpu_us();
    sbx_broker_serve(policy, pair[0]);
    double broker_cpu = cpu_us() - cpu_before;
    struct numbers confined;
    ssize_t r = read(report[0], &confined, sizeof(confined));
    int status = 0;
    waitpid(child, &status, 0);
    if (r != (ssize_t) sizeof(confined) || confined.errors < 0) {
        printf("FAIL the confined run did not report (lockdown failed?)\n");
        return 1;
    }

    printf("\n%-44s %12s %12s %8s\n", "per call (microseconds)", "native", "confined", "ratio");
    struct {
        const char *what;
        double a, b;
    } rows[] = {
        {"readlink /proc/self/fd/1 (trap alone)", native.readlink_self, confined.readlink_self},
        {"stat of one file, repeated (brokered)", native.stat_one, confined.stat_one},
        {"walk: stat every file", native.walk_stat, confined.walk_stat},
        {"walk: open and close every file", native.walk_open, confined.walk_open},
        {"walk: list every folder (per folder)", native.walk_list, confined.walk_list},
        {"walk: metadata a folder at a time (per file)", native.walk_list_stat, confined.walk_list_stat},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        printf("%-44s %12.2f %12.2f %7.1fx\n", rows[i].what, rows[i].a, rows[i].b, rows[i].a > 0 ? rows[i].b / rows[i].a : 0);
    }
    double trap = confined.readlink_self - native.readlink_self;
    double brokered = confined.stat_one - native.stat_one;
    printf("\nsplit of one brokered stat: trap %.2f us, IPC and decision %.2f us\n", trap, brokered - trap);
    long n = __atomic_load_n(&requests, __ATOMIC_RELAXED);
    printf("broker: %ld requests, %.1f s CPU, %.2f us CPU per request\n", n, broker_cpu / 1e6, n ? broker_cpu / n : 0);
    printf("100k-file walk, confined: stat %.1f s, open+close %.1f s, sbx_list_stat %.2f s"
           " (native %.2f s, %.2f s, readdir+fstatat %.2f s)\n",
           confined.walk_stat * 100000 / 1e6, confined.walk_open * 100000 / 1e6, confined.walk_list_stat * 100000 / 1e6,
           native.walk_stat * 100000 / 1e6, native.walk_open * 100000 / 1e6, native.walk_list_stat * 100000 / 1e6);
    /* The tree is this run's own: removed file by file. */
    char path[600];
    for (long i = 0; i < files; i++) {
        file_name(i, path, sizeof(path));
        unlink(path);
        if (i % PER_DIRECTORY == PER_DIRECTORY - 1 || i == files - 1) {
            snprintf(path, sizeof(path), "%s/d%04ld", root, i / PER_DIRECTORY);
            rmdir(path);
        }
    }
    rmdir(root);
    if (native.errors || confined.errors) printf("errors: native %ld, confined %ld\n", native.errors, confined.errors);
    return native.errors || confined.errors ? 1 : 0;
}
