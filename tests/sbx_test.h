/*
 * The test's harness: what every area shares (tests/sbx_test.c includes it first, then each area).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_TEST_H
#define SBX_TEST_H

#define _GNU_SOURCE
#include "sbx.h"
#include "sbx_contract.h"
#include "sbx_zones.h"
#include "protocol.h"
#include "exec_shared.h"

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
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef __NR_statx
#define __NR_statx 332
static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal_number) { (void) signal_number; usr1_seen = 1; }

#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal_number) { (void) signal_number; usr1_seen = 1; }

#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal_number) { (void) signal_number; usr1_seen = 1; }

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


static volatile sig_atomic_t usr1_seen;
static void on_usr1(int signal_number) { (void) signal_number; usr1_seen = 1; }

#endif
