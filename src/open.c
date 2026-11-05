/*
 * sbx_open on Linux and Android: an open() by path. Under sbx_lockdown it
 * traps and the broker answers it, so a host's code can use the same call
 * on every system (on Windows it is an explicit request, src/windows_client.c).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"
#include "open_flags.h"

#include <errno.h>
#include <fcntl.h>

int sbx_open(const char *path, unsigned flags, sbx_handle *out) {
    if (!path || !out || path[0] != '/' || !sbx_open_flags_valid(flags)) return -EINVAL;
    int open_flags = O_CLOEXEC;
    if (flags & SBX_OPEN_DIRECTORY) {
        open_flags |= O_RDONLY | O_DIRECTORY;
    } else {
        unsigned access = flags & (SBX_OPEN_READ | SBX_OPEN_WRITE);
        open_flags |= access == (SBX_OPEN_READ | SBX_OPEN_WRITE) ? O_RDWR : access == SBX_OPEN_WRITE ? O_WRONLY : O_RDONLY;
        if (flags & SBX_OPEN_CREATE) open_flags |= O_CREAT;
        if (flags & SBX_OPEN_TRUNCATE) open_flags |= O_TRUNC;
        if (flags & SBX_OPEN_EXCLUSIVE) open_flags |= O_EXCL;
        if (flags & SBX_OPEN_APPEND) open_flags |= O_APPEND;
    }
    int fd = open(path, open_flags, 0666);
    if (fd < 0) return -errno;
    *out = fd;
    return 0;
}
