/*
 * sbx_open on Windows: the confined program's explicit request to the
 * broker, on the pipe end it inherited (its value is in SBX_BROKER). The
 * reply's handle has already been duplicated into this process. Nothing
 * here is trusted: a program that skips it only loses its own access.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "sbx.h"
#include "windows_protocol.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#define WRITING (SBX_OPEN_WRITE | SBX_OPEN_CREATE | SBX_OPEN_TRUNCATE | SBX_OPEN_EXCLUSIVE | SBX_OPEN_APPEND)
#define ALL (SBX_OPEN_READ | WRITING | SBX_OPEN_DIRECTORY)

static SRWLOCK channel_lock = SRWLOCK_INIT;
static HANDLE channel;
static int channel_looked;

/* Called with channel_lock held. */
static HANDLE broker_channel(void) {
    if (channel_looked) return channel;
    channel_looked = 1;
    wchar_t value[32];
    DWORD n = GetEnvironmentVariableW(SBXW_ENV, value, 32);
    if (n == 0 || n >= 32) return NULL;
    unsigned long long number = 0;
    for (DWORD i = 0; i < n; i++) {
        if (value[i] < L'0' || value[i] > L'9') return NULL;
        number = number * 10 + (unsigned long long) (value[i] - L'0');
    }
    HANDLE pipe = (HANDLE) (uintptr_t) number;
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) return NULL;
    channel = pipe;
    return channel;
}

int sbx_open(const char *path, unsigned flags, sbx_handle *out) {
    if (!path || !out || (flags & ~ALL)) return -EINVAL;
    size_t length = strlen(path) + 1;
    if (length > SBXW_PATH_MAX) return -ENAMETOOLONG;
    struct sbxw_request request;
    request.version = SBXW_VERSION;
    request.op = SBXW_OPEN;
    request.flags = flags;
    request.length = (uint32_t) length;
    memcpy(request.path, path, length);
    struct sbxw_reply reply;
    DWORD got = 0;
    AcquireSRWLockExclusive(&channel_lock);
    HANDLE pipe = broker_channel();
    BOOL sent = pipe && TransactNamedPipe(pipe, &request, (DWORD) (SBXW_HEADER + length), &reply, sizeof(reply), &got, NULL);
    ReleaseSRWLockExclusive(&channel_lock);
    if (!pipe) return -ENOSYS;
    if (!sent || got != sizeof(reply)) return -EIO;
    if (reply.result != 0) return reply.result < 0 ? reply.result : -EIO;
    *out = (HANDLE) (uintptr_t) reply.handle;
    return 0;
}
