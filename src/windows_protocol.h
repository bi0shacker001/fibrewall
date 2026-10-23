/*
 * The Windows broker's wire format, on a message-mode named pipe: one
 * request message, one reply message. The path is UTF-8 and ends with a
 * NUL within length.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_WINDOWS_PROTOCOL_H
#define SBX_WINDOWS_PROTOCOL_H

#include <stdint.h>

#define SBXW_VERSION 1u
#define SBXW_OPEN 1u
#define SBXW_PATH_MAX 4096
#define SBXW_ENV L"SBX_BROKER"

struct sbxw_request {
    uint32_t version;
    uint32_t op;
    uint32_t flags;   /* SBX_OPEN_* */
    uint32_t length;  /* bytes of path, its NUL included */
    char path[SBXW_PATH_MAX];
};

#define SBXW_HEADER (4 * sizeof(uint32_t))

struct sbxw_reply {
    int32_t result;   /* 0 or a negative errno */
    uint32_t reserved;
    uint64_t handle;  /* the handle's value in the confined process */
};

#endif
