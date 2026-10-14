/*
 * The wire format between lockdown.c's SIGSYS handler and broker.c.
 *
 * Request, one SEQPACKET message: struct sbx_request, then path_len bytes
 * of path, then path2_len bytes of the second path (rename), neither
 * terminated. Descriptors travel with it (SCM_RIGHTS): first the socket to
 * answer on (one end of a socketpair made for this request alone, so
 * threads share nothing), then the directory the path is relative to when
 * dirfd_sent, then the second path's when dirfd2_sent. A relative path
 * whose directory is AT_FDCWD is relative to the confined process's
 * current directory, which the handler keeps (the process cannot chdir
 * for real) and sends. The broker learns the sender's pid from
 * SCM_CREDENTIALS, not from the request.
 *
 * Reply, one message on the answer socket: struct sbx_reply, then
 * data_len bytes (a struct stat, a struct statfs, a link target or a
 * directory name), and for an open or chdir that succeeded the
 * descriptor.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_PROTOCOL_H
#define SBX_PROTOCOL_H

#include <stdint.h>

#define SBX_PROTOCOL_VERSION 1
#define SBX_PATH_MAX 4096

enum sbx_op {
    SBX_OPEN = 1,      /* flags = open flags, mode = creation mode */
    SBX_STAT = 2,      /* flags = AT_SYMLINK_NOFOLLOW or 0; data = struct stat */
    SBX_ACCESS = 3,    /* mode = R_OK|W_OK|X_OK or F_OK */
    SBX_READLINK = 4,  /* mode = the caller's buffer size; data = the target */
    SBX_MKDIR = 5,     /* mode = creation mode */
    SBX_UNLINK = 6,    /* flags = AT_REMOVEDIR or 0 */
    SBX_RENAME = 7,    /* flags = renameat2 flags; path2 = the new name */
    SBX_STATFS = 8,    /* data = struct statfs */
    SBX_CHDIR = 9,     /* the reply carries an O_PATH descriptor of the directory */
    SBX_GETCWD = 10,   /* path = "."; mode = the caller's buffer size; data = the directory's name */
};

struct sbx_request {
    uint16_t version;
    uint16_t op;
    int32_t flags;
    uint32_t mode;
    uint32_t path_len;
    uint32_t path2_len;
    int32_t tid;        /* for /proc/thread-self; the broker checks it is the sender's */
    uint8_t dirfd_sent;
    uint8_t dirfd2_sent;
    uint8_t reserved[6];
};

struct sbx_reply {
    int64_t result;     /* >= 0 on success (a byte count for READLINK and GETCWD), else -errno */
    uint32_t data_len;
    uint32_t reserved;
};

#endif
