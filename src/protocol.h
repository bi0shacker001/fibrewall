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
/* The most one SBX_LIST reply carries; a larger read is answered short, as the kernel may. */
#define SBX_LIST_MAX 32768

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
    SBX_LIST = 11,     /* path = "."; the directory's own descriptor is sent; mode = the caller's buffer size;
                          data = linux_dirent64 records read from that descriptor (its position moves) */
    SBX_CHMOD = 12,    /* mode = the new mode (the broker keeps 0777 of it) */
    SBX_UTIMENS = 13,  /* flags = AT_SYMLINK_NOFOLLOW or 0; path2 = two struct timespec (atime, mtime), or
                          empty for "now" */
    /*
     * Sockets (SBX_LOCK_NET_BROKERED). The body ("path") is binary here, never a name: an int, or a socket
     * address. The socket a call is about travels as the first descriptor after the answer socket
     * (dirfd_sent = 1); the broker acts on that same open file description.
     */
    SBX_SOCKET = 14,   /* flags = domain, mode = type (with SOCK_NONBLOCK); body = int protocol; the reply
                          carries the new socket */
    SBX_CONNECT = 15,  /* body = the address. An inet socket is connected by the broker (result 0 or -errno,
                          -EINPROGRESS for a non-blocking one). A Unix path is answered with a new socket the
                          broker connected when it is a system socket the process may have (the caller puts it
                          in place of its own), else -ENOSYS: the caller connects it itself */
    SBX_BIND = 16,     /* body = the address */
    SBX_LISTEN = 17,   /* body = int backlog */
    SBX_ACCEPT = 18,   /* body = int accept4 flags; the reply carries the connection, data = the peer's
                          address, result = its length */
    SBX_LEARN = 19,    /* SBX_LOCK_LEARN: body = struct sbx_learn_record, a call the filter would have refused;
                          the broker audits it and answers 0, and the handler then makes the call */
    /* SBX_LOCK_PATHOPS. */
    SBX_LINK = 20,     /* path = the existing name, path2 = the new one; flags = AT_SYMLINK_FOLLOW or 0 */
    SBX_SYMLINK = 21,  /* path = the new name, path2 = the target as given (no directory travels for it) */
    SBX_TRUNCATE = 22, /* path2 = the new length, an int64_t */
    /*
     * SBX_LOCK_UNIX. body = the struct sockaddr_un as the process gave it; the process's socket is the first
     * descriptor after the answer socket (dirfd_sent = 1), and its current directory the second
     * (dirfd2_sent = 1) when the path is relative. The broker binds or connects that same socket.
     */
    SBX_UNIX_BIND = 23,
    SBX_UNIX_CONNECT = 24,
    /*
     * SBX_LOCK_EXEC: path = the program to run. Decided as a read of what it resolves to; the reply carries it
     * opened read-only, and the broker answers the sender's /proc/<pid>/exe with it from then on.
     */
    SBX_EXEC = 25,
    /* SBX_LOCK_SIGNAL_TREE: body = struct sbx_signal_request; the broker sends the signal when the target is the tree's */
    SBX_SIGNAL = 26,
    /*
     * SBX_LOCK_WATCH: path = the path to watch, mode = the inotify mask; the process's inotify descriptor is
     * the first descriptor after the answer socket (dirfd_sent = 1), and its current directory the second
     * (dirfd2_sent = 1) when the path is relative. The broker adds the mark on that descriptor; result = the
     * watch descriptor.
     */
    SBX_WATCH = 27,
};

/* The calls SBX_SIGNAL carries. */
enum sbx_signal_kind { SBX_SIG_KILL, SBX_SIG_TGKILL, SBX_SIG_TKILL, SBX_SIG_QUEUEINFO, SBX_SIG_TGQUEUEINFO };

/* A signal for the broker to send: kill(tgid), tgkill(tgid, tid), tkill(tid), and the sigqueueinfo pair with info. */
struct sbx_signal_request {
    int32_t kind;
    int32_t tgid;
    int32_t tid;
    int32_t signal;
    uint8_t info[128];
};

/* One call a learning lockdown let through: its number, its arguments, and the errno it would have had. */
struct sbx_learn_record {
    int64_t nr;
    int64_t args[6];
    int32_t would;
    int32_t reserved;
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
