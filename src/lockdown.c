/*
 * The confined half of sbx (see include/sbx.h): the seccomp filter and the
 * SIGSYS handler that forwards path system calls to the broker.
 *
 * The filter, after an architecture check (a call made through another
 * architecture's entry, such as x86_64's int 0x80 or x32, is refused):
 *   - traps every call the broker can answer: open, stat, access,
 *     readlink, mkdir, unlink, rename, statfs, chdir, fchdir and getcwd in
 *     all their forms;
 *   - refuses with ENOSYS statx, openat2 and clone3, whose callers fall
 *     back to fstatat, openat and clone;
 *   - refuses with EACCES every other call that names a path or reaches
 *     past the process: truncate, link, symlink, mknod, chmod, chown,
 *     utimes on a path, inotify and fanotify marks, file handles, path
 *     xattrs, execve, socket (but a datagram Unix socket for the system
 *     log when asked), bind, connect, ptrace, process_vm_readv/writev,
 *     process_madvise, bpf, perf_event_open and io_uring;
 *   - refuses with EPERM namespaces and mounts (clone with a CLONE_NEW*
 *     flag, unshare, setns, mount and the new mount API, pivot_root,
 *     chroot), the kernel keyring, kcmp, pidfd_open, pidfd_getfd,
 *     pidfd_send_signal, tkill, a signal to any process but this one, and
 *     a new SIGSYS handler;
 *   - allows everything else, including every call on a descriptor.
 * It stacks on whatever filter the process already has and can only
 * narrow it.
 *
 * The handler answers some paths itself, from descriptors (local files:
 * own-opened devices and the host's sbx_local_add). In passthrough it
 * sends only the paths under the host's claims to the broker and does the
 * rest itself, with the kernel deciding, as if there were no filter.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
/* Numbers from 424 on are the same on every architecture. */
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#define __NR_move_mount 429
#define __NR_fsopen 430
#define __NR_fsconfig 431
#define __NR_fsmount 432
#define __NR_fspick 433
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

#if defined(__aarch64__)
#define SBX_ARCH AUDIT_ARCH_AARCH64
#define ARG(uc, i) ((long) (uc)->uc_mcontext.regs[i])
#define SET_RESULT(uc, v) ((uc)->uc_mcontext.regs[0] = (unsigned long) (v))
#elif defined(__x86_64__)
#define SBX_ARCH AUDIT_ARCH_X86_64
static const int x86_args[6] = {REG_RDI, REG_RSI, REG_RDX, REG_R10, REG_R8, REG_R9};
#define ARG(uc, i) ((long) (uc)->uc_mcontext.gregs[x86_args[i]])
#define SET_RESULT(uc, v) ((uc)->uc_mcontext.gregs[REG_RAX] = (long) (v))
#endif

/*
 * Everything from here to sbx_lockdown is for the two architectures the
 * handler knows (their system-call numbers and registers). Elsewhere (a
 * 32-bit build of a host that also ships those ABIs) the library builds,
 * and sbx_lockdown and sbx_local_add answer ENOSYS.
 */
#ifdef SBX_ARCH

/* SECCOMP_RET_DATA of our traps, which tells them from anyone else's SIGSYS. */
#define SBX_TRAP_DATA 0x5b0

static int broker = -1;
static int locked;
/* The confined process's current directory: it cannot chdir for real, since it may not open what it enters. */
static int cwd = -1;
static struct sigaction previous;

/*
 * Local files: paths the handler answers itself from a descriptor, with no
 * broker. Two kinds: devices this process opened just before lockdown
 * (sbx_lockdown_options.own_opens), read and written; and files the host
 * hands over under names of its choosing (sbx_local_add), read only.
 * Entries are added from ordinary code, before or after lockdown, under a
 * spin lock; the handler reads them without one, because an entry is
 * complete before the count that publishes it is stored.
 */
#define LOCAL_DEVICE 0x100u
static struct {
    const char *path;
    int fd;
    unsigned mode; /* SBX_READ, or SBX_READ | SBX_WRITE | LOCAL_DEVICE */
} locals[SBX_LOCALS_MAX];
static unsigned local_count;
static char local_lock;

static void lock_locals(void) {
    while (__atomic_test_and_set(&local_lock, __ATOMIC_ACQUIRE)) sched_yield();
}

static void unlock_locals(void) { __atomic_clear(&local_lock, __ATOMIC_RELEASE); }

/* The index of the local file at exactly path, or -1. */
static int local_index(const char *path) {
    if (path == NULL || path[0] != '/') return -1;
    unsigned count = __atomic_load_n(&local_count, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < count; i++) {
        if (strcmp(path, locals[i].path) == 0) return (int) i;
    }
    return -1;
}

static int local_fd(int i) { return __atomic_load_n(&locals[i].fd, __ATOMIC_ACQUIRE); }

/* A duplicate of a local file for an open of exactly its path, or -ENOENT when path is not one. */
static long local_open(const char *path, int flags) {
    int i = local_index(path);
    if (i < 0) return -ENOENT;
    int writing = (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)) != 0;
    if (writing && !(locals[i].mode & SBX_WRITE)) return -EACCES;
    long fd = fcntl(local_fd(i), (flags & O_CLOEXEC) ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
    if (fd < 0) return -errno;
    /* A handed-over file reads from its start (the duplicate shares its offset with every other one). */
    if (!(locals[i].mode & LOCAL_DEVICE)) lseek((int) fd, 0, SEEK_SET);
    return fd;
}

/*
 * stat and access of a local file, answered from its descriptor: the
 * broker's rules need not hold it, and a library that checks for a file
 * before it opens it (libhidl's access of /dev/hwbinder) must see what the
 * open will give. The answer is the file's, even for lstat of a path that
 * is a symlink to it. -ENOENT when path is not one.
 */
static long local_stat(const char *path, struct stat *st) {
    int i = local_index(path);
    if (i < 0) return -ENOENT;
    return syscall(__NR_fstat, local_fd(i), st) == 0 ? 0 : -errno;
}

static long local_access(const char *path, int mode) {
    int i = local_index(path);
    if (i < 0) return -ENOENT;
    if ((mode & W_OK) && !(locals[i].mode & SBX_WRITE)) return -EACCES;
    /* A device is never run. */
    if ((mode & X_OK) && (locals[i].mode & LOCAL_DEVICE)) return -EACCES;
    return 0;
}

/* Adds an entry, or replaces the descriptor of the one at the same path; takes fd. Ordinary code only. */
static int add_local(const char *path, int fd, unsigned mode) {
    if (path == NULL || path[0] != '/' || strnlen(path, SBX_PATH_MAX) == SBX_PATH_MAX || fd < 0) return -EINVAL;
    lock_locals();
    unsigned count = local_count;
    for (unsigned i = 0; i < count; i++) {
        if (strcmp(path, locals[i].path) == 0) {
            int old = __atomic_exchange_n(&locals[i].fd, fd, __ATOMIC_ACQ_REL);
            unlock_locals();
            close(old);
            return 0;
        }
    }
    if (count == SBX_LOCALS_MAX) {
        unlock_locals();
        return -ENOSPC;
    }
    char *copy = strdup(path);
    if (copy == NULL) {
        unlock_locals();
        return -ENOMEM;
    }
    locals[count].path = copy;
    locals[count].fd = fd;
    locals[count].mode = mode;
    __atomic_store_n(&local_count, count + 1, __ATOMIC_RELEASE);
    unlock_locals();
    return 0;
}

int sbx_local_add(const char *path, int fd) {
    int added = add_local(path, fd, SBX_READ);
    if (added != 0 && fd >= 0) close(fd);
    return added;
}

/* Removes the entries from first on and closes their descriptors (a refused lockdown's own-opened devices). */
static void drop_locals_from(unsigned first) {
    lock_locals();
    unsigned count = local_count;
    __atomic_store_n(&local_count, first, __ATOMIC_RELEASE);
    for (unsigned i = first; i < count; i++) {
        close(locals[i].fd);
        free((void *) locals[i].path);
    }
    unlock_locals();
}

/*
 * Passthrough (SBX_LOCK_PASSTHROUGH): the folders the broker answers for;
 * every other path goes to the kernel, through the handler, as the call
 * would have gone without the filter.
 */
static int passthrough;
static char *claims[SBX_CLAIMS_MAX];
static size_t claim_lengths[SBX_CLAIMS_MAX];
static unsigned claim_count;

/*
 * The directory argument of the handler's own calls to the kernel in
 * passthrough. Every path the handler sends there is absolute, and the
 * kernel ignores the directory argument of an absolute path, so this is
 * never a descriptor: it is the one value the filter lets through
 * untrapped. Code that uses it itself reaches only what the kernel would
 * give the process anyway, which is what passthrough means.
 */
#define PASS_DIRFD (-0x5b1)

static int claimed(const char *path) {
    for (unsigned i = 0; i < claim_count; i++) {
        size_t n = claim_lengths[i];
        if (strncmp(path, claims[i], n) == 0 && (path[n] == '/' || path[n] == '\0')) return 1;
    }
    return 0;
}

static void free_claims(void) {
    for (unsigned i = 0; i < claim_count; i++) free(claims[i]);
    claim_count = 0;
    passthrough = 0;
}

static int current_directory(void) { return __atomic_load_n(&cwd, __ATOMIC_ACQUIRE); }

static long forward(uint32_t op, int dirfd, const char *path, int dirfd2, const char *path2,
                    int flags, uint32_t mode, void *out, size_t out_len) {
    if (path == NULL || (op == SBX_RENAME && path2 == NULL)) return -EFAULT;
    size_t length = strnlen(path, SBX_PATH_MAX);
    /* A rename's second name; a utimensat's two times travel in the same place, as bytes. */
    size_t length2 = op == SBX_RENAME ? strnlen(path2, SBX_PATH_MAX)
                   : (op == SBX_UTIMENS && path2 != NULL) ? 2 * sizeof(struct timespec) : 0;
    if (length == SBX_PATH_MAX || length2 == SBX_PATH_MAX) return -ENAMETOOLONG;
    if (length == 0 || (op == SBX_RENAME && length2 == 0)) return -ENOENT;

    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = (uint16_t) op;
    request.flags = flags;
    request.mode = mode;
    request.path_len = (uint32_t) length;
    request.path2_len = (uint32_t) length2;
    request.tid = (int32_t) syscall(__NR_gettid);

    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, answer) != 0) return -errno;
    int fds[3];
    int count = 0;
    fds[count++] = answer[1];
    if (path[0] != '/') {
        fds[count++] = dirfd == AT_FDCWD ? current_directory() : dirfd;
        request.dirfd_sent = 1;
    }
    if (op == SBX_RENAME && path2[0] != '/') {
        fds[count++] = dirfd2 == AT_FDCWD ? current_directory() : dirfd2;
        request.dirfd2_sent = 1;
    }

    struct iovec parts[3] = {
        {&request, sizeof(request)},
        {(void *) path, length},
        {(void *) path2, length2},
    };
    union {
        char buffer[CMSG_SPACE(sizeof(int) * 3)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = parts;
    message.msg_iovlen = length2 ? 3 : 2;
    message.msg_control = control.buffer;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * count);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int) * count);
    memcpy(CMSG_DATA(header), fds, sizeof(int) * count);

    ssize_t sent;
    do sent = sendmsg(broker, &message, MSG_NOSIGNAL);
    while (sent < 0 && errno == EINTR);
    int send_error = errno;
    close(answer[1]);
    if (sent < 0) {
        close(answer[0]);
        /* EBADF: a bad directory descriptor of the caller's; anything else, the broker is gone. */
        return send_error == EBADF ? -EBADF : -EIO;
    }

    struct sbx_reply reply;
    memset(&reply, 0, sizeof(reply));
    struct iovec back[2] = {{&reply, sizeof(reply)}, {out, out_len}};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } back_control;
    memset(&back_control, 0, sizeof(back_control));
    struct msghdr answer_message;
    memset(&answer_message, 0, sizeof(answer_message));
    answer_message.msg_iov = back;
    answer_message.msg_iovlen = out_len ? 2 : 1;
    answer_message.msg_control = back_control.buffer;
    answer_message.msg_controllen = sizeof(back_control.buffer);
    int keep_open = op == SBX_OPEN && !(flags & O_CLOEXEC);
    ssize_t received;
    do received = recvmsg(answer[0], &answer_message, keep_open ? 0 : MSG_CMSG_CLOEXEC);
    while (received < 0 && errno == EINTR);
    close(answer[0]);
    if (received < (ssize_t) sizeof(reply)) return -EIO;

    int passed = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&answer_message); c; c = CMSG_NXTHDR(&answer_message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&passed, CMSG_DATA(c), sizeof(int));
        }
    }
    if ((op == SBX_OPEN || op == SBX_CHDIR) && reply.result >= 0) {
        if (passed < 0) return -EIO;
        return passed;
    }
    if (passed >= 0) close(passed);
    return (long) reply.result;
}

/* Makes directory the current one, taking it; closes the one it replaces. */
static void set_directory(int directory) {
    int old = __atomic_exchange_n(&cwd, directory, __ATOMIC_ACQ_REL);
    if (old >= 0) close(old);
}

static long change_directory_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return -errno;
    set_directory(copy);
    return 0;
}

/* "/proc/self/fd/<fd>" into name (at least 32 bytes), with no stdio in the handler. */
static void fd_link(char *name, int fd) {
    static const char prefix[] = "/proc/self/fd/";
    memcpy(name, prefix, sizeof(prefix) - 1);
    char digits[12];
    int n = 0;
    unsigned value = fd < 0 ? 0u : (unsigned) fd;
    do digits[n++] = (char) ('0' + value % 10);
    while ((value /= 10) != 0);
    size_t at = sizeof(prefix) - 1;
    while (n > 0) name[at++] = digits[--n];
    name[at] = '\0';
}

static long kernel(long result) { return result < 0 ? -errno : result; }

#define ROUTE_BROKER 0
#define ROUTE_KERNEL 1

/*
 * Where a path call goes. Without passthrough, always to the broker. In
 * passthrough, an absolute path under a claim goes to the broker and any
 * other to the kernel as it is. A relative path is judged by where it
 * lands, its directory's name (from /proc/self/fd) joined to it: under a
 * claim it goes to the broker with its directory; otherwise to the kernel
 * as /proc/self/fd/<directory>/<path>, which the kernel walks from that
 * same directory. *where is set for ROUTE_KERNEL, in buffer
 * (SBX_PATH_MAX bytes) when it had to be built.
 */
static long route(int dirfd, const char *path, char *buffer, const char **where) {
    if (!passthrough) return ROUTE_BROKER;
    if (path == NULL) return -EFAULT;
    if (path[0] == '\0') return -ENOENT;
    if (path[0] == '/') {
        if (claimed(path)) return ROUTE_BROKER;
        *where = path;
        return ROUTE_KERNEL;
    }
    char link[32];
    fd_link(link, dirfd == AT_FDCWD ? current_directory() : dirfd);
    size_t length = strnlen(path, SBX_PATH_MAX);
    long n = syscall(__NR_readlinkat, PASS_DIRFD, link, buffer, SBX_PATH_MAX - 1);
    if (n < 0) return errno == ENOENT ? -EBADF : -errno;
    if (buffer[0] == '/' && (size_t) n + 1 + length < SBX_PATH_MAX) {
        buffer[n] = '/';
        memcpy(buffer + n + 1, path, length);
        buffer[n + 1 + length] = '\0';
        if (claimed(buffer)) return ROUTE_BROKER;
    }
    size_t prefix = strlen(link);
    if (prefix + 1 + length >= SBX_PATH_MAX) return -ENAMETOOLONG;
    memcpy(buffer, link, prefix);
    buffer[prefix] = '/';
    memcpy(buffer + prefix + 1, path, length);
    buffer[prefix + 1 + length] = '\0';
    *where = buffer;
    return ROUTE_KERNEL;
}

static long open_path(int dirfd, const char *path, int flags, uint32_t mode, char *buffer) {
    long mine = local_open(path, flags);
    if (mine != -ENOENT) return mine;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_openat, PASS_DIRFD, where, flags, mode));
    return forward(SBX_OPEN, dirfd, path, 0, NULL, flags, mode, NULL, 0);
}

static long stat_path(int dirfd, const char *path, struct stat *st, int flags, char *buffer) {
    long mine = local_stat(path, st);
    if (mine != -ENOENT) return mine;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_newfstatat, PASS_DIRFD, where, st, flags));
    return forward(SBX_STAT, dirfd, path, 0, NULL, flags & AT_SYMLINK_NOFOLLOW, 0, st, sizeof(struct stat));
}

static long access_path(int dirfd, const char *path, int mode, int flags, char *buffer) {
    long mine = local_access(path, mode);
    if (mine != -ENOENT) return mine;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) {
        if (flags == 0) return kernel(syscall(__NR_faccessat, PASS_DIRFD, where, mode));
        return kernel(syscall(__NR_faccessat2, PASS_DIRFD, where, mode, flags));
    }
    return forward(SBX_ACCESS, dirfd, path, 0, NULL, 0, (uint32_t) mode, NULL, 0);
}

static long readlink_path(int dirfd, const char *path, char *out, long size, char *buffer) {
    if (size <= 0) return -EINVAL;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_readlinkat, PASS_DIRFD, where, out, size));
    return forward(SBX_READLINK, dirfd, path, 0, NULL, 0, (uint32_t) size, out, (size_t) size);
}

static long mkdir_path(int dirfd, const char *path, uint32_t mode, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_mkdirat, PASS_DIRFD, where, mode));
    return forward(SBX_MKDIR, dirfd, path, 0, NULL, 0, mode, NULL, 0);
}

static long unlink_path(int dirfd, const char *path, int flags, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_unlinkat, PASS_DIRFD, where, flags));
    return forward(SBX_UNLINK, dirfd, path, 0, NULL, flags & AT_REMOVEDIR, 0, NULL, 0);
}

/* A rename goes to the kernel only when neither name is the broker's. */
static long rename_path(int dirfd, const char *path, int dirfd2, const char *path2, int flags, char *buffer) {
    const char *where = NULL, *where2 = NULL;
    char buffer2[SBX_PATH_MAX];
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    long to2 = route(dirfd2, path2, buffer2, &where2);
    if (to2 < 0) return to2;
    if (to == ROUTE_KERNEL && to2 == ROUTE_KERNEL) {
        return kernel(syscall(__NR_renameat2, PASS_DIRFD, where, PASS_DIRFD, where2, flags));
    }
    return forward(SBX_RENAME, dirfd, path, dirfd2, path2, flags, 0, NULL, 0);
}

static long statfs_path(const char *path, struct statfs *out, char *buffer) {
    const char *where = NULL;
    long to = route(AT_FDCWD, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_BROKER) return forward(SBX_STATFS, AT_FDCWD, path, 0, NULL, 0, 0, out, sizeof(struct statfs));
    long fd = syscall(__NR_openat, PASS_DIRFD, where, O_PATH | O_CLOEXEC, 0);
    if (fd < 0) return -errno;
    long result = kernel(syscall(__NR_fstatfs, (int) fd, out));
    close((int) fd);
    return result;
}

static long change_directory(const char *path, char *buffer) {
    const char *where = NULL;
    long to = route(AT_FDCWD, path, buffer, &where);
    if (to < 0) return to;
    long fd;
    if (to == ROUTE_KERNEL) fd = kernel(syscall(__NR_openat, PASS_DIRFD, where, O_PATH | O_DIRECTORY | O_CLOEXEC, 0));
    else fd = forward(SBX_CHDIR, AT_FDCWD, path, 0, NULL, 0, 0, NULL, 0);
    if (fd < 0) return fd;
    set_directory((int) fd);
    return 0;
}

static long get_directory(char *out, size_t size) {
    if (out == NULL || size == 0) return -EINVAL;
    if (!passthrough) {
        /* The broker counts the terminating NUL, as the kernel does. */
        return forward(SBX_GETCWD, AT_FDCWD, ".", 0, NULL, 0, (uint32_t) size, out, size);
    }
    char link[32];
    fd_link(link, current_directory());
    long n = syscall(__NR_readlinkat, PASS_DIRFD, link, out, size);
    if (n < 0) return -errno;
    if ((size_t) n >= size) return -ERANGE;
    out[n] = '\0';
    return n + 1;
}

static long chmod_path(int dirfd, const char *path, uint32_t mode, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_fchmodat, PASS_DIRFD, where, mode));
    return forward(SBX_CHMOD, dirfd, path, 0, NULL, 0, mode, NULL, 0);
}

static long utimens_path(int dirfd, const char *path, const struct timespec *times, int flags, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return kernel(syscall(__NR_utimensat, PASS_DIRFD, where, times, flags));
    return forward(SBX_UTIMENS, dirfd, path, 0, (const char *) times, flags & AT_SYMLINK_NOFOLLOW, 0, NULL, 0);
}

/*
 * getdents64, which traps in passthrough. The handler lists the folder
 * itself first (its own call carries LIST_MARK in the upper half of the
 * count, which the kernel ignores and the filter lets through); a folder
 * the kernel refuses to list (an Android isolated process may not read a
 * folder its app opened for it) goes to the broker with its descriptor,
 * which lists it from the same open file description when it may read it.
 */
#define LIST_MARK 0x5b2u
static long list_directory(int fd, void *out, unsigned count) {
    long n = syscall(__NR_getdents64, fd, out, (unsigned long) count | ((unsigned long) LIST_MARK << 32));
    if (n >= 0 || errno != EACCES) return kernel(n);
    size_t asked = count < SBX_LIST_MAX ? count : SBX_LIST_MAX;
    return forward(SBX_LIST, fd, ".", 0, NULL, 0, (uint32_t) asked, out, asked);
}

static long dispatch(long nr, ucontext_t *uc) {
    long a0 = ARG(uc, 0), a1 = ARG(uc, 1), a2 = ARG(uc, 2), a3 = ARG(uc, 3), a4 = ARG(uc, 4);
    char buffer[SBX_PATH_MAX];
    switch (nr) {
    case __NR_openat:
        return open_path((int) a0, (const char *) a1, (int) a2, (uint32_t) a3, buffer);
    case __NR_newfstatat: {
        const char *path = (const char *) a1;
        if ((a3 & AT_EMPTY_PATH) && path != NULL && path[0] == '\0') {
            return syscall(__NR_fstat, (int) a0, (void *) a2) == 0 ? 0 : -errno;
        }
        return stat_path((int) a0, path, (struct stat *) a2, (int) a3, buffer);
    }
    case __NR_faccessat:
        return access_path((int) a0, (const char *) a1, (int) a2, 0, buffer);
    case __NR_faccessat2:
        return access_path((int) a0, (const char *) a1, (int) a2, (int) a3, buffer);
    case __NR_readlinkat:
        return readlink_path((int) a0, (const char *) a1, (char *) a2, a3, buffer);
    case __NR_mkdirat:
        return mkdir_path((int) a0, (const char *) a1, (uint32_t) a2, buffer);
    case __NR_unlinkat:
        return unlink_path((int) a0, (const char *) a1, (int) a2, buffer);
#ifdef __NR_renameat
    case __NR_renameat:
        return rename_path((int) a0, (const char *) a1, (int) a2, (const char *) a3, 0, buffer);
#endif
    case __NR_renameat2:
        return rename_path((int) a0, (const char *) a1, (int) a2, (const char *) a3, (int) a4, buffer);
    case __NR_statfs:
        return statfs_path((const char *) a0, (struct statfs *) a1, buffer);
    case __NR_chdir:
        return change_directory((const char *) a0, buffer);
    case __NR_fchdir:
        return change_directory_fd((int) a0);
    case __NR_getcwd:
        return get_directory((char *) a0, (size_t) a1);
    case __NR_fchmodat:
        return chmod_path((int) a0, (const char *) a1, (uint32_t) a2, buffer);
    case __NR_utimensat:
        /* Only a call with a path traps; utimensat(fd, NULL, ...) is futimens, on a descriptor. */
        return utimens_path((int) a0, (const char *) a1, (const struct timespec *) a2, (int) a3, buffer);
    case __NR_getdents64:
        return list_directory((int) a0, (void *) a1, (unsigned) a2);
#ifdef __NR_open
    case __NR_open:
        return open_path(AT_FDCWD, (const char *) a0, (int) a1, (uint32_t) a2, buffer);
    case __NR_creat:
        return open_path(AT_FDCWD, (const char *) a0, O_CREAT | O_WRONLY | O_TRUNC, (uint32_t) a1, buffer);
    case __NR_stat:
        return stat_path(AT_FDCWD, (const char *) a0, (struct stat *) a1, 0, buffer);
    case __NR_lstat:
        return stat_path(AT_FDCWD, (const char *) a0, (struct stat *) a1, AT_SYMLINK_NOFOLLOW, buffer);
    case __NR_access:
        return access_path(AT_FDCWD, (const char *) a0, (int) a1, 0, buffer);
    case __NR_readlink:
        return readlink_path(AT_FDCWD, (const char *) a0, (char *) a1, a2, buffer);
    case __NR_mkdir:
        return mkdir_path(AT_FDCWD, (const char *) a0, (uint32_t) a1, buffer);
    case __NR_unlink:
        return unlink_path(AT_FDCWD, (const char *) a0, 0, buffer);
    case __NR_rmdir:
        return unlink_path(AT_FDCWD, (const char *) a0, AT_REMOVEDIR, buffer);
    case __NR_rename:
        return rename_path(AT_FDCWD, (const char *) a0, AT_FDCWD, (const char *) a1, 0, buffer);
    case __NR_chmod:
        return chmod_path(AT_FDCWD, (const char *) a0, (uint32_t) a1, buffer);
#endif
    default:
        return -ENOSYS;
    }
}

static void on_sigsys(int signal_number, siginfo_t *info, void *context) {
    if (info->si_code != SYS_SECCOMP || info->si_errno != SBX_TRAP_DATA) {
        /* Not ours (the platform's own filter traps too): hand it on as if we were not here. */
        if ((previous.sa_flags & SA_SIGINFO) && previous.sa_sigaction != NULL) {
            previous.sa_sigaction(signal_number, info, context);
        } else if (previous.sa_handler != SIG_DFL && previous.sa_handler != SIG_IGN) {
            previous.sa_handler(signal_number);
        } else {
            /* The default action, which a new handler for SIGSYS may no longer be installed to take. */
            static const char message[] = "sbx: a system call was refused by another seccomp filter\n";
            ssize_t ignored = write(2, message, sizeof(message) - 1);
            (void) ignored;
            syscall(__NR_exit_group, 128 + SIGSYS);
        }
        return;
    }
    int saved_errno = errno;
    ucontext_t *uc = (ucontext_t *) context;
    SET_RESULT(uc, dispatch(info->si_syscall, uc));
    errno = saved_errno;
}

#define FILTER_MAX 512
static struct sock_filter filter[FILTER_MAX];
static unsigned short filter_length;

#define ARG_LO(i) (offsetof(struct seccomp_data, args[i]))
#define ARG_HI(i) (offsetof(struct seccomp_data, args[i]) + 4)

static void emit(struct sock_filter instruction) {
    if (filter_length < FILTER_MAX) filter[filter_length] = instruction;
    filter_length++;
}

static void load(unsigned offset) { emit((struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset)); }
static void ret(unsigned action) { emit((struct sock_filter) BPF_STMT(BPF_RET | BPF_K, action)); }
static void jeq(unsigned value, unsigned char jt, unsigned char jf) {
    emit((struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, jf));
}

/* One rule: if the call is nr, return action. The accumulator holds nr throughout. */
static void rule(unsigned nr, unsigned action) {
    jeq(nr, 0, 1);
    ret(action);
}

#define TRAP (SECCOMP_RET_TRAP | SBX_TRAP_DATA)
#define REFUSE (SECCOMP_RET_ERRNO | EACCES)
#define DENY (SECCOMP_RET_ERRNO | EPERM)
#define NOSYS (SECCOMP_RET_ERRNO | ENOSYS)
#define ALLOW SECCOMP_RET_ALLOW

/*
 * Blocks that test arguments. Each starts with "if the call is not nr,
 * skip the block", and every path through a block returns, so the
 * accumulator still holds nr for the rules after it.
 */

/* nr is allowed only when its first argument is this process. */
static void own_process_only(unsigned nr, pid_t pid) {
    jeq(nr, 0, 6);
    load(ARG_LO(0));
    jeq((unsigned) pid, 0, 3);
    load(ARG_HI(0));
    jeq(0, 0, 1);
    ret(ALLOW);
    ret(DENY);
}

/* nr is refused when its argument arg is one of the sealed descriptors (compared as the kernel reads an fd: 32 bits). */
static void sealed_block(unsigned nr, unsigned arg, const int *fds, unsigned count) {
    jeq(nr, 0, (unsigned char) (count + 3));
    load(ARG_LO(arg));
    for (unsigned k = 0; k < count; k++) jeq((unsigned) fds[k], (unsigned char) (count - k), 0);
    ret(ALLOW);
    ret(DENY);
}

/*
 * In passthrough, nr is let through when its directory argument (both of
 * them, for a rename) is PASS_DIRFD: the handler's own calls to the
 * kernel. Any other use of nr traps.
 */
static void passthrough_block(unsigned nr, int two_directories) {
    if (!two_directories) {
        jeq(nr, 0, 4);
        load(ARG_LO(0));
        jeq((unsigned) PASS_DIRFD, 0, 1);
        ret(ALLOW);
        ret(TRAP);
        return;
    }
    jeq(nr, 0, 6);
    load(ARG_LO(0));
    jeq((unsigned) PASS_DIRFD, 0, 3);
    load(ARG_LO(2));
    jeq((unsigned) PASS_DIRFD, 0, 1);
    ret(ALLOW);
    ret(TRAP);
}

static int build_filter(unsigned flags, pid_t pid, const int *sealed, unsigned sealed_count) {
    filter_length = 0;
    load(offsetof(struct seccomp_data, arch));
    jeq(SBX_ARCH, 1, 0);
    ret(REFUSE);
    load(offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    /* x32 calls share the architecture but set this bit. */
    emit((struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1));
    ret(REFUSE);
#endif
    int unbrokered = (flags & SBX_LOCK_UNBROKERED) != 0;
    int pass = (flags & SBX_LOCK_PASSTHROUGH) != 0;
    if (pass) {
        static const unsigned one[] = {
            __NR_openat, __NR_newfstatat, __NR_faccessat, __NR_faccessat2, __NR_readlinkat, __NR_mkdirat, __NR_unlinkat,
            __NR_fchmodat,
        };
        for (size_t i = 0; i < sizeof(one) / sizeof(one[0]); i++) passthrough_block(one[i], 0);
        /* utimensat: futimens (no path) is a descriptor call; with a path, the handler's own calls pass. */
        jeq(__NR_utimensat, 0, 8);
        load(ARG_LO(1));
        jeq(0, 0, 2);
        load(ARG_HI(1));
        jeq(0, 2, 0);
        load(ARG_LO(0));
        jeq((unsigned) PASS_DIRFD, 0, 1);
        ret(ALLOW);
        ret(TRAP);
        /* getdents64 names no path, but an isolated process may be refused a brokered folder's listing (list_directory). */
        jeq(__NR_getdents64, 0, 4);
        load(ARG_HI(2));
        jeq(LIST_MARK, 0, 1);
        ret(ALLOW);
        ret(TRAP);
        passthrough_block(__NR_renameat2, 1);
#ifdef __NR_renameat
        passthrough_block(__NR_renameat, 1);
#endif
    }
    /* Brokered. */
    static const unsigned brokered[] = {
        __NR_openat, __NR_newfstatat, __NR_faccessat, __NR_faccessat2, __NR_readlinkat, __NR_mkdirat,
        __NR_unlinkat, __NR_renameat2, __NR_statfs, __NR_chdir, __NR_fchdir, __NR_getcwd, __NR_fchmodat,
#ifdef __NR_renameat
        __NR_renameat,
#endif
#ifdef __NR_open
        __NR_open, __NR_creat, __NR_stat, __NR_lstat, __NR_access, __NR_readlink, __NR_mkdir, __NR_unlink,
        __NR_rmdir, __NR_rename, __NR_chmod,
#endif
    };
    if (!unbrokered) {
        for (size_t i = 0; i < sizeof(brokered) / sizeof(brokered[0]); i++) rule(brokered[i], TRAP);
        /* Callers fall back to the brokered forms. */
        rule(__NR_statx, NOSYS);
        rule(__NR_openat2, NOSYS);
#ifdef __NR_fchmodat2
        rule(__NR_fchmodat2, NOSYS);
#endif
    }
    if (!unbrokered && !pass) {
        /* utimensat(fd, NULL, ...) is futimens, on a descriptor; with a path it goes to the broker. */
        jeq(__NR_utimensat, 0, 6);
        load(ARG_LO(1));
        jeq(0, 0, 3);
        load(ARG_HI(1));
        jeq(0, 0, 1);
        ret(ALLOW);
        ret(TRAP);
    }
    /* clone3 takes its flags in memory a filter cannot read; callers fall back to clone, whose flags it can. */
    rule(__NR_clone3, NOSYS);
    /* A Unix datagram socket for the system log, or inet sockets, when asked; no other socket. */
    if (flags & SBX_LOCK_LOG_SOCKET) {
        jeq(__NR_socket, 0, 7);
        load(ARG_LO(0));
        jeq(AF_UNIX, 0, 4);
        load(ARG_LO(1));
        emit((struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf));
        jeq(SOCK_DGRAM, 0, 1);
        ret(ALLOW);
        ret(REFUSE);
    } else if (flags & SBX_LOCK_INET) {
        jeq(__NR_socket, 0, 9);
        load(ARG_LO(0));
        jeq(AF_INET, 1, 0);
        jeq(AF_INET6, 0, 5);
        load(ARG_LO(1));
        emit((struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf));
        jeq(SOCK_STREAM, 1, 0);
        jeq(SOCK_DGRAM, 0, 1);
        ret(ALLOW);
        ret(REFUSE);
    } else {
        rule(__NR_socket, REFUSE);
    }
    /* No new namespaces through clone. */
    jeq(__NR_clone, 0, 4);
    load(ARG_LO(0));
    emit((struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x7e020000u /* CLONE_NEW* */, 0, 1));
    ret(DENY);
    ret(ALLOW);
    if (!unbrokered) {
        /* The SIGSYS handler stays ours. */
        jeq(__NR_rt_sigaction, 0, 4);
        load(ARG_LO(0));
        jeq(SIGSYS, 0, 1);
        ret(DENY);
        ret(ALLOW);
    }
    /* Signals only to this process. */
    own_process_only(__NR_kill, pid);
    own_process_only(__NR_tgkill, pid);
    own_process_only(__NR_rt_sigqueueinfo, pid);
    own_process_only(__NR_rt_tgsigqueueinfo, pid);
    /* Sealed descriptors: kept, but no longer used. */
    if (sealed_count > 0) {
        sealed_block(__NR_ioctl, 0, sealed, sealed_count);
        sealed_block(__NR_fcntl, 0, sealed, sealed_count);
        sealed_block(__NR_dup, 0, sealed, sealed_count);
        sealed_block(__NR_dup3, 0, sealed, sealed_count);
        sealed_block(__NR_mmap, 4, sealed, sealed_count);
#ifdef __NR_dup2
        sealed_block(__NR_dup2, 0, sealed, sealed_count);
#endif
    }
    /* Refused: other paths (the kernel's own checks decide them when there is no broker, and in passthrough). */
    static const unsigned refused_paths[] = {
        __NR_truncate, __NR_linkat, __NR_symlinkat, __NR_mknodat, __NR_fchownat,
        __NR_inotify_add_watch, __NR_fanotify_mark, __NR_name_to_handle_at, __NR_open_by_handle_at,
        __NR_setxattr, __NR_lsetxattr, __NR_getxattr, __NR_lgetxattr, __NR_listxattr, __NR_llistxattr,
        __NR_removexattr, __NR_lremovexattr,
#ifdef __NR_open
        __NR_link, __NR_symlink, __NR_mknod, __NR_chown, __NR_lchown, __NR_utime, __NR_utimes,
        __NR_futimesat, __NR_uselib,
#endif
    };
    if (!unbrokered && !pass) {
        for (size_t i = 0; i < sizeof(refused_paths) / sizeof(refused_paths[0]); i++) rule(refused_paths[i], REFUSE);
    }
    /* Refused: reaching past the process. */
    static const unsigned refused[] = {
        __NR_execve, __NR_execveat, __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
        __NR_process_madvise, __NR_bpf, __NR_perf_event_open, __NR_io_uring_setup, __NR_io_uring_enter,
        __NR_io_uring_register,
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) rule(refused[i], REFUSE);
    /* connect only when a socket can be made (the log's, or inet ones); bind only for inet ones, the only sockets then. */
    if (!(flags & (SBX_LOCK_LOG_SOCKET | SBX_LOCK_INET))) rule(__NR_connect, REFUSE);
    if (!(flags & SBX_LOCK_INET)) rule(__NR_bind, REFUSE);
    static const unsigned denied[] = {
        __NR_unshare, __NR_setns, __NR_mount, __NR_umount2, __NR_pivot_root, __NR_chroot, __NR_open_tree,
        __NR_move_mount, __NR_fsopen, __NR_fsconfig, __NR_fsmount, __NR_fspick, __NR_mount_setattr,
        __NR_keyctl, __NR_add_key, __NR_request_key, __NR_kcmp, __NR_pidfd_open, __NR_pidfd_getfd,
        __NR_pidfd_send_signal, __NR_tkill,
    };
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) rule(denied[i], DENY);
    ret(ALLOW);
    return filter_length <= FILTER_MAX ? 0 : -E2BIG;
}
#else
int sbx_local_add(const char *path, int fd) {
    (void) path;
    if (fd >= 0) close(fd);
    return -ENOSYS;
}
#endif

int sbx_lockdown(int broker_fd, const struct sbx_lockdown_options *options) {
#ifndef SBX_ARCH
    (void) broker_fd;
    (void) options;
    return -ENOSYS;
#else
    if (locked) return -EALREADY;
    struct sbx_lockdown_options none = {.flags = 0};
    if (!options) options = &none;
    int unbrokered = (options->flags & SBX_LOCK_UNBROKERED) != 0;
    int pass = (options->flags & SBX_LOCK_PASSTHROUGH) != 0;
    if (unbrokered && pass) return -EINVAL;
    if ((options->flags & SBX_LOCK_INET) && (options->flags & SBX_LOCK_LOG_SOCKET)) return -EINVAL;
    if (unbrokered) broker_fd = -1;
    else if (broker_fd < 0) return -EBADF;
    if (options->claim_count > SBX_CLAIMS_MAX || (options->claim_count && !options->claims)) return -EINVAL;
    for (unsigned k = 0; k < options->claim_count; k++) {
        const char *claim = options->claims[k];
        if (!claim || claim[0] != '/' || strnlen(claim, SBX_PATH_MAX) == SBX_PATH_MAX) return -EINVAL;
    }
    if (options->sealed_count > SBX_SEALED_MAX || (options->sealed_count && !options->sealed_fds)) return -EINVAL;
    if (options->own_open_count > SBX_OWN_OPENS_MAX || (options->own_open_count && !options->own_opens)) return -EINVAL;
    for (unsigned k = 0; k < options->sealed_count; k++) {
        if (options->sealed_fds[k] < 0 || options->sealed_fds[k] == broker_fd) return -EINVAL;
    }
    int built = build_filter(options->flags, getpid(), options->sealed_fds, options->sealed_count);
    if (built != 0) return built;
    if (unbrokered) {
        /* Nothing is forwarded, so no handler and no current directory to keep. */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -errno;
        struct sock_fprog program = {.len = filter_length, .filter = filter};
        long synced = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
        if (synced != 0) return synced > 0 ? -EBUSY : -errno;
        locked = 1;
        return 0;
    }
    int directory = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return -errno;
    broker = broker_fd;
    cwd = directory;
    unsigned locals_before = __atomic_load_n(&local_count, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < options->own_open_count; i++) {
        const char *path = options->own_opens[i];
        if (!path || path[0] != '/') continue;
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) continue;
        if (add_local(path, fd, SBX_READ | SBX_WRITE | LOCAL_DEVICE) != 0) close(fd);
    }
    int error = 0;
    for (unsigned k = 0; k < options->claim_count && error == 0; k++) {
        char *copy = strdup(options->claims[k]);
        if (copy == NULL) {
            error = -ENOMEM;
            break;
        }
        size_t n = strlen(copy);
        while (n > 0 && copy[n - 1] == '/') copy[--n] = '\0';  /* "/" claims everything: length 0 */
        claims[claim_count] = copy;
        claim_lengths[claim_count] = n;
        claim_count++;
    }
    passthrough = pass;

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = on_sigsys;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (error != 0) {
        /* Nothing installed yet. */
    } else if (sigaction(SIGSYS, &action, &previous) != 0) {
        error = -errno;
    } else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        error = -errno;
    } else {
        struct sock_fprog program = {.len = filter_length, .filter = filter};
        long synced = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
        if (synced == 0) {
            locked = 1;
            return 0;
        }
        /* A positive result names a thread that could not be synchronised: a lockdown that misses threads is none. */
        error = synced > 0 ? -EBUSY : -errno;
    }
    if (error != -ENOMEM) sigaction(SIGSYS, &previous, NULL);
    drop_locals_from(locals_before);
    free_claims();
    close(directory);
    broker = -1;
    cwd = -1;
    return error;
#endif
}
