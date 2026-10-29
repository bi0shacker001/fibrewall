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
 *     log when asked), bind, connect, ptrace, process_vm_writev,
 *     process_vm_readv of any other process,
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
#include "exec_shared.h"
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <unwind.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG 2
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
/* Terminal input injection; the same values on the two arches above. */
#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif
#ifndef TIOCLINUX
#define TIOCLINUX 0x541c
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
#else
/* The owner's rule: 64-bit only, no 32-bit stubs (Droidtop/tracker#646). */
#error "sbx locks down on x86_64 and arm64 only"
#endif


/* SECCOMP_RET_DATA of our traps, which tells them from anyone else's SIGSYS. */
#define SBX_TRAP_DATA 0x5b0
/* SBX_LOCK_LEARN's traps: a call a real lockdown refuses with EACCES, or with EPERM. */
#define SBX_TRAP_LEARN_EACCES 0x5b1
#define SBX_TRAP_LEARN_EPERM 0x5b2

/*
 * The learning trampoline: sbx_learn_call(nr, a0..a5) makes system call
 * nr and answers its raw result (-errno on failure).
 * sbx_learn_call_after is the instruction after its syscall, the address
 * the kernel shows a learning filter (seccomp_data.instruction_pointer), so
 * that filter can let exactly these calls through.
 */
long sbx_learn_call(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
extern const char sbx_learn_call_after[];

/*
 * The trampoline the handler routes its own kernel calls through, and the
 * address just after its syscall instruction, which the filter recognises
 * (trampoline_after). Without SBX_LOCK_EXEC it is sbx_learn_call; with it,
 * the fixed page, the same in every image of the tree, so the filter's check
 * still holds after exec. Declared here so the handler's net and path
 * forwarders, above the trampoline setup below, can reach it.
 */
typedef long (*trampoline_fn)(long, long, long, long, long, long, long);
static trampoline_fn through = sbx_learn_call;
static uintptr_t through_after;  /* 0 until a lockdown sets it */
#if defined(__x86_64__)
__asm__(".text\n"
        ".p2align 4\n"
        ".globl sbx_learn_call\n"
        ".hidden sbx_learn_call\n"
        ".type sbx_learn_call,@function\n"
        "sbx_learn_call:\n"
        "  mov %rdi, %rax\n"
        "  mov %rsi, %rdi\n"
        "  mov %rdx, %rsi\n"
        "  mov %rcx, %rdx\n"
        "  mov %r8, %r10\n"
        "  mov %r9, %r8\n"
        "  mov 8(%rsp), %r9\n"
        "  syscall\n"
        ".globl sbx_learn_call_after\n"
        ".hidden sbx_learn_call_after\n"
        "sbx_learn_call_after:\n"
        "  ret\n"
        ".size sbx_learn_call, .-sbx_learn_call\n");
#elif defined(__aarch64__)
__asm__(".text\n"
        ".p2align 4\n"
        ".globl sbx_learn_call\n"
        ".hidden sbx_learn_call\n"
        ".type sbx_learn_call,%function\n"
        "sbx_learn_call:\n"
        "  mov x8, x0\n"
        "  mov x0, x1\n"
        "  mov x1, x2\n"
        "  mov x2, x3\n"
        "  mov x3, x4\n"
        "  mov x4, x5\n"
        "  mov x5, x6\n"
        "  svc #0\n"
        ".globl sbx_learn_call_after\n"
        ".hidden sbx_learn_call_after\n"
        "sbx_learn_call_after:\n"
        "  ret\n"
        ".size sbx_learn_call, .-sbx_learn_call\n");
#endif

static int broker = -1;
static unsigned lock_flags;  /* the lockdown's flags; exchange() reads SBX_LOCK_FAIL_CLOSED, the filter build the rest */
static int locked;
/* The confined process's current directory: it cannot chdir for real, since it may not open what it enters. */
static int cwd = -1;
static struct sigaction previous;

/*
 * Local files: paths the handler answers itself from a descriptor, with no
 * broker. Two kinds: devices this process opened just before lockdown
 * (sbx_lockdown_options.own_opens), read and written; and files the host
 * hands over under names of its choosing (sbx_local_add), read only, or
 * read and written when the host says so (sbx_local_add_mode).
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

/*
 * Spare opens of each own-opened device, opened with it before lockdown: an
 * open of the device after lockdown takes one whole, so it gets an open file
 * of its own, as an open of the real device would. Binder keeps its state
 * per open file and maps each one once, so two users given duplicates of one
 * descriptor shared it, and the second mmap failed with EBUSY: the Adreno
 * driver's own copy of libhidl, starting after the lockdown, aborted the
 * process with "Mmapping /dev/hwbinder failed: Device or resource busy"
 * (Droidtop/tracker#550, Retroid Pocket 5, 2026-10-24). Once a device's
 * spares are gone, an open gets a duplicate, as before. Filled before the
 * filter goes on and only claimed after, so the handler needs no lock.
 */
#define OWN_OPEN_SPARES 3
static struct {
    const char *path;  /* the device's entry in locals[] */
    int fd;
    int taken;
} spares[SBX_OWN_OPENS_MAX * OWN_OPEN_SPARES];
static unsigned spare_count;

/* A spare of the device at path, claimed, with close-on-exec as flags ask; -1 when none is left. */
static int take_spare(const char *path, int flags) {
    for (unsigned k = 0; k < spare_count; k++) {
        if (strcmp(spares[k].path, path) != 0) continue;
        int free_slot = 0;
        if (!__atomic_compare_exchange_n(&spares[k].taken, &free_slot, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) continue;
        int fd = spares[k].fd;
        if (!(flags & O_CLOEXEC)) fcntl(fd, F_SETFD, 0);
        return fd;
    }
    return -1;
}

/* A duplicate of a local file for an open of exactly its path, or -ENOENT when path is not one. */
static long local_open(const char *path, int flags) {
    int i = local_index(path);
    if (i < 0) return -ENOENT;
    int writing = (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)) != 0;
    if (writing && !(locals[i].mode & SBX_WRITE)) return -EACCES;
    if (locals[i].mode & LOCAL_DEVICE) {
        int spare = take_spare(locals[i].path, flags);
        if (spare >= 0) return spare;
    }
    long fd = fcntl(local_fd(i), (flags & O_CLOEXEC) ? F_DUPFD_CLOEXEC : F_DUPFD, 0);
    if (fd < 0) return -errno;
    /* A handed-over file reads from its start (the duplicate shares its offset with every other one). */
    if (!(locals[i].mode & LOCAL_DEVICE)) lseek((int) fd, 0, SEEK_SET);
    /* The one open flag a shared description can still honour for a writable file: it is the same file. */
    if ((flags & O_TRUNC) && (locals[i].mode & SBX_WRITE) && !(locals[i].mode & LOCAL_DEVICE) &&
        syscall(__NR_ftruncate, (int) fd, 0) != 0) {
        long error = -errno;
        close((int) fd);
        return error;
    }
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
            __atomic_store_n(&locals[i].mode, mode, __ATOMIC_RELEASE);
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

int sbx_local_add_mode(const char *path, int fd, unsigned mode) {
    if (mode != SBX_READ && mode != (SBX_READ | SBX_WRITE)) {
        if (fd >= 0) close(fd);
        return -EINVAL;
    }
    int added = add_local(path, fd, mode);
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
 * never a descriptor. It is a sentinel, not a key: the filter no longer
 * trusts an argument value to tell the handler's calls apart from a
 * worker's -- those are bound to the handler's gateway address instead
 * (allow_from_gateway, review A-06) -- so a worker that issues the same
 * call with this value still traps to the broker and reaches only what
 * passthrough would allow it anyway.
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

/*
 * One request and its reply. extra are the descriptors after the answer
 * socket (the directories, or the socket a network call is about); body
 * and body2 are the request's bytes. The reply's data goes to out, and a
 * descriptor it carries to *passed (else -1), received close-on-exec
 * unless keep_open. Returns the reply's result, or -EIO when the broker is
 * gone (-EBADF for a bad descriptor of the caller's).
 */
/*
 * A broker that has gone, or answered with a short or malformed reply, is a
 * failure the caller cannot recover from. With SBX_LOCK_FAIL_CLOSED the whole
 * process ends, so no descendant outlives the authority confining it (review
 * A-21); otherwise the call answers EIO as before and the process runs on. A
 * caller's own bad descriptor is not a broker failure, so it never comes
 * here. Async-signal-safe: it runs in the SIGSYS handler.
 */
#define SBX_FAIL_CLOSED_STATUS 120
static long broker_failure(void) {
    if (lock_flags & SBX_LOCK_FAIL_CLOSED) syscall(__NR_exit_group, SBX_FAIL_CLOSED_STATUS);
    return -EIO;
}

static long exchange(struct sbx_request *request, const int *extra, int extra_count, const void *body, size_t body_len,
                     const void *body2, size_t body2_len, void *out, size_t out_len, int keep_open, int *passed) {
    *passed = -1;
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, answer) != 0) return -errno;
    int fds[3];
    int count = 0;
    fds[count++] = answer[1];
    for (int i = 0; i < extra_count && count < 3; i++) fds[count++] = extra[i];

    struct iovec parts[3] = {
        {request, sizeof(*request)},
        {(void *) body, body_len},
        {(void *) body2, body2_len},
    };
    union {
        char buffer[CMSG_SPACE(sizeof(int) * 3)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = parts;
    message.msg_iovlen = body2_len ? 3 : 2;
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
        return send_error == EBADF ? -EBADF : broker_failure();
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
    ssize_t received;
    do received = recvmsg(answer[0], &answer_message, keep_open ? 0 : MSG_CMSG_CLOEXEC);
    while (received < 0 && errno == EINTR);
    close(answer[0]);
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&answer_message); c; c = CMSG_NXTHDR(&answer_message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(passed, CMSG_DATA(c), sizeof(int));
        }
    }
    if (received < (ssize_t) sizeof(reply) || reply.data_len > out_len) {
        /* Too short to be a reply, or claiming more data than the buffer: a broker not speaking the protocol. */
        if (*passed >= 0) close(*passed);
        *passed = -1;
        return broker_failure();
    }
    return (long) reply.result;
}

static long forward(uint32_t op, int dirfd, const char *path, int dirfd2, const char *path2,
                    int flags, uint32_t mode, void *out, size_t out_len) {
    /* A rename's or link's second name, or a symlink's target; a utimensat's times or a truncate's length as bytes. */
    int named2 = op == SBX_RENAME || op == SBX_LINK || op == SBX_SYMLINK;
    if (path == NULL || (named2 && path2 == NULL)) return -EFAULT;
    size_t length = strnlen(path, SBX_PATH_MAX);
    size_t length2 = named2 ? strnlen(path2, SBX_PATH_MAX)
                   : (op == SBX_UTIMENS && path2 != NULL) ? 2 * sizeof(struct timespec)
                   : op == SBX_TRUNCATE ? sizeof(int64_t) : 0;
    if (length == SBX_PATH_MAX || length2 == SBX_PATH_MAX) return -ENAMETOOLONG;
    if (length == 0 || (named2 && length2 == 0)) return -ENOENT;

    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = (uint16_t) op;
    request.flags = flags;
    request.mode = mode;
    request.path_len = (uint32_t) length;
    request.path2_len = (uint32_t) length2;
    request.tid = (int32_t) syscall(__NR_gettid);

    int extra[2];
    int count = 0;
    if (path[0] != '/') {
        extra[count++] = dirfd == AT_FDCWD ? current_directory() : dirfd;
        request.dirfd_sent = 1;
    }
    if ((op == SBX_RENAME || op == SBX_LINK) && path2[0] != '/') {
        extra[count++] = dirfd2 == AT_FDCWD ? current_directory() : dirfd2;
        request.dirfd2_sent = 1;
    }
    int passed;
    long result = exchange(&request, extra, count, path, length, path2, length2, out, out_len,
                           op == SBX_OPEN && !(flags & O_CLOEXEC), &passed);
    if ((op == SBX_OPEN || op == SBX_CHDIR || op == SBX_EXEC) && result >= 0) {
        if (passed < 0) return -EIO;
        return passed;
    }
    if (passed >= 0) close(passed);
    return result;
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
    long n = through(__NR_readlinkat, PASS_DIRFD, (long) (uintptr_t) link, (long) (uintptr_t) buffer,
                     SBX_PATH_MAX - 1, 0, 0);
    if (n < 0) return n == -ENOENT ? -EBADF : n;
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
    if (to == ROUTE_KERNEL) return through(__NR_openat, PASS_DIRFD, (long) (uintptr_t) where, flags, mode, 0, 0);
    return forward(SBX_OPEN, dirfd, path, 0, NULL, flags, mode, NULL, 0);
}

static long stat_path(int dirfd, const char *path, struct stat *st, int flags, char *buffer) {
    long mine = local_stat(path, st);
    if (mine != -ENOENT) return mine;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_newfstatat, PASS_DIRFD, (long) (uintptr_t) where, (long) (uintptr_t) st, flags, 0, 0);
    return forward(SBX_STAT, dirfd, path, 0, NULL, flags & AT_SYMLINK_NOFOLLOW, 0, st, sizeof(struct stat));
}

static long access_path(int dirfd, const char *path, int mode, int flags, char *buffer) {
    long mine = local_access(path, mode);
    if (mine != -ENOENT) return mine;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) {
        if (flags == 0) return through(__NR_faccessat, PASS_DIRFD, (long) (uintptr_t) where, mode, 0, 0, 0);
        return through(__NR_faccessat2, PASS_DIRFD, (long) (uintptr_t) where, mode, flags, 0, 0);
    }
    return forward(SBX_ACCESS, dirfd, path, 0, NULL, 0, (uint32_t) mode, NULL, 0);
}

static long readlink_path(int dirfd, const char *path, char *out, long size, char *buffer) {
    if (size <= 0) return -EINVAL;
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_readlinkat, PASS_DIRFD, (long) (uintptr_t) where, (long) (uintptr_t) out, size, 0, 0);
    return forward(SBX_READLINK, dirfd, path, 0, NULL, 0, (uint32_t) size, out, (size_t) size);
}

static long mkdir_path(int dirfd, const char *path, uint32_t mode, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_mkdirat, PASS_DIRFD, (long) (uintptr_t) where, mode, 0, 0, 0);
    return forward(SBX_MKDIR, dirfd, path, 0, NULL, 0, mode, NULL, 0);
}

static long unlink_path(int dirfd, const char *path, int flags, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_unlinkat, PASS_DIRFD, (long) (uintptr_t) where, flags, 0, 0, 0);
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
        return through(__NR_renameat2, PASS_DIRFD, (long) (uintptr_t) where, PASS_DIRFD, (long) (uintptr_t) where2, flags, 0);
    }
    return forward(SBX_RENAME, dirfd, path, dirfd2, path2, flags, 0, NULL, 0);
}

/* SBX_LOCK_PATHOPS: the broker makes these; without it the filter refuses them before they get here. */
static long link_path(int dirfd, const char *path, int dirfd2, const char *path2, int flags) {
    if (flags & ~AT_SYMLINK_FOLLOW) return -EINVAL;
    return forward(SBX_LINK, dirfd, path, dirfd2, path2, flags, 0, NULL, 0);
}

static long symlink_path(const char *target, int dirfd, const char *path) {
    return forward(SBX_SYMLINK, dirfd, path, AT_FDCWD, target, 0, 0, NULL, 0);
}

static long truncate_path(const char *path, long length) {
    if (length < 0) return -EINVAL;
    int64_t wanted = length;
    return forward(SBX_TRUNCATE, AT_FDCWD, path, 0, (const char *) &wanted, 0, 0, NULL, 0);
}

static long statfs_path(const char *path, struct statfs *out, char *buffer) {
    const char *where = NULL;
    long to = route(AT_FDCWD, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_BROKER) return forward(SBX_STATFS, AT_FDCWD, path, 0, NULL, 0, 0, out, sizeof(struct statfs));
    long fd = through(__NR_openat, PASS_DIRFD, (long) (uintptr_t) where, O_PATH | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return fd;
    long result = kernel(syscall(__NR_fstatfs, (int) fd, out));
    close((int) fd);
    return result;
}

static long change_directory(const char *path, char *buffer) {
    const char *where = NULL;
    long to = route(AT_FDCWD, path, buffer, &where);
    if (to < 0) return to;
    long fd;
    if (to == ROUTE_KERNEL) fd = through(__NR_openat, PASS_DIRFD, (long) (uintptr_t) where, O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
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
    long n = through(__NR_readlinkat, PASS_DIRFD, (long) (uintptr_t) link, (long) (uintptr_t) out, (long) size, 0, 0);
    if (n < 0) return n;
    if ((size_t) n >= size) return -ERANGE;
    out[n] = '\0';
    return n + 1;
}

static long chmod_path(int dirfd, const char *path, uint32_t mode, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_fchmodat, PASS_DIRFD, (long) (uintptr_t) where, mode, 0, 0, 0);
    return forward(SBX_CHMOD, dirfd, path, 0, NULL, 0, mode, NULL, 0);
}

static long utimens_path(int dirfd, const char *path, const struct timespec *times, int flags, char *buffer) {
    const char *where = NULL;
    long to = route(dirfd, path, buffer, &where);
    if (to < 0) return to;
    if (to == ROUTE_KERNEL) return through(__NR_utimensat, PASS_DIRFD, (long) (uintptr_t) where, (long) (uintptr_t) times, flags, 0, 0);
    return forward(SBX_UTIMENS, dirfd, path, 0, (const char *) times, flags & AT_SYMLINK_NOFOLLOW, 0, NULL, 0);
}

/*
 * getdents64, which traps in passthrough. The handler lists the folder
 * itself first (its own call goes through the gateway, which the filter
 * recognises by its address); a folder the kernel refuses to list (an
 * Android isolated process may not read a folder its app opened for it)
 * goes to the broker with its descriptor, which lists it from the same open
 * file description when it may read it.
 */
static long list_directory(int fd, void *out, unsigned count) {
    /* Through the gateway: the filter allows it by its address, not a forgeable marker (review A-06). */
    long n = through(__NR_getdents64, fd, (long) (uintptr_t) out, (long) count, 0, 0, 0);
    if (n != -EACCES) return n;
    size_t asked = count < SBX_LIST_MAX ? count : SBX_LIST_MAX;
    return forward(SBX_LIST, fd, ".", 0, NULL, 0, (uint32_t) asked, out, asked);
}

/*
 * Sockets, with SBX_LOCK_NET_BROKERED: an inet socket is created, connected,
 * bound, listened on and accepted from by the broker, under its own
 * identity (an Android isolated process may create none and may not listen
 * or accept on one it was given). The handler's own connect and accept of a
 * Unix socket go through the gateway (trampoline_after), which the filter
 * recognises by its address, so a worker cannot forge them.
 */

static int socket_domain(int fd) {
    int domain = 0;
    socklen_t length = sizeof(domain);
    return getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 ? domain : -errno;
}

static long net_forward(uint32_t op, int subject, const void *body, size_t body_len, int flags, uint32_t mode,
                        void *out, size_t out_len, int keep_open, int *passed) {
    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = (uint16_t) op;
    request.flags = flags;
    request.mode = mode;
    request.path_len = (uint32_t) body_len;
    request.tid = (int32_t) syscall(__NR_gettid);
    request.dirfd_sent = subject >= 0;
    return exchange(&request, &subject, subject >= 0 ? 1 : 0, body, body_len, NULL, 0, out, out_len, keep_open, passed);
}

static long net_socket(int domain, int type, int protocol) {
    int passed;
    long result = net_forward(SBX_SOCKET, -1, &protocol, sizeof(protocol), domain, (uint32_t) type, NULL, 0,
                              !(type & SOCK_CLOEXEC), &passed);
    if (result < 0) {
        if (passed >= 0) close(passed);
        return result;
    }
    return passed >= 0 ? passed : -EIO;
}

static long net_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (address == NULL) return -EFAULT;
    if ((int) length <= 0 || length > sizeof(struct sockaddr_storage)) return -EINVAL;
    int domain = socket_domain(fd);
    if (domain < 0) return domain;
    if (domain == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *) address;
        int named = length > offsetof(struct sockaddr_un, sun_path) && un->sun_path[0] != '\0';
        if (named) {
            /* A system socket the host named is connected by the broker; the caller's socket becomes that one. */
            int passed;
            long result = net_forward(SBX_CONNECT, fd, address, length, 0, 0, NULL, 0, 1, &passed);
            if (result == 0 && passed >= 0) {
                int close_on_exec = (fcntl(fd, F_GETFD) & FD_CLOEXEC) ? O_CLOEXEC : 0;
                long placed = dup3(passed, fd, close_on_exec) < 0 ? -errno : 0;
                close(passed);
                return placed;
            }
            if (passed >= 0) close(passed);
            if (result != -ENOSYS) return result;
        }
        /* Through the gateway, so the filter allows it by its address, not a forgeable marker (review A-06). */
        return through(__NR_connect, fd, (long) (uintptr_t) address, (long) length, 0, 0, 0);
    }
    int passed;
    long result = net_forward(SBX_CONNECT, fd, address, length, 0, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

static long net_bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (address == NULL) return -EFAULT;
    if ((int) length <= 0 || length > sizeof(struct sockaddr_storage)) return -EINVAL;
    int domain = socket_domain(fd);
    if (domain < 0) return domain;
    if (domain == AF_UNIX) return -EACCES;  /* no names in the file system or the abstract namespace */
    int passed;
    long result = net_forward(SBX_BIND, fd, address, length, 0, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

static long net_listen(int fd, int backlog) {
    int domain = socket_domain(fd);
    if (domain < 0) return domain;
    if (domain == AF_UNIX) return -EACCES;  /* an unbound Unix socket would take an abstract name */
    int passed;
    long result = net_forward(SBX_LISTEN, fd, &backlog, sizeof(backlog), 0, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

static long net_accept(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    int domain = socket_domain(fd);
    if (domain < 0) return domain;
    if (domain != AF_INET && domain != AF_INET6) {
        /* Through the gateway, so the filter allows it by its address, not a forgeable marker (review A-06). */
        return through(__NR_accept4, fd, (long) (uintptr_t) address, (long) (uintptr_t) length, (long) flags, 0, 0);
    }
    struct sockaddr_storage peer;
    int passed;
    long result = net_forward(SBX_ACCEPT, fd, &flags, sizeof(flags), 0, 0, &peer, sizeof(peer), !(flags & SOCK_CLOEXEC), &passed);
    if (result < 0) {
        if (passed >= 0) close(passed);
        return result;
    }
    if (passed < 0) return -EIO;
    if (address != NULL && length != NULL) {
        socklen_t room = *length;
        socklen_t have = (socklen_t) result;
        memcpy(address, &peer, room < have ? room : have);
        *length = have;
    }
    return passed;
}

/*
 * SBX_LOCK_UNIX: bind and connect trap whatever the address, since the
 * filter cannot read it. A Unix one goes to the broker with the socket
 * (and the current directory for a relative path), which decides it and
 * makes the call on that socket; an inet one (SBX_LOCK_INET as well) goes
 * the brokered network's way, under the policy's network grants.
 */
static int unix_mode;

static long unix_call(uint32_t op, int fd, const struct sockaddr *address, socklen_t length) {
    if (address == NULL) return -EFAULT;
    if ((int) length < (int) sizeof(sa_family_t) || length > sizeof(struct sockaddr_storage)) return -EINVAL;
    int domain = socket_domain(fd);
    if (domain < 0) return domain;
    if (domain == AF_INET || domain == AF_INET6) {
        return op == SBX_UNIX_CONNECT ? net_connect(fd, address, length) : net_bind(fd, address, length);
    }
    if (domain != AF_UNIX) return -EAFNOSUPPORT;
    if (address->sa_family != AF_UNIX || length > sizeof(struct sockaddr_un)) return -EINVAL;
    const struct sockaddr_un *un = (const struct sockaddr_un *) address;
    int relative = length > offsetof(struct sockaddr_un, sun_path) && un->sun_path[0] != '/' && un->sun_path[0] != '\0';
    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = (uint16_t) op;
    request.path_len = (uint32_t) length;
    request.tid = (int32_t) syscall(__NR_gettid);
    request.dirfd_sent = 1;
    request.dirfd2_sent = (uint8_t) relative;
    int extra[2] = {fd, current_directory()};
    int passed;
    long result = exchange(&request, extra, relative ? 2 : 1, address, length, NULL, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

/*
 * SBX_LOCK_WATCH: inotify_add_watch goes to the broker with the inotify
 * descriptor (and the current directory for a relative path); the broker
 * decides the path and adds the mark on that same descriptor.
 */
static long watch_call(int fd, const char *path, uint32_t mask) {
    if (path == NULL) return -EFAULT;
    size_t length = strnlen(path, SBX_PATH_MAX);
    if (length == SBX_PATH_MAX) return -ENAMETOOLONG;
    if (length == 0) return -ENOENT;
    int relative = path[0] != '/';
    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = SBX_WATCH;
    request.mode = mask;
    request.path_len = (uint32_t) length;
    request.tid = (int32_t) syscall(__NR_gettid);
    request.dirfd_sent = 1;
    request.dirfd2_sent = (uint8_t) relative;
    int extra[2] = {fd, relative ? current_directory() : -1};
    int passed;
    long result = exchange(&request, extra, relative ? 2 : 1, path, length, NULL, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

/* SIGSYS as a bit of the kernel's 64-bit signal mask. */
#define SIGSYS_BIT (1ULL << (SIGSYS - 1))

/*
 * rt_sigprocmask, made on the interrupted thread's saved mask rather than
 * with the call itself: the kernel restores that mask when the handler
 * returns, so this is the call's effect, with SIGSYS always left open. A
 * trap on a thread that has SIGSYS blocked kills the whole process (the
 * kernel resets the handler to the default to deliver it), so no thread
 * may block it once the filter is on (docs/design.md, "SIGSYS stays
 * open").
 */
static long sigmask_call(ucontext_t *uc, int how, const void *set, void *old, unsigned long size) {
    if (size != sizeof(uint64_t)) return -EINVAL;
    uint64_t current;
    memcpy(&current, &uc->uc_sigmask, sizeof(current));
    uint64_t next = current;
    if (set != NULL) {
        uint64_t asked;
        memcpy(&asked, set, sizeof(asked));
        switch (how) {
        case SIG_BLOCK: next = current | asked; break;
        case SIG_UNBLOCK: next = current & ~asked; break;
        case SIG_SETMASK: next = asked; break;
        default: return -EINVAL;
        }
    }
    if (old != NULL) memcpy(old, &current, sizeof(current));
    next &= ~SIGSYS_BIT;
    memcpy(&uc->uc_sigmask, &next, sizeof(next));
    return 0;
}

/* through, through_after and the trampoline_fn typedef are declared above, by sbx_learn_call. */
SBXE_TRAMPOLINE_ASM
#ifdef __x86_64__
/* rt_sigreturn, for a handler sbx_adopt installs without libc. */
void sbx_restorer(void);
__asm__(".text\n.globl sbx_restorer\n.hidden sbx_restorer\n.type sbx_restorer,@function\n"
        "sbx_restorer:\n  mov $15, %rax\n  syscall\n");
#endif
extern const char sbxe_trampoline_start[], sbxe_trampoline_after[], sbxe_trampoline_end[];

static uintptr_t trampoline_after(void) {
    return through_after ? through_after : (uintptr_t) sbx_learn_call_after;
}

/*
 * The fixed trampoline page: mapped here, or found already mapped by
 * sbx-exec in an image it started. Anything else at that address fails the
 * lockdown.
 */
static int map_trampoline(void) {
    void *want = (void *) SBXE_TRAMPOLINE_ADDRESS, *entry = (void *) SBXE_TRAMPOLINE_ENTRY;
    size_t length = (size_t) (sbxe_trampoline_end - sbxe_trampoline_start);
    void *page = mmap(want, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /* MAP_FIXED_NOREPLACE */,
                      -1, 0);
    if (page == want) {
        memcpy(entry, sbxe_trampoline_start, length);
        if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0) {
            int error = errno;
            munmap(page, 4096);
            return -error;
        }
    } else {
        /* A kernel before 4.17 takes the address as a hint and maps elsewhere when it is taken. */
        if (page != MAP_FAILED) munmap(page, 4096);
        unsigned char resident;
        if (mincore(want, 4096, &resident) != 0) return -ENOMEM;
        if (memcmp(entry, sbxe_trampoline_start, length) != 0) return -EEXIST;
    }
    through = (trampoline_fn) SBXE_TRAMPOLINE_ENTRY;
    through_after = SBXE_TRAMPOLINE_ENTRY + (uintptr_t) (sbxe_trampoline_after - sbxe_trampoline_start);
    return 0;
}

/* SBX_LOCK_EXEC's state: the helper and the child library's path (the flags are lock_flags, above). */
static int helper_fd = -1;
static char child_library[SBX_PATH_MAX];

/*
 * SBX_LOCK_LEARN: a call a real lockdown refuses with errno would. The
 * broker records it (SBX_LEARN, answered before the call is made, so the
 * records keep their order), then the call is made as asked, through the
 * trampoline the learning filter lets through.
 */
static long learn_call(long nr, ucontext_t *uc, int would) {
    struct sbx_learn_record record;
    memset(&record, 0, sizeof(record));
    record.nr = nr;
    for (int i = 0; i < 6; i++) record.args[i] = ARG(uc, i);
    record.would = would;
    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = SBX_LEARN;
    request.path_len = sizeof(record);
    request.tid = (int32_t) syscall(__NR_gettid);
    int passed;
    exchange(&request, NULL, 0, &record, sizeof(record), NULL, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    /*
     * A program started by exec keeps the filter but not this handler, so
     * its first trapped call (any path) would end it with signal 31: exec is
     * recorded and refused, as a real lockdown refuses it.
     */
    if (nr == __NR_execve || nr == __NR_execveat) return -would;
    return through(nr, ARG(uc, 0), ARG(uc, 1), ARG(uc, 2), ARG(uc, 3), ARG(uc, 4), ARG(uc, 5));
}

/* The kernel's struct sigaction for rt_sigaction, the same on x86_64 and arm64 (both have sa_restorer). */
struct kernel_sigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    uint64_t mask;
};

/*
 * rt_sigaction, made with SIGSYS left out of the new handler's mask: while
 * a handler runs the kernel blocks its mask, and a trapped call made there
 * with SIGSYS blocked kills the process (docs/design.md, "SIGSYS stays
 * open"). The call is made through the trampoline, which a real filter
 * lets through for this call alone. A new SIGSYS handler is refused, by the
 * filter, or here with SBX_LOCK_EXEC (whose filter lets one through the
 * trampoline for sbx_adopt): bionic installs debuggerd's for SIGSYS, which
 * would end the process on the next trapped call.
 */
static long sigaction_call(long signal_number, const void *action, void *old, unsigned long size) {
    if (size != sizeof(uint64_t)) return -EINVAL;
    if (action != NULL && signal_number == SIGSYS) return -EPERM;
    if (action == NULL) return through(__NR_rt_sigaction, signal_number, 0, (long) old, (long) size, 0, 0);
    struct kernel_sigaction copy;
    memcpy(&copy, action, sizeof(copy));
    copy.mask &= ~SIGSYS_BIT;
    return through(__NR_rt_sigaction, signal_number, (long) &copy, (long) old, (long) size, 0, 0);
}

/* A signal the filter sent to the broker (SBX_LOCK_SIGNAL_TREE): the broker decides and sends it. */
static long signal_call(int kind, long tgid, long tid, long signal_number, const void *info) {
    struct sbx_signal_request body;
    memset(&body, 0, sizeof(body));
    body.kind = kind;
    body.tgid = (int32_t) tgid;
    body.tid = (int32_t) tid;
    body.signal = (int32_t) signal_number;
    if (info) memcpy(body.info, info, sizeof(body.info));
    struct sbx_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBX_PROTOCOL_VERSION;
    request.op = SBX_SIGNAL;
    request.path_len = sizeof(body);
    request.tid = (int32_t) syscall(__NR_gettid);
    int passed;
    long result = exchange(&request, NULL, 0, &body, sizeof(body), NULL, 0, NULL, 0, 0, &passed);
    if (passed >= 0) close(passed);
    return result;
}

/* value in decimal into out (at least 12 bytes), with no stdio in the handler. */
static char *decimal(char *out, unsigned value) {
    char digits[12];
    int n = 0;
    do digits[n++] = (char) ('0' + value % 10);
    while ((value /= 10) != 0);
    char *at = out;
    while (n > 0) *at++ = digits[--n];
    *at = '\0';
    return out;
}

static int starts_with(const char *text, const char *prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

/*
 * execve and execveat under SBX_LOCK_EXEC (docs/design.md, "SBX_LOCK_EXEC
 * and sbx-exec"). The broker decides the target as a read and answers with
 * it open. The handler then runs sbx-exec through the trampoline (the one
 * execveat the filter lets through), with the broker connection, the
 * current directory, the target and the lockdown's flags; sbx-exec loads
 * the target in this process, which keeps its pid and its filter. The new
 * image's libsbx_child.so adopts the connection (sbx_adopt), finding the
 * helper and the child library in SBX_EXEC_HELPER_FD and SBX_CHILD_LIBRARY.
 * Returns only when the exec failed.
 */
static long exec_call(int dirfd, const char *path, char *const *argv, char *const *envp, int flags, int depth);

/*
 * A "#!" script, as the kernel runs one: the interpreter named on the
 * first line, with its one optional argument, then the script's path as
 * it was given, then the program's arguments after argv[0]. The
 * interpreter is decided by the broker like any exec (it may be a script
 * itself, up to the kernel's 4 levels). Returns only on failure.
 */
static long script_call(int target, const char *path, char *const *argv, char *const *envp, int depth) {
    char line[256];
    ssize_t n = pread(target, line, sizeof(line) - 1, 0);
    if (n < 2) return -ENOEXEC;
    line[n] = '\0';
    char *end = memchr(line, '\n', (size_t) n);
    if (!end) return -ENOEXEC; /* a first line longer than the kernel reads */
    *end = '\0';
    char *interpreter = line + 2;
    while (*interpreter == ' ' || *interpreter == '\t') interpreter++;
    char *argument = interpreter;
    while (*argument && *argument != ' ' && *argument != '\t') argument++;
    if (*argument) *argument++ = '\0';
    while (*argument == ' ' || *argument == '\t') argument++;
    char *trail = argument + strlen(argument);
    while (trail > argument && (trail[-1] == ' ' || trail[-1] == '\t' || trail[-1] == '\r')) *--trail = '\0';
    if (!*interpreter) return -ENOEXEC;
    size_t argc = 0;
    while (argv && argv[argc]) argc++;
    size_t size = (argc + 4) * sizeof(char *);
    size = (size + 4095) & ~(size_t) 4095;
    char **args = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (args == MAP_FAILED) return -ENOMEM;
    size_t k = 0;
    args[k++] = interpreter;
    if (*argument) args[k++] = argument;
    args[k++] = (char *) path;
    for (size_t i = 1; i < argc; i++) args[k++] = argv[i];
    args[k] = NULL;
    long result = exec_call(AT_FDCWD, interpreter, args, envp, 0, depth + 1);
    munmap(args, size);
    return result;
}

static long exec_call(int dirfd, const char *path, char *const *argv, char *const *envp, int flags, int depth) {
    if (helper_fd < 0) return -EACCES;
    if (depth > 4) return -ELOOP;
    if (path == NULL) return -EFAULT;
    char link[32];
    if (path[0] == '\0') {
        if (!(flags & AT_EMPTY_PATH)) return -ENOENT;
        fd_link(link, dirfd == AT_FDCWD ? current_directory() : dirfd);
        path = link;
        dirfd = AT_FDCWD;
    }
    size_t argc = 0, envc = 0, env_bytes = 0;
    while (argv && argv[argc]) {
        if (++argc > (1u << 20)) return -E2BIG;
    }
    while (envp && envp[envc]) {
        if (++envc > (1u << 20)) return -E2BIG;
    }
    long target = forward(SBX_EXEC, dirfd, path, 0, NULL, 0, 0, NULL, 0);
    if (target < 0) return target;
    char magic[2];
    if (pread((int) target, magic, 2, 0) == 2 && magic[0] == '#' && magic[1] == '!') {
        long result = script_call((int) target, path, argv, envp, depth);
        close((int) target);
        return result;
    }

    static const char helper_name[] = "SBX_EXEC_HELPER_FD=", library_name[] = "SBX_CHILD_LIBRARY=";
    env_bytes = sizeof(helper_name) + 12 + sizeof(library_name) + strlen(child_library) + 1;
    size_t pointers = (8 + argc + 1) + (envc + 3);
    size_t size = pointers * sizeof(char *) + 5 * 12 + env_bytes;
    size = (size + 4095) & ~(size_t) 4095;
    char **space = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (space == MAP_FAILED) {
        close((int) target);
        return -ENOMEM;
    }
    /* The helper's descriptors, kept across the exec; every other one of ours is close-on-exec. */
    int kept[4] = {
        fcntl(broker, F_DUPFD, 3), fcntl(current_directory(), F_DUPFD, 3), fcntl((int) target, F_DUPFD, 3),
        fcntl(helper_fd, F_DUPFD, 3),
    };
    close((int) target);
    long result = -EMFILE;
    if (kept[0] >= 0 && kept[1] >= 0 && kept[2] >= 0 && kept[3] >= 0) {
        char **args = space, **env = space + 8 + argc + 1;
        char *text = (char *) (space + pointers);
        args[0] = (char *) "sbx-exec";
        for (int i = 0; i < 3; i++) {
            args[1 + i] = decimal(text, (unsigned) kept[i]);
            text += 12;
        }
        args[4] = decimal(text, lock_flags);
        text += 12;
        args[5] = child_library;
        args[6] = (char *) path;
        args[7] = (char *) "--";
        for (size_t i = 0; i < argc; i++) args[8 + i] = argv[i];
        args[8 + argc] = NULL;
        size_t e = 0;
        for (size_t i = 0; i < envc; i++) {
            if (starts_with(envp[i], helper_name) || starts_with(envp[i], library_name)) continue;
            env[e++] = envp[i];
        }
        env[e++] = text;
        memcpy(text, helper_name, sizeof(helper_name) - 1);
        decimal(text + sizeof(helper_name) - 1, (unsigned) kept[3]);
        text += strlen(text) + 1;
        env[e++] = text;
        memcpy(text, library_name, sizeof(library_name) - 1);
        memcpy(text + sizeof(library_name) - 1, child_library, strlen(child_library) + 1);
        env[e] = NULL;
        result = through(__NR_execveat, kept[3], (long) "", (long) args, (long) env, AT_EMPTY_PATH, 0);
    }
    for (int i = 0; i < 4; i++) {
        if (kept[i] >= 0) close(kept[i]);
    }
    munmap(space, size);
    return result;
}

static long dispatch(long nr, ucontext_t *uc) {
    long a0 = ARG(uc, 0), a1 = ARG(uc, 1), a2 = ARG(uc, 2), a3 = ARG(uc, 3), a4 = ARG(uc, 4);
    char buffer[SBX_PATH_MAX];
    switch (nr) {
    case __NR_rt_sigaction:
        return sigaction_call(a0, (const void *) a1, (void *) a2, (unsigned long) a3);
    case __NR_rt_sigprocmask:
        return sigmask_call(uc, (int) a0, (const void *) a1, (void *) a2, (unsigned long) a3);
    case __NR_openat:
        return open_path((int) a0, (const char *) a1, (int) a2, (uint32_t) a3, buffer);
    case __NR_kill:
        return signal_call(SBX_SIG_KILL, a0, 0, a1, NULL);
    case __NR_tgkill:
        return signal_call(SBX_SIG_TGKILL, a0, a1, a2, NULL);
    case __NR_tkill:
        return signal_call(SBX_SIG_TKILL, 0, a0, a1, NULL);
    case __NR_rt_sigqueueinfo:
        return signal_call(SBX_SIG_QUEUEINFO, a0, 0, a1, (const void *) a2);
    case __NR_rt_tgsigqueueinfo:
        return signal_call(SBX_SIG_TGQUEUEINFO, a0, a1, a2, (const void *) a3);
    case __NR_execve:
        return exec_call(AT_FDCWD, (const char *) a0, (char *const *) a1, (char *const *) a2, 0, 0);
    case __NR_execveat:
        return exec_call((int) a0, (const char *) a1, (char *const *) a2, (char *const *) a3, (int) a4, 0);
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
    case __NR_linkat:
        return link_path((int) a0, (const char *) a1, (int) a2, (const char *) a3, (int) a4);
    case __NR_symlinkat:
        return symlink_path((const char *) a0, (int) a1, (const char *) a2);
    case __NR_truncate:
        return truncate_path((const char *) a0, a1);
    case __NR_inotify_add_watch:
        /* Trapped only with SBX_LOCK_WATCH; otherwise refused or the kernel's. */
        return watch_call((int) a0, (const char *) a1, (uint32_t) a2);
    case __NR_socket:
        return net_socket((int) a0, (int) a1, (int) a2);
    case __NR_connect:
        if (unix_mode) return unix_call(SBX_UNIX_CONNECT, (int) a0, (const struct sockaddr *) a1, (socklen_t) a2);
        return net_connect((int) a0, (const struct sockaddr *) a1, (socklen_t) a2);
    case __NR_bind:
        if (unix_mode) return unix_call(SBX_UNIX_BIND, (int) a0, (const struct sockaddr *) a1, (socklen_t) a2);
        return net_bind((int) a0, (const struct sockaddr *) a1, (socklen_t) a2);
    case __NR_listen:
        return net_listen((int) a0, (int) a1);
    case __NR_accept4:
        return net_accept((int) a0, (struct sockaddr *) a1, (socklen_t *) a2, (int) a3);
#ifdef __NR_accept
    case __NR_accept:
        return net_accept((int) a0, (struct sockaddr *) a1, (socklen_t *) a2, 0);
#endif
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
    case __NR_link:
        return link_path(AT_FDCWD, (const char *) a0, AT_FDCWD, (const char *) a1, 0);
    case __NR_symlink:
        return symlink_path((const char *) a0, AT_FDCWD, (const char *) a1);
#endif
    default:
        return -ENOSYS;
    }
}

/* The trace ring (sbx_trace), or NULL. */
static struct sbx_trace_header *trace_ring;

static struct sbx_trace_entry *trace_entries(struct sbx_trace_header *ring) {
    return (struct sbx_trace_entry *) (ring + 1);
}

int sbx_trace(int fd, unsigned slots) {
    if (locked) return -EALREADY;
    if (__atomic_load_n(&trace_ring, __ATOMIC_ACQUIRE)) return -EALREADY;
    if (slots < 16 || slots > 4096) return -EINVAL;
    size_t size = SBX_TRACE_FAULT_OFFSET(slots) + sizeof(struct sbx_trace_fault);
    if (ftruncate(fd, 0) != 0 || ftruncate(fd, (off_t) size) != 0) return -errno;
    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) return -errno;
    struct sbx_trace_header *ring = mapped;
    ring->version = SBX_TRACE_VERSION;
    ring->slots = slots;
    ring->next = 0;
    ring->pid = (int32_t) getpid();
    ring->locked = 0;
    /* Last, so a reader that sees the magic sees the rest. */
    __atomic_store_n(&ring->magic, SBX_TRACE_MAGIC, __ATOMIC_RELEASE);
    __atomic_store_n(&trace_ring, ring, __ATOMIC_RELEASE);
    return 0;
}

/* The handler's first act: plain stores, no system call before the call is noted. */
static struct sbx_trace_entry *trace_enter(const siginfo_t *info, const ucontext_t *uc) {
    struct sbx_trace_header *ring = __atomic_load_n(&trace_ring, __ATOMIC_ACQUIRE);
    if (!ring) return NULL;
    uint32_t n = __atomic_fetch_add(&ring->next, 1, __ATOMIC_RELAXED);
    struct sbx_trace_entry *entry = &trace_entries(ring)[n % ring->slots];
    __atomic_store_n(&entry->seq, 0, __ATOMIC_RELAXED);
    entry->nr = info->si_syscall;
    entry->ip = (uint64_t) (uintptr_t) info->si_call_addr;
    entry->arg0 = (uint64_t) ARG(uc, 0);
    entry->state = SBX_TRACE_ENTERED | ((uint32_t) (info->si_errno & 0xffffff) << 8);
    entry->tid = 0;
    __atomic_store_n(&entry->seq, n + 1, __ATOMIC_RELEASE);
    /* Allowed by every filter; after the note, so a death here still leaves one. */
    entry->tid = (int32_t) syscall(__NR_gettid);
    return entry;
}

static void trace_leave(struct sbx_trace_entry *entry) {
    if (!entry) return;
    uint32_t state = __atomic_load_n(&entry->state, __ATOMIC_RELAXED);
    __atomic_store_n(&entry->state, (state & ~0xffu) | SBX_TRACE_LEFT, __ATOMIC_RELEASE);
}

/* The return addresses an unwind from the handler finds, the handler's own frames first. */
struct unwound {
    uint64_t pc[SBX_TRACE_FRAMES + 16];
    unsigned count;
};

static _Unwind_Reason_Code unwind_one(struct _Unwind_Context *context, void *data) {
    struct unwound *unwound = data;
    uint64_t pc = (uint64_t) _Unwind_GetIP(context);
    if (pc == 0) return _URC_END_OF_STACK;
    unwound->pc[unwound->count++] = pc;
    return unwound->count < sizeof(unwound->pc) / sizeof(unwound->pc[0]) ? _URC_NO_REASON : _URC_END_OF_STACK;
}

/* Copies at most size - 1 bytes and terminates: no snprintf in a signal handler. */
static void copy_name(char *out, size_t size, const char *name) {
    size_t k = 0;
    for (; name && name[k] && k + 1 < size; k++) out[k] = name[k];
    out[k] = '\0';
}

/* A frame: pc, and the library and symbol it falls in. A return address is looked up one byte back, inside its call. */
static void fault_frame(struct sbx_trace_frame *frame, uint64_t pc, int is_return) {
    frame->pc = pc;
    Dl_info found;
    memset(&found, 0, sizeof(found));
    if (dladdr((const void *) (uintptr_t) (is_return ? pc - 1 : pc), &found) == 0) return;
    frame->base = (uint64_t) (uintptr_t) found.dli_fbase;
    frame->symbol = (uint64_t) (uintptr_t) found.dli_saddr;
    const char *file = found.dli_fname;
    for (const char *c = file; c && *c; c++) {
        if (*c == '/') file = c + 1;
    }
    copy_name(frame->module, sizeof(frame->module), file);
    copy_name(frame->name, sizeof(frame->name), found.dli_sname);
}

static int fault_taken;

/* Tests set this to exercise the frame-pointer walk alone (internal.h). */
int sbx_trace_fault_frame_pointers_only;

/* How far above the faulting sp a frame record may lie: a thread's stack, at most. */
#define FRAME_WALK_SPAN (8u << 20)

/*
 * The faulting thread's callers from its own frame records, starting at
 * the frame pointer the signal saved: on arm64 x29 points at {previous x29,
 * return address}, on x86_64 rbp at {previous rbp, return address}.
 * Android's arm64 code keeps frame pointers. Each record must lie above the
 * last, within FRAME_WALK_SPAN of sp and aligned, or the walk stops. A read
 * that faults anyway ends the process (SIGSEGV is blocked in this handler),
 * so each frame is counted as soon as it is written: what was found stays.
 */
static unsigned walk_frame_pointers(struct sbx_trace_fault *fault, const ucontext_t *uc, unsigned frames) {
#if defined(__aarch64__)
    uintptr_t fp = (uintptr_t) uc->uc_mcontext.regs[29];
    const uintptr_t align = 16;
#else
    uintptr_t fp = (uintptr_t) uc->uc_mcontext.gregs[REG_RBP];
    const uintptr_t align = 8;
#endif
    uintptr_t low = (uintptr_t) fault->sp;
    int chain = fp >= low && fp - low < FRAME_WALK_SPAN && fp % align == 0;
    /*
     * A leaf function sets up no frame record, so the chain starts at its
     * caller's and would skip the caller itself. That caller's return
     * address is in x30 on arm64 and on top of the stack on x86_64. It is
     * kept when it falls in a loaded library and is not the chain's first
     * address anyway, and dropped when it is inside the faulting function
     * itself (a non-leaf has since used x30 for its own calls). Where no
     * symbol says which function either is in, it is kept and named "link"
     * so a reader takes it as a lead, not a proven caller.
     */
#if defined(__aarch64__)
    uint64_t link = (uint64_t) uc->uc_mcontext.regs[30] & 0x0000ffffffffffffull;
#else
    uint64_t link = low % 8 == 0 ? (uint64_t) *(const uintptr_t *) low : 0;
#endif
    uint64_t first = chain ? (uint64_t) ((const uintptr_t *) fp)[1] & 0x0000ffffffffffffull : 0;
    if (link != 0 && link != first && frames < SBX_TRACE_FRAMES) {
        Dl_info at_link, at_pc;
        memset(&at_link, 0, sizeof(at_link));
        memset(&at_pc, 0, sizeof(at_pc));
        if (dladdr((const void *) (uintptr_t) (link - 1), &at_link) != 0) {
            int known = dladdr((const void *) (uintptr_t) fault->pc, &at_pc) != 0 && at_pc.dli_saddr != NULL &&
                        at_link.dli_saddr != NULL;
            int same = known && at_link.dli_saddr == at_pc.dli_saddr && at_link.dli_fbase == at_pc.dli_fbase;
            if (!same) {
                fault_frame(&fault->frame[frames], link, 1);
                if (!known) copy_name(fault->frame[frames].name, sizeof(fault->frame[frames].name), "link");
                __atomic_store_n(&fault->frames, ++frames, __ATOMIC_RELEASE);
            }
        }
    }
    while (chain && frames < SBX_TRACE_FRAMES && fp >= low && fp - low < FRAME_WALK_SPAN && fp % align == 0) {
        const uintptr_t *record = (const uintptr_t *) fp;
        uintptr_t next = record[0];
        /* Pointer authentication may sign the saved address; a user address has no high bits. */
        uint64_t ret = (uint64_t) record[1] & 0x0000ffffffffffffull;
        if (ret == 0) break;
        fault_frame(&fault->frame[frames], ret, 1);
        __atomic_store_n(&fault->frames, ++frames, __ATOMIC_RELEASE);
        if (next <= fp) break;
        fp = next;
    }
    return frames;
}

void sbx_trace_fault(int signal_number, const siginfo_t *info, const void *context) {
    struct sbx_trace_header *ring = __atomic_load_n(&trace_ring, __ATOMIC_ACQUIRE);
    if (!ring || !info || !context) return;
    if (__atomic_exchange_n(&fault_taken, 1, __ATOMIC_ACQ_REL)) return;
    struct sbx_trace_fault *fault = (struct sbx_trace_fault *) ((char *) ring + SBX_TRACE_FAULT_OFFSET(ring->slots));
    const ucontext_t *uc = context;
    __atomic_store_n(&fault->state, SBX_TRACE_ENTERED, __ATOMIC_RELEASE);
    fault->signal = signal_number;
    fault->code = info->si_code;
    fault->address = (uint64_t) (uintptr_t) info->si_addr;
#if defined(__x86_64__)
    fault->pc = (uint64_t) uc->uc_mcontext.gregs[REG_RIP];
    fault->sp = (uint64_t) uc->uc_mcontext.gregs[REG_RSP];
    fault->lr = (uint64_t) uc->uc_mcontext.gregs[REG_RBP];
#elif defined(__aarch64__)
    fault->pc = (uint64_t) uc->uc_mcontext.pc;
    fault->sp = (uint64_t) uc->uc_mcontext.sp;
    fault->lr = (uint64_t) uc->uc_mcontext.regs[30];
#endif
    fault->tid = (int32_t) syscall(__NR_gettid);
    /* The faulting place first, from the registers: it holds even when the unwind below finds nothing. */
    unsigned frames = 0;
    if (fault->pc != 0) fault_frame(&fault->frame[frames++], fault->pc, 0);
    __atomic_store_n(&fault->frames, frames, __ATOMIC_RELEASE);
    /*
     * The unwind starts in this handler and passes through the signal
     * frame; its own frames are dropped up to the faulting pc. When it does
     * not reach the faulting pc (on an arm64 Retroid Pocket 5 it stopped at
     * ART's signal chain, and the record showed only this handler's frames;
     * Droidtop/tracker#550, 2026-10-24), the callers come from the faulting
     * thread's frame records instead.
     */
    struct unwound unwound = {.count = 0};
    if (!sbx_trace_fault_frame_pointers_only) _Unwind_Backtrace(unwind_one, &unwound);
    /* The unwind is used when it found the faulting pc with callers after it. */
    unsigned first = 0;
    for (unsigned k = 0; k < unwound.count; k++) {
        if (unwound.pc[k] == fault->pc) {
            first = k + 1;
            break;
        }
    }
    if (first > 0 && first < unwound.count) {
        for (unsigned k = first; k < unwound.count && frames < SBX_TRACE_FRAMES; k++) {
            fault_frame(&fault->frame[frames++], unwound.pc[k], 1);
        }
    } else {
        frames = walk_frame_pointers(fault, uc, frames);
    }
    fault->frames = frames;
    __atomic_store_n(&fault->state, SBX_TRACE_LEFT, __ATOMIC_RELEASE);
}

static void handle_sigsys(int signal_number, siginfo_t *info, void *context);

static void on_sigsys(int signal_number, siginfo_t *info, void *context) {
    struct sbx_trace_entry *entry = trace_enter(info, (ucontext_t *) context);
    handle_sigsys(signal_number, info, context);
    trace_leave(entry);
}

static void handle_sigsys(int signal_number, siginfo_t *info, void *context) {
    int learning = info->si_code == SYS_SECCOMP &&
                   (info->si_errno == SBX_TRAP_LEARN_EACCES || info->si_errno == SBX_TRAP_LEARN_EPERM);
    if (learning) {
        int saved_errno = errno;
        ucontext_t *uc = (ucontext_t *) context;
        SET_RESULT(uc, learn_call(info->si_syscall, uc, info->si_errno == SBX_TRAP_LEARN_EPERM ? EPERM : EACCES));
        errno = saved_errno;
        return;
    }
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
/*
 * A refusal, or under SBX_LOCK_LEARN a trap that records the call and makes
 * it (learn_call); the trap data says which errno a real lockdown answers.
 * The _ALWAYS forms stay refusals in learning too.
 */
#define REFUSE_ALWAYS (SECCOMP_RET_ERRNO | EACCES)
#define DENY_ALWAYS (SECCOMP_RET_ERRNO | EPERM)
#define LEARN_EACCES (SECCOMP_RET_TRAP | SBX_TRAP_LEARN_EACCES)
#define LEARN_EPERM (SECCOMP_RET_TRAP | SBX_TRAP_LEARN_EPERM)
static unsigned refuse_action = REFUSE_ALWAYS, deny_action = DENY_ALWAYS;
#define REFUSE refuse_action
#define DENY deny_action
#define NOSYS (SECCOMP_RET_ERRNO | ENOSYS)
#define ALLOW SECCOMP_RET_ALLOW

/*
 * Blocks that test arguments. Each starts with "if the call is not nr,
 * skip the block", and every path through a block returns, so the
 * accumulator still holds nr for the rules after it.
 */

/* nr is allowed only when its first argument is this process. */
static void own_process_only(unsigned nr, pid_t pid, unsigned otherwise) {
    jeq(nr, 0, 6);
    load(ARG_LO(0));
    jeq((unsigned) pid, 0, 3);
    load(ARG_HI(0));
    jeq(0, 0, 1);
    ret(ALLOW);
    ret(otherwise);
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
 * Allows nr only when it is made from the handler's gateway -- the trampoline
 * the handler routes its own calls through, at trampoline_after() -- and traps
 * any other caller to the broker. The handler's own privileged calls (a
 * brokered connect/accept of a Unix socket, a directory listing, a passthrough
 * path op) are bound this way instead of by a magic argument value a worker
 * could forge (review A-06); execveat and rt_sigaction are bound the same way.
 * When the call is not nr the accumulator still holds nr for the rules below.
 */
static void allow_from_gateway(unsigned nr) {
    uint64_t after = (uint64_t) trampoline_after();
    jeq(nr, 0, 6);
    load(offsetof(struct seccomp_data, instruction_pointer));
    jeq((unsigned) after, 0, 3);
    load(offsetof(struct seccomp_data, instruction_pointer) + 4);
    jeq((unsigned) (after >> 32), 0, 1);
    ret(ALLOW);
    ret(TRAP);
}

/*
 * socket() with SBX_LOCK_UNIX: Unix stream and seqpacket sockets, a Unix
 * datagram one with SBX_LOCK_LOG_SOCKET, inet stream and datagram ones with
 * SBX_LOCK_INET; nothing else. One block per family: if the family
 * matches, the type (without its flags) decides; every path returns.
 */
static void socket_rule(unsigned flags) {
    struct family {
        unsigned domain;
        unsigned types[3];
        unsigned count;
    } families[3];
    unsigned family_count = 0;
    families[family_count++] = (struct family) {AF_UNIX, {SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM},
                                                (flags & (SBX_LOCK_LOG_SOCKET | SBX_LOCK_SOCKETS)) ? 3u : 2u};
    int netlink = (flags & SBX_LOCK_SOCKETS) != 0;
    if (flags & (SBX_LOCK_INET | SBX_LOCK_SOCKETS)) {
        families[family_count++] = (struct family) {AF_INET, {SOCK_STREAM, SOCK_DGRAM, 0}, 2};
        families[family_count++] = (struct family) {AF_INET6, {SOCK_STREAM, SOCK_DGRAM, 0}, 2};
    }
    unsigned total = 2;  /* the load of the domain and the final refusal */
    for (unsigned f = 0; f < family_count; f++) total += 5 + families[f].count;
    if (netlink) total += 5;
    jeq(__NR_socket, 0, (unsigned char) total);
    load(ARG_LO(0));
    if (netlink) {
        /* Route netlink only (interfaces and addresses), whatever the type. */
        jeq(AF_NETLINK, 0, 4);
        load(ARG_LO(2));
        jeq(0 /* NETLINK_ROUTE */, 0, 1);
        ret(ALLOW);
        ret(REFUSE);
    }
    for (unsigned f = 0; f < family_count; f++) {
        unsigned count = families[f].count;
        jeq(families[f].domain, 0, (unsigned char) (4 + count));
        load(ARG_LO(1));
        emit((struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf));
        for (unsigned t = 0; t < count; t++) jeq(families[f].types[t], (unsigned char) (count - t), 0);
        ret(REFUSE);
        ret(ALLOW);
    }
    ret(REFUSE);
}

static int build_filter(unsigned flags, pid_t pid, const int *sealed, unsigned sealed_count) {
    filter_length = 0;
    int learn = (flags & SBX_LOCK_LEARN) != 0;
    refuse_action = learn ? LEARN_EACCES : REFUSE_ALWAYS;
    deny_action = learn ? LEARN_EPERM : DENY_ALWAYS;
    load(offsetof(struct seccomp_data, arch));
    jeq(SBX_ARCH, 1, 0);
    ret(REFUSE_ALWAYS);
    load(offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
    /* x32 calls share the architecture but set this bit. */
    emit((struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1));
    ret(REFUSE_ALWAYS);
#endif
    if (flags & SBX_LOCK_EXEC) {
        /* The adoption probe (sbx_adopt): proof, in an image sbx-exec started, that this filter is in place. */
        jeq(__NR_prctl, 0, 3);
        load(ARG_LO(0));
        jeq(SBX_EXEC_PROBE, 0, 1);
        ret(SECCOMP_RET_ERRNO | ENOTRECOVERABLE);
        load(offsetof(struct seccomp_data, nr));
        /*
         * The handler's run of sbx-exec: execveat(fd, "", ..., AT_EMPTY_PATH)
         * through the trampoline. Every other exec traps (exec_call).
         */
        uint64_t after = (uint64_t) trampoline_after();
        jeq(__NR_execveat, 0, 7);
        load(offsetof(struct seccomp_data, instruction_pointer));
        jeq((unsigned) after, 0, 5);
        load(offsetof(struct seccomp_data, instruction_pointer) + 4);
        jeq((unsigned) (after >> 32), 0, 3);
        load(ARG_LO(4));
        emit((struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, AT_EMPTY_PATH, 0, 1));
        ret(ALLOW);
        load(offsetof(struct seccomp_data, nr));
    }
    if (learn) {
        /*
         * The learning handler makes a recorded call through its own
         * trampoline, which only a learning filter lets through: anything
         * at that address would get past a real one.
         */
        uint64_t after = (uint64_t) trampoline_after();
        load(offsetof(struct seccomp_data, instruction_pointer));
        jeq((unsigned) after, 0, 3);
        load(offsetof(struct seccomp_data, instruction_pointer) + 4);
        jeq((unsigned) (after >> 32), 0, 1);
        ret(ALLOW);
        load(offsetof(struct seccomp_data, nr));
    }
    int unbrokered = (flags & SBX_LOCK_UNBROKERED) != 0;
    int pass = (flags & SBX_LOCK_PASSTHROUGH) != 0;
    if (pass) {
        static const unsigned one[] = {
            __NR_openat, __NR_newfstatat, __NR_faccessat, __NR_faccessat2, __NR_readlinkat, __NR_mkdirat, __NR_unlinkat,
            __NR_fchmodat,
        };
        for (size_t i = 0; i < sizeof(one) / sizeof(one[0]); i++) allow_from_gateway(one[i]);
        /*
         * utimensat: futimens (no path) is a descriptor call any code may make, so a null path is
         * allowed whatever its caller; with a path it is a path op, allowed only from the handler's
         * gateway (trampoline_after), not by a forgeable argument value (review A-06).
         */
        uint64_t utimens_after = (uint64_t) trampoline_after();
        jeq(__NR_utimensat, 0, 10);
        load(ARG_LO(1));
        jeq(0, 0, 2);
        load(ARG_HI(1));
        jeq(0, 4, 0);
        load(offsetof(struct seccomp_data, instruction_pointer));
        jeq((unsigned) utimens_after, 0, 3);
        load(offsetof(struct seccomp_data, instruction_pointer) + 4);
        jeq((unsigned) (utimens_after >> 32), 0, 1);
        ret(ALLOW);
        ret(TRAP);
        /* getdents64 names no path, but an isolated process may be refused a brokered folder's listing (list_directory). */
        allow_from_gateway(__NR_getdents64);
        allow_from_gateway(__NR_renameat2);
#ifdef __NR_renameat
        allow_from_gateway(__NR_renameat);
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
    if (flags & SBX_LOCK_NET_BROKERED) {
        /* Inet sockets are the broker's; Unix ones the process's own. connect and accept4 pass from the gateway only. */
        jeq(__NR_socket, 0, 7);
        load(ARG_LO(0));
        jeq(AF_INET, 3, 0);
        jeq(AF_INET6, 2, 0);
        jeq(AF_UNIX, 0, 2);
        ret(ALLOW);
        ret(TRAP);
        ret(REFUSE);
        allow_from_gateway(__NR_connect);
        allow_from_gateway(__NR_accept4);
        rule(__NR_bind, TRAP);
        rule(__NR_listen, TRAP);
#ifdef __NR_accept
        rule(__NR_accept, TRAP);
#endif
    }
    if (flags & SBX_LOCK_UNIX) {
        /* The address is in memory the filter cannot read: the handler sends each to the broker. */
        rule(__NR_connect, TRAP);
        rule(__NR_bind, TRAP);
    }
    /* A Unix datagram socket for the system log, or inet sockets, when asked; no other socket. */
    if (flags & SBX_LOCK_NET_BROKERED) {
        /* decided above */
    } else if (flags & (SBX_LOCK_UNIX | SBX_LOCK_SOCKETS)) {
        socket_rule(flags);
    } else if (flags & SBX_LOCK_LOG_SOCKET) {
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
    ret(DENY_ALWAYS);  /* even learning: a clone made from the handler would run the child on its stack */
    ret(ALLOW);
    if (!unbrokered) {
        /*
         * The SIGSYS handler stays ours. Any other handler is installed by our
         * handler (sigaction_call), with SIGSYS left out of its mask, through
         * the trampoline, which is let through here for rt_sigaction alone.
         */
        uint64_t after = (uint64_t) trampoline_after();
        if (flags & SBX_LOCK_EXEC) {
            /*
             * Each new image installs its handler, through the trampoline
             * (sbx-exec's, then libsbx_child.so's), so a SIGSYS handler is
             * allowed there too. Code that replaces ours only loses its own
             * file access: the filter still refuses what the handler would
             * have forwarded.
             */
            jeq(__NR_rt_sigaction, 0, 6);
        } else {
            jeq(__NR_rt_sigaction, 0, 9);
            load(ARG_LO(0));
            jeq(SIGSYS, 0, 1);
            ret(DENY_ALWAYS);  /* even learning: without our handler nothing after it would be recorded */
        }
        load(offsetof(struct seccomp_data, instruction_pointer));
        jeq((unsigned) after, 0, 3);
        load(offsetof(struct seccomp_data, instruction_pointer) + 4);
        jeq((unsigned) (after >> 32), 0, 1);
        ret(ALLOW);
        ret(TRAP);
        /* And SIGSYS stays open on every thread: the handler makes the call (sigmask_call). */
        rule(__NR_rt_sigprocmask, TRAP);
    }
    /* Signals only to this process, unless SBX_LOCK_SIGNALS leaves them to the kernel. */
    if (!(flags & SBX_LOCK_SIGNALS)) {
        /* With SBX_LOCK_SIGNAL_TREE, any other target goes to the broker (signal_call). */
        unsigned otherwise = (flags & SBX_LOCK_SIGNAL_TREE) ? TRAP : DENY;
        own_process_only(__NR_kill, pid, otherwise);
        own_process_only(__NR_tgkill, pid, otherwise);
        own_process_only(__NR_rt_sigqueueinfo, pid, otherwise);
        own_process_only(__NR_rt_tgsigqueueinfo, pid, otherwise);
        if (flags & SBX_LOCK_SIGNAL_TREE) rule(__NR_tkill, TRAP);
    }
    /*
     * TIOCSTI and TIOCLINUX push bytes into the input queue of a terminal
     * the process inherited; a confined process could use either to plant a
     * command that the shell runs after it exits. Refuse them on any
     * descriptor, whatever the fd rules below. The kernel reads the ioctl
     * request as a 32-bit int, so match the low word alone: the high bits
     * are discarded and cannot be used to slip a request past this.
     */
    jeq(__NR_ioctl, 0, 4);
    load(ARG_LO(1));
    jeq(TIOCSTI, 1, 0);
    jeq(TIOCLINUX, 0, 1);
    ret(DENY);
    load(offsetof(struct seccomp_data, nr));
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
        /* SBX_LOCK_PATHOPS sends link, symlink and truncate to the broker; SBX_LOCK_INOTIFY lets marks through. */
        static const unsigned pathops[] = {
            __NR_truncate, __NR_linkat, __NR_symlinkat,
#ifdef __NR_link
            __NR_link, __NR_symlink,
#endif
        };
        if (flags & SBX_LOCK_PATHOPS) {
            for (size_t i = 0; i < sizeof(pathops) / sizeof(pathops[0]); i++) rule(pathops[i], TRAP);
        }
        /* SBX_LOCK_WATCH sends inotify marks to the broker. */
        if (flags & SBX_LOCK_WATCH) rule(__NR_inotify_add_watch, TRAP);
        for (size_t i = 0; i < sizeof(refused_paths) / sizeof(refused_paths[0]); i++) {
            if (refused_paths[i] == __NR_inotify_add_watch && (flags & (SBX_LOCK_INOTIFY | SBX_LOCK_WATCH))) continue;
            rule(refused_paths[i], REFUSE);
        }
    }
    /*
     * Reading its own memory reaches nothing past the process, and ART does
     * it: art::SafeCopy reads with process_vm_readv on getpid(), and
     * FaultManager::IsInGeneratedCode calls SafeCopy before it decides that a
     * SIGSEGV is one of ART's implicit null checks. Refused, every null
     * receiver in Java became a fatal SIGSEGV at nterp_op_invoke_virtual
     * instead of a NullPointerException: KiriKiri and mkxp-z died so locked
     * down on a Retroid Pocket 5 (Droidtop/tracker#550, 2026-10-24). Any
     * other process's memory stays refused.
     */
    own_process_only(__NR_process_vm_readv, pid, REFUSE);
    /* Refused: reaching past the process. */
    static const unsigned refused[] = {
        __NR_execve, __NR_execveat, __NR_ptrace, __NR_process_vm_writev,
        __NR_process_madvise, __NR_bpf, __NR_perf_event_open, __NR_io_uring_setup, __NR_io_uring_enter,
        __NR_io_uring_register,
    };
    if (flags & SBX_LOCK_EXEC) {
        rule(__NR_execve, TRAP);
        rule(__NR_execveat, TRAP);
    }
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) rule(refused[i], REFUSE);
    /* connect only when a socket can be made (the log's, or inet ones); bind only for inet ones, the only sockets then. */
    if (!(flags & (SBX_LOCK_LOG_SOCKET | SBX_LOCK_INET | SBX_LOCK_NET_BROKERED | SBX_LOCK_SOCKETS))) rule(__NR_connect, REFUSE);
    if (!(flags & (SBX_LOCK_INET | SBX_LOCK_NET_BROKERED | SBX_LOCK_SOCKETS))) rule(__NR_bind, REFUSE);
    static const unsigned denied[] = {
        __NR_unshare, __NR_setns, __NR_mount, __NR_umount2, __NR_pivot_root, __NR_chroot, __NR_open_tree,
        __NR_move_mount, __NR_fsopen, __NR_fsconfig, __NR_fsmount, __NR_fspick, __NR_mount_setattr,
        __NR_keyctl, __NR_add_key, __NR_request_key, __NR_kcmp, __NR_pidfd_open, __NR_pidfd_getfd,
        __NR_pidfd_send_signal, __NR_tkill, __NR_init_module, __NR_finit_module, __NR_delete_module,
    };
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        if (denied[i] == __NR_tkill && (flags & (SBX_LOCK_SIGNALS | SBX_LOCK_SIGNAL_TREE))) continue;
        rule(denied[i], DENY);
    }
    ret(ALLOW);
    return filter_length <= FILTER_MAX ? 0 : -E2BIG;
}

/*
 * Takes SIGSYS out of every installed handler's mask, read and written with
 * the raw call: ART's sigchain interposes sigaction(), and what blocks
 * SIGSYS while a handler runs is the mask the kernel holds. Before the filter
 * goes on; after it, sigaction_call keeps SIGSYS out of every new one.
 */
static void open_sigsys_in_handlers(void) {
    for (int signal_number = 1; signal_number <= 64; signal_number++) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP || signal_number == SIGSYS) continue;
        struct kernel_sigaction action;
        if (syscall(__NR_rt_sigaction, signal_number, NULL, &action, sizeof(uint64_t)) != 0) continue;
        if (action.handler == SIG_DFL || action.handler == SIG_IGN || !(action.mask & SIGSYS_BIT)) continue;
        action.mask &= ~SIGSYS_BIT;
        syscall(__NR_rt_sigaction, signal_number, &action, NULL, sizeof(uint64_t));
    }
}

/*
 * Whether any thread of this process has SIGSYS blocked, from each
 * thread's SigBlk line in /proc/self/task/<tid>/status. Answered before the
 * filter goes on; afterwards no thread can block it (sigmask_call).
 */
static int sigsys_blocked_somewhere(void) {
    DIR *tasks = opendir("/proc/self/task");
    if (!tasks) return 0;
    int found = 0;
    struct dirent *entry;
    while (!found && (entry = readdir(tasks)) != NULL) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char path[sizeof("/proc/self/task//status") + sizeof(entry->d_name)];
        snprintf(path, sizeof(path), "/proc/self/task/%s/status", entry->d_name);
        FILE *status = fopen(path, "re");
        if (!status) continue;
        /*
         * A thread that has exited (Z, X) can still be listed for a moment
         * after pthread_join returns, with its last mask; it makes no calls.
         * State comes before SigBlk in the file.
         */
        char line[256];
        int exited = 0;
        while (fgets(line, sizeof(line), status)) {
            char state;
            unsigned long long blocked;
            if (sscanf(line, "State: %c", &state) == 1) {
                exited = state == 'Z' || state == 'X';
            } else if (sscanf(line, "SigBlk: %llx", &blocked) == 1) {
                found = !exited && (blocked & SIGSYS_BIT) != 0;
                break;
            }
        }
        fclose(status);
    }
    closedir(tasks);
    return found;
}

/*
 * Sets the options' resource limits on the process (review A-18). Each is both
 * the soft and hard limit; only lowering is attempted, which needs no
 * privilege. Called after the library's own setup opens and just before the
 * filter, so a low RLIMIT_NOFILE cannot break the lockdown itself.
 */
static int apply_limits(const struct sbx_lockdown_options *options) {
    for (unsigned i = 0; i < options->limit_count; i++) {
        struct rlimit limit = {options->limits[i].value, options->limits[i].value};
        if (setrlimit(options->limits[i].resource, &limit) != 0) return -errno;
    }
    return 0;
}

int sbx_lockdown(int broker_fd, const struct sbx_lockdown_options *options) {
    if (locked) return -EALREADY;
    struct sbx_lockdown_options none = {.flags = 0};
    if (!options) options = &none;
    int unbrokered = (options->flags & SBX_LOCK_UNBROKERED) != 0;
    int pass = (options->flags & SBX_LOCK_PASSTHROUGH) != 0;
    if (unbrokered && pass) return -EINVAL;
    unsigned install = SECCOMP_FILTER_FLAG_TSYNC | ((options->flags & SBX_LOCK_AUDIT) ? SECCOMP_FILTER_FLAG_LOG : 0);
    /* Learning sends every record to the broker. */
    if ((options->flags & SBX_LOCK_LEARN) && unbrokered) return -EINVAL;
    /* With SBX_LOCK_UNIX, bind goes to the broker, so the log's Unix socket can no longer take a name unseen. */
    if ((options->flags & SBX_LOCK_INET) && (options->flags & SBX_LOCK_LOG_SOCKET) && !(options->flags & SBX_LOCK_UNIX)) {
        return -EINVAL;
    }
    /* Brokered Unix sockets need the broker, and are not the brokered network's (which has its own Unix rules). */
    if ((options->flags & SBX_LOCK_UNIX) && (options->flags & (SBX_LOCK_UNBROKERED | SBX_LOCK_NET_BROKERED))) {
        return -EINVAL;
    }
    /* Signals left to the kernel, or judged by the broker: one or the other, and judging needs the broker. */
    if ((options->flags & SBX_LOCK_SIGNAL_TREE) && (options->flags & (SBX_LOCK_SIGNALS | SBX_LOCK_UNBROKERED))) {
        return -EINVAL;
    }
    /* Watches decided by the broker, or left to the kernel: one or the other, and deciding needs the broker. */
    if ((options->flags & SBX_LOCK_WATCH) && (options->flags & SBX_LOCK_INOTIFY || unbrokered || pass)) return -EINVAL;
    /* The process's own sockets, or the broker's: one or the other. */
    if ((options->flags & SBX_LOCK_SOCKETS) && (options->flags & SBX_LOCK_NET_BROKERED)) return -EINVAL;
    /* The broker's network needs the broker, and replaces the process's own. */
    if ((options->flags & SBX_LOCK_NET_BROKERED) && (options->flags & (SBX_LOCK_INET | SBX_LOCK_UNBROKERED))) return -EINVAL;
    /* Exec through the broker and the helper: needs both, and the broker's decisions (not passthrough's). */
    int exec = (options->flags & SBX_LOCK_EXEC) != 0;
    if (exec && (unbrokered || pass || !options->exec_helper || !options->child_library ||
                 options->child_library[0] != '/' || strnlen(options->child_library, SBX_PATH_MAX) == SBX_PATH_MAX)) {
        return -EINVAL;
    }
    if (unbrokered) broker_fd = -1;
    else if (broker_fd < 0) return -EBADF;
    if (options->claim_count > SBX_CLAIMS_MAX || (options->claim_count && !options->claims)) return -EINVAL;
    for (unsigned k = 0; k < options->claim_count; k++) {
        const char *claim = options->claims[k];
        if (!claim || claim[0] != '/' || strnlen(claim, SBX_PATH_MAX) == SBX_PATH_MAX) return -EINVAL;
    }
    if (options->sealed_count > SBX_SEALED_MAX || (options->sealed_count && !options->sealed_fds)) return -EINVAL;
    if (options->own_open_count > SBX_OWN_OPENS_MAX || (options->own_open_count && !options->own_opens)) return -EINVAL;
    if (options->limit_count > SBX_LIMITS_MAX || (options->limit_count && !options->limits)) return -EINVAL;
    for (unsigned k = 0; k < options->sealed_count; k++) {
        if (options->sealed_fds[k] < 0 || options->sealed_fds[k] == broker_fd) return -EINVAL;
    }
    /* A thread that has SIGSYS blocked would kill the process on its first trapped call. */
    if (!unbrokered) {
        /*
         * A thread on its way out can still be listed with its last mask, in
         * a state that is not yet Z or X, for a while after pthread_join on a
         * slow machine (the API 28 emulator failed this way at random).
         * Only a thread that stays blocked is a reason to refuse.
         */
        int blocked = sigsys_blocked_somewhere();
        for (int tries = 0; blocked && tries < 20; tries++) {
            usleep(5000);
            blocked = sigsys_blocked_somewhere();
        }
        if (blocked) return -EDEADLK;
    }
    /* So would a handler whose mask blocks it, for any trapped call made while it runs. */
    if (!unbrokered) open_sigsys_in_handlers();
    int helper = -1;
    if (exec) {
        helper = open(options->exec_helper, O_RDONLY | O_CLOEXEC);
        if (helper < 0) return -errno;
        int mapped = map_trampoline();
        if (mapped != 0) {
            close(helper);
            return mapped;
        }
    }
    int built = build_filter(options->flags, getpid(), options->sealed_fds, options->sealed_count);
    if (built != 0) {
        if (helper >= 0) close(helper);
        return built;
    }
    if (unbrokered) {
        /* Nothing is forwarded, so no handler and no current directory to keep. */
        int limited = apply_limits(options);
        if (limited != 0) { if (helper >= 0) close(helper); return limited; }
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -errno;
        struct sock_fprog program = {.len = filter_length, .filter = filter};
        long synced = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, install, &program);
        if (synced != 0) return synced > 0 ? -EBUSY : -errno;
        locked = 1;
        return 0;
    }
    int directory = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        int error = -errno;
        if (helper >= 0) close(helper);
        return error;
    }
    broker = broker_fd;
    cwd = directory;
    unsigned locals_before = __atomic_load_n(&local_count, __ATOMIC_ACQUIRE);
    for (unsigned i = 0; i < options->own_open_count; i++) {
        const char *path = options->own_opens[i];
        if (!path || path[0] != '/') continue;
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) continue;
        if (add_local(path, fd, SBX_READ | SBX_WRITE | LOCAL_DEVICE) != 0) {
            close(fd);
            continue;
        }
        /* The entry's own descriptor answers stat, access and duplicates; the spares go to opens. */
        int entry = local_index(path);
        for (unsigned s = 0; entry >= 0 && s < OWN_OPEN_SPARES && spare_count < sizeof(spares) / sizeof(spares[0]); s++) {
            int spare = open(path, O_RDWR | O_CLOEXEC);
            if (spare < 0) break;
            spares[spare_count].path = locals[entry].path;
            spares[spare_count].fd = spare;
            spares[spare_count].taken = 0;
            spare_count++;
        }
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
    unix_mode = (options->flags & SBX_LOCK_UNIX) != 0;
    lock_flags = options->flags;
    if (exec) {
        helper_fd = helper;
        snprintf(child_library, sizeof(child_library), "%s", options->child_library);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = on_sigsys;
    /*
     * SA_NODEFER: SIGSYS stays deliverable while this handler runs. Without
     * it the kernel blocks SIGSYS for the handler's duration, and a trapped
     * call made meanwhile by another signal's handler on the same thread
     * (ART's signal chain calls sigprocmask, which traps) kills the process
     * with signal 31. Such a call now enters this handler again: each
     * request has its own answer socket, the handler takes no lock, and
     * errno is kept per entry.
     */
    action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&action.sa_mask);
    if (error != 0) {
        /* Nothing installed yet. */
    } else if ((error = apply_limits(options)) != 0) {
        /* The rlimits were refused; nothing is installed yet (A-18). */
    } else if (sigaction(SIGSYS, &action, &previous) != 0) {
        error = -errno;
    } else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        error = -errno;
    } else {
        struct sock_fprog program = {.len = filter_length, .filter = filter};
        long synced = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, install, &program);
        if (synced == 0) {
            locked = 1;
            struct sbx_trace_header *ring = __atomic_load_n(&trace_ring, __ATOMIC_ACQUIRE);
            if (ring) __atomic_store_n(&ring->locked, 1, __ATOMIC_RELEASE);
            return 0;
        }
        /* A positive result names a thread that could not be synchronised: a lockdown that misses threads is none. */
        error = synced > 0 ? -EBUSY : -errno;
    }
    if (error != -ENOMEM) sigaction(SIGSYS, &previous, NULL);
    if (helper >= 0) close(helper);
    helper_fd = -1;
    drop_locals_from(locals_before);
    free_claims();
    close(directory);
    broker = -1;
    cwd = -1;
    return error;
}

int sbx_adopt(unsigned flags, int broker_fd, int cwd_fd, int exec_helper_fd, const char *library) {
    if (locked) return -EALREADY;
    if (!(flags & SBX_LOCK_EXEC) || (flags & (SBX_LOCK_UNBROKERED | SBX_LOCK_PASSTHROUGH))) return -EINVAL;
    if (broker_fd < 0 || cwd_fd < 0 || exec_helper_fd < 0) return -EBADF;
    if (!library || library[0] != '/' || strnlen(library, SBX_PATH_MAX) == SBX_PATH_MAX) return -EINVAL;
    /* The filter the exec kept answers the probe; without it nothing here is confined, so nothing is claimed. */
    errno = 0;
    if (prctl(SBX_EXEC_PROBE, 0, 0, 0, 0) != -1 || errno != ENOTRECOVERABLE) return -EPERM;
    int mapped = map_trampoline();
    if (mapped != 0) return mapped;
    fcntl(cwd_fd, F_SETFD, FD_CLOEXEC);
    fcntl(exec_helper_fd, F_SETFD, FD_CLOEXEC);
    broker = broker_fd;
    cwd = cwd_fd;
    helper_fd = exec_helper_fd;
    snprintf(child_library, sizeof(child_library), "%s", library);
    passthrough = 0;
    unix_mode = (flags & SBX_LOCK_UNIX) != 0;
    lock_flags = flags;
    /*
     * The full handler replaces sbx-exec's minimal one, through the
     * trampoline, which the filter allows with SBX_LOCK_EXEC. Not through
     * libc's sigaction: that traps, and both handlers refuse a new SIGSYS
     * handler.
     */
    struct kernel_sigaction action;
    memset(&action, 0, sizeof(action));
    action.handler = (void *) on_sigsys;
    action.flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
#ifdef __x86_64__
    action.flags |= 0x04000000; /* SA_RESTORER: x86_64 returns from a handler only through one */
    action.restorer = (void *) sbx_restorer;
#endif
    long installed = through(__NR_rt_sigaction, SIGSYS, (long) &action, 0, sizeof(uint64_t), 0, 0);
    if (installed != 0) {
        int error = (int) installed;
        broker = -1;
        cwd = -1;
        helper_fd = -1;
        return error;
    }
    locked = 1;
    return 0;
}
