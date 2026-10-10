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
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
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

/* SECCOMP_RET_DATA of our traps, which tells them from anyone else's SIGSYS. */
#define SBX_TRAP_DATA 0x5b0

static int broker = -1;
static int locked;
/* The confined process's current directory: it cannot chdir for real, since it may not open what it enters. */
static int cwd = -1;
static struct sigaction previous;

static int current_directory(void) { return __atomic_load_n(&cwd, __ATOMIC_ACQUIRE); }

static long forward(uint32_t op, int dirfd, const char *path, int dirfd2, const char *path2,
                    int flags, uint32_t mode, void *out, size_t out_len) {
    if (path == NULL || (op == SBX_RENAME && path2 == NULL)) return -EFAULT;
    size_t length = strnlen(path, SBX_PATH_MAX);
    size_t length2 = op == SBX_RENAME ? strnlen(path2, SBX_PATH_MAX) : 0;
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

static long change_directory(const char *path) {
    long fd = forward(SBX_CHDIR, AT_FDCWD, path, 0, NULL, 0, 0, NULL, 0);
    if (fd < 0) return fd;
    set_directory((int) fd);
    return 0;
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

static long get_directory(char *buffer, size_t size) {
    if (buffer == NULL || size == 0) return -EINVAL;
    long n = forward(SBX_GETCWD, AT_FDCWD, ".", 0, NULL, 0, (uint32_t) size, buffer, size);
    if (n < 0) return n;
    return n; /* the broker counts the terminating NUL, as the kernel does */
}

static long dispatch(long nr, ucontext_t *uc) {
    long a0 = ARG(uc, 0), a1 = ARG(uc, 1), a2 = ARG(uc, 2), a3 = ARG(uc, 3), a4 = ARG(uc, 4);
    switch (nr) {
    case __NR_openat:
        return forward(SBX_OPEN, (int) a0, (const char *) a1, 0, NULL, (int) a2, (uint32_t) a3, NULL, 0);
    case __NR_newfstatat: {
        const char *path = (const char *) a1;
        if ((a3 & AT_EMPTY_PATH) && path != NULL && path[0] == '\0') {
            return syscall(__NR_fstat, (int) a0, (void *) a2) == 0 ? 0 : -errno;
        }
        return forward(SBX_STAT, (int) a0, path, 0, NULL, (int) (a3 & AT_SYMLINK_NOFOLLOW), 0,
                       (void *) a2, sizeof(struct stat));
    }
    case __NR_faccessat:
    case __NR_faccessat2:
        return forward(SBX_ACCESS, (int) a0, (const char *) a1, 0, NULL, 0, (uint32_t) a2, NULL, 0);
    case __NR_readlinkat:
        if (a3 <= 0) return -EINVAL;
        return forward(SBX_READLINK, (int) a0, (const char *) a1, 0, NULL, 0, (uint32_t) a3, (void *) a2,
                       (size_t) a3);
    case __NR_mkdirat:
        return forward(SBX_MKDIR, (int) a0, (const char *) a1, 0, NULL, 0, (uint32_t) a2, NULL, 0);
    case __NR_unlinkat:
        return forward(SBX_UNLINK, (int) a0, (const char *) a1, 0, NULL, (int) (a2 & AT_REMOVEDIR), 0, NULL, 0);
#ifdef __NR_renameat
    case __NR_renameat:
        return forward(SBX_RENAME, (int) a0, (const char *) a1, (int) a2, (const char *) a3, 0, 0, NULL, 0);
#endif
    case __NR_renameat2:
        return forward(SBX_RENAME, (int) a0, (const char *) a1, (int) a2, (const char *) a3, (int) a4, 0, NULL, 0);
    case __NR_statfs:
        return forward(SBX_STATFS, AT_FDCWD, (const char *) a0, 0, NULL, 0, 0, (void *) a1, sizeof(struct statfs));
    case __NR_chdir:
        return change_directory((const char *) a0);
    case __NR_fchdir:
        return change_directory_fd((int) a0);
    case __NR_getcwd:
        return get_directory((char *) a0, (size_t) a1);
#ifdef __NR_open
    case __NR_open:
        return forward(SBX_OPEN, AT_FDCWD, (const char *) a0, 0, NULL, (int) a1, (uint32_t) a2, NULL, 0);
    case __NR_creat:
        return forward(SBX_OPEN, AT_FDCWD, (const char *) a0, 0, NULL, O_CREAT | O_WRONLY | O_TRUNC,
                       (uint32_t) a1, NULL, 0);
    case __NR_stat:
        return forward(SBX_STAT, AT_FDCWD, (const char *) a0, 0, NULL, 0, 0, (void *) a1, sizeof(struct stat));
    case __NR_lstat:
        return forward(SBX_STAT, AT_FDCWD, (const char *) a0, 0, NULL, AT_SYMLINK_NOFOLLOW, 0, (void *) a1,
                       sizeof(struct stat));
    case __NR_access:
        return forward(SBX_ACCESS, AT_FDCWD, (const char *) a0, 0, NULL, 0, (uint32_t) a1, NULL, 0);
    case __NR_readlink:
        if (a2 <= 0) return -EINVAL;
        return forward(SBX_READLINK, AT_FDCWD, (const char *) a0, 0, NULL, 0, (uint32_t) a2, (void *) a1,
                       (size_t) a2);
    case __NR_mkdir:
        return forward(SBX_MKDIR, AT_FDCWD, (const char *) a0, 0, NULL, 0, (uint32_t) a1, NULL, 0);
    case __NR_unlink:
        return forward(SBX_UNLINK, AT_FDCWD, (const char *) a0, 0, NULL, 0, 0, NULL, 0);
    case __NR_rmdir:
        return forward(SBX_UNLINK, AT_FDCWD, (const char *) a0, 0, NULL, AT_REMOVEDIR, 0, NULL, 0);
    case __NR_rename:
        return forward(SBX_RENAME, AT_FDCWD, (const char *) a0, AT_FDCWD, (const char *) a1, 0, 0, NULL, 0);
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

#ifdef SBX_ARCH
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
    /* Brokered. */
    static const unsigned brokered[] = {
        __NR_openat, __NR_newfstatat, __NR_faccessat, __NR_faccessat2, __NR_readlinkat, __NR_mkdirat,
        __NR_unlinkat, __NR_renameat2, __NR_statfs, __NR_chdir, __NR_fchdir, __NR_getcwd,
#ifdef __NR_renameat
        __NR_renameat,
#endif
#ifdef __NR_open
        __NR_open, __NR_creat, __NR_stat, __NR_lstat, __NR_access, __NR_readlink, __NR_mkdir, __NR_unlink,
        __NR_rmdir, __NR_rename,
#endif
    };
    if (!unbrokered) {
        for (size_t i = 0; i < sizeof(brokered) / sizeof(brokered[0]); i++) rule(brokered[i], TRAP);
        /* Callers fall back to the brokered forms. */
        rule(__NR_statx, NOSYS);
        rule(__NR_openat2, NOSYS);
        /* utimensat(fd, NULL, ...) is futimens, on a descriptor; with a path it is refused. */
        jeq(__NR_utimensat, 0, 6);
        load(ARG_LO(1));
        jeq(0, 0, 3);
        load(ARG_HI(1));
        jeq(0, 0, 1);
        ret(ALLOW);
        ret(REFUSE);
    }
    /* clone3 takes its flags in memory a filter cannot read; callers fall back to clone, whose flags it can. */
    rule(__NR_clone3, NOSYS);
    /* A Unix datagram socket for the system log, when asked; no other socket. */
    if (flags & SBX_LOCK_LOG_SOCKET) {
        jeq(__NR_socket, 0, 7);
        load(ARG_LO(0));
        jeq(AF_UNIX, 0, 4);
        load(ARG_LO(1));
        emit((struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf));
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
    /* Refused: other paths (the kernel's own checks decide them when there is no broker). */
    static const unsigned refused_paths[] = {
        __NR_truncate, __NR_linkat, __NR_symlinkat, __NR_mknodat, __NR_fchmodat, __NR_fchownat,
        __NR_inotify_add_watch, __NR_fanotify_mark, __NR_name_to_handle_at, __NR_open_by_handle_at,
        __NR_setxattr, __NR_lsetxattr, __NR_getxattr, __NR_lgetxattr, __NR_listxattr, __NR_llistxattr,
        __NR_removexattr, __NR_lremovexattr,
#ifdef __NR_open
        __NR_link, __NR_symlink, __NR_mknod, __NR_chmod, __NR_chown, __NR_lchown, __NR_utime, __NR_utimes,
        __NR_futimesat, __NR_uselib,
#endif
    };
    if (!unbrokered) {
        for (size_t i = 0; i < sizeof(refused_paths) / sizeof(refused_paths[0]); i++) rule(refused_paths[i], REFUSE);
    }
    /* Refused: reaching past the process. */
    static const unsigned refused[] = {
        __NR_execve, __NR_execveat, __NR_bind, __NR_ptrace, __NR_process_vm_readv, __NR_process_vm_writev,
        __NR_process_madvise, __NR_bpf, __NR_perf_event_open, __NR_io_uring_setup, __NR_io_uring_enter,
        __NR_io_uring_register,
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) rule(refused[i], REFUSE);
    /* connect only for the log's datagram socket, the one socket that can be made; nothing else to connect. */
    if (!(flags & SBX_LOCK_LOG_SOCKET)) rule(__NR_connect, REFUSE);
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
#endif

int sbx_lockdown(int broker_fd, const struct sbx_lockdown_options *options) {
#ifndef SBX_ARCH
    (void) broker_fd;
    (void) options;
    return -ENOSYS;
#else
    if (locked) return -EALREADY;
    struct sbx_lockdown_options none = {0, NULL, 0};
    if (!options) options = &none;
    int unbrokered = (options->flags & SBX_LOCK_UNBROKERED) != 0;
    if (unbrokered) broker_fd = -1;
    else if (broker_fd < 0) return -EBADF;
    if (options->sealed_count > SBX_SEALED_MAX || (options->sealed_count && !options->sealed_fds)) return -EINVAL;
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

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = on_sigsys;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    int error = 0;
    if (sigaction(SIGSYS, &action, &previous) != 0) {
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
    sigaction(SIGSYS, &previous, NULL);
    close(directory);
    broker = -1;
    cwd = -1;
    return error;
#endif
}
