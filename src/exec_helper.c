/*
 * sbx-exec: how a confined image runs another one (SBX_LOCK_EXEC).
 *
 * The kernel keeps the seccomp filter across exec but resets the SIGSYS
 * handler, and the next image's dynamic linker opens its libraries by
 * path before any constructor could install one: every such open would
 * trap with no handler and kill the process. So the handler of the image
 * that called execve, once the broker has allowed the target, executes
 * this program instead. It is static and freestanding (no libc, no
 * interpreter), so it makes no path call before it has a handler of its
 * own. It
 *
 *   1. maps the trampoline page at the fixed address the filter checks;
 *   2. installs a minimal SIGSYS handler that sends the loader's path calls
 *      to the broker on the inherited connection and emulates
 *      rt_sigaction and rt_sigprocmask as the full handler does;
 *   3. maps the target and its interpreter as the kernel would, builds the
 *      new stack (libsbx_child.so first on LD_PRELOAD, SBX_ADOPT=1) and
 *      jumps to the interpreter.
 *
 * libsbx_child.so's constructor then adopts the connection and installs
 * the full handler. Arguments (all decimal):
 *
 *   sbx-exec <broker fd> <cwd fd> <target fd> <flags> <child library> <target path> -- <argv...>
 *
 * The environment is the program's. Fails closed: any error ends the
 * process (exit 127) before the target runs.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#include "exec_shared.h"

#include <stddef.h>
#include <stdint.h>

/* One image, no dynamic linking: every symbol is reached directly, relative to the code. */
#pragma GCC visibility push(hidden)

/* ---- System calls, without libc ---- */

#if defined(__x86_64__)
#define NR_read 0
#define NR_close 3
#define NR_mmap 9
#define NR_mprotect 10
#define NR_munmap 11
#define NR_rt_sigaction 13
#define NR_rt_sigprocmask 14
#define NR_rt_sigreturn 15
#define NR_pread64 17
#define NR_writev 20
#define NR_socketpair 53
#define NR_sendmsg 46
#define NR_recvmsg 47
#define NR_exit_group 231
#define NR_gettid 186
#define NR_openat 257
#define NR_newfstatat 262
#define NR_readlinkat 267
#define NR_faccessat 269
#define NR_faccessat2 439
#define NR_statfs 137
#define NR_getcwd 79
#define NR_chdir 80
#define NR_open 2
#define NR_stat 4
#define NR_lstat 6
#define NR_access 21
#define NR_readlink 89
static inline long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#elif defined(__aarch64__)
#define NR_read 63
#define NR_close 57
#define NR_mmap 222
#define NR_mprotect 226
#define NR_munmap 215
#define NR_rt_sigaction 134
#define NR_rt_sigprocmask 135
#define NR_pread64 67
#define NR_writev 66
#define NR_socketpair 199
#define NR_sendmsg 211
#define NR_recvmsg 212
#define NR_exit_group 94
#define NR_gettid 178
#define NR_openat 56
#define NR_newfstatat 79
#define NR_readlinkat 78
#define NR_faccessat 48
#define NR_faccessat2 439
#define NR_statfs 43
#define NR_getcwd 17
#define NR_chdir 49
static inline long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
#else
#error "sbx-exec: x86_64 and aarch64 only"
#endif

#define sys3(n, a, b, c) sys6(n, (long) (a), (long) (b), (long) (c), 0, 0, 0)
#define sys4(n, a, b, c, d) sys6(n, (long) (a), (long) (b), (long) (c), (long) (d), 0, 0)

/* The compiler may call these even here. */
void *memcpy(void *to, const void *from, size_t n) {
    unsigned char *t = to;
    const unsigned char *f = from;
    while (n--) *t++ = *f++;
    return to;
}
void *memset(void *to, int c, size_t n) {
    unsigned char *t = to;
    while (n--) *t++ = (unsigned char) c;
    return to;
}
static size_t length_of(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static int same_prefix(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return 0;
    }
    return 1;
}

__attribute__((noreturn)) static void die(const char *why) {
    static const char head[] = "sbx-exec: ";
    struct { const void *base; size_t length; } parts[3] = {
        {head, sizeof(head) - 1}, {why, length_of(why)}, {"\n", 1}};
    sys3(NR_writev, 2, parts, 3);
    sys3(NR_exit_group, 127, 0, 0);
    __builtin_unreachable();
}

static long parse_number(const char *s) {
    long n = 0;
    if (!*s) die("a bad number in the arguments");
    for (; *s; s++) {
        if (*s < '0' || *s > '9') die("a bad number in the arguments");
        n = n * 10 + (*s - '0');
    }
    return n;
}

/* ---- The minimal handler: the loader's path calls, through the broker ---- */

static int broker_fd = -1, cwd_fd = -1;

struct iov { void *base; size_t length; };
struct message {
    void *name;
    unsigned name_length;
    struct iov *iov;
    size_t iov_length;
    void *control;
    size_t control_length;
    unsigned flags;
};
struct control_header { size_t length; int level; int type; };
#define SOL_SOCKET_ 1
#define SCM_RIGHTS_ 1
#define AF_UNIX_ 1
#define SOCK_SEQPACKET_ 5
#define SOCK_CLOEXEC_ 02000000
#define MSG_NOSIGNAL_ 0x4000
#define MSG_CMSG_CLOEXEC_ 0x40000000
#define AT_FDCWD_ (-100)
#define AT_SYMLINK_NOFOLLOW_ 0x100
#define AT_EMPTY_PATH_ 0x1000
#define O_CLOEXEC_ 02000000

/* One request and its reply, as lockdown.c's exchange makes them. */
static long exchange(struct sbxe_request *request, int dirfd, const char *path, size_t path_length,
                     void *out, size_t out_length, int *passed) {
    *passed = -1;
    int answer[2];
    long made = sys4(NR_socketpair, AF_UNIX_, SOCK_SEQPACKET_ | SOCK_CLOEXEC_, 0, answer);
    if (made < 0) return made;
    int fds[2] = {answer[1], dirfd};
    int count = dirfd >= 0 ? 2 : 1;
    struct iov parts[2] = {{request, sizeof(*request)}, {(void *) path, path_length}};
    union {
        char buffer[sizeof(struct control_header) + 2 * sizeof(int) + 8];
        struct control_header align;
    } control;
    memset(&control, 0, sizeof(control));
    control.align.length = sizeof(struct control_header) + (size_t) count * sizeof(int);
    control.align.level = SOL_SOCKET_;
    control.align.type = SCM_RIGHTS_;
    memcpy(control.buffer + sizeof(struct control_header), fds, (size_t) count * sizeof(int));
    struct message message = {0, 0, parts, 2, control.buffer, (sizeof(struct control_header) + (size_t) count * sizeof(int) + 7) & ~(size_t) 7, 0};
    long sent = sys3(NR_sendmsg, broker_fd, &message, MSG_NOSIGNAL_);
    sys3(NR_close, answer[1], 0, 0);
    if (sent < 0) {
        sys3(NR_close, answer[0], 0, 0);
        return -5; /* EIO */
    }
    struct sbxe_reply reply;
    memset(&reply, 0, sizeof(reply));
    struct iov back[2] = {{&reply, sizeof(reply)}, {out, out_length}};
    union {
        char buffer[sizeof(struct control_header) + sizeof(int) + 8];
        struct control_header align;
    } back_control;
    memset(&back_control, 0, sizeof(back_control));
    struct message answer_message = {0, 0, back, out_length ? 2 : 1, back_control.buffer, sizeof(back_control.buffer), 0};
    long received = sys3(NR_recvmsg, answer[0], &answer_message, MSG_CMSG_CLOEXEC_);
    sys3(NR_close, answer[0], 0, 0);
    if (answer_message.control_length >= sizeof(struct control_header) + sizeof(int) &&
        back_control.align.level == SOL_SOCKET_ && back_control.align.type == SCM_RIGHTS_) {
        memcpy(passed, back_control.buffer + sizeof(struct control_header), sizeof(int));
    }
    if (received < (long) sizeof(reply)) {
        if (*passed >= 0) sys3(NR_close, *passed, 0, 0);
        *passed = -1;
        return -5;
    }
    return (long) reply.result;
}

static long forward(unsigned op, int dirfd, const char *path, int flags, unsigned mode, void *out, size_t out_length) {
    if (!path) return -14; /* EFAULT */
    size_t n = 0;
    while (n < SBXE_PATH_MAX && path[n]) n++;
    if (n == SBXE_PATH_MAX) return -36; /* ENAMETOOLONG */
    if (n == 0) return -2;              /* ENOENT */
    struct sbxe_request request;
    memset(&request, 0, sizeof(request));
    request.version = SBXE_PROTOCOL_VERSION;
    request.op = (uint16_t) op;
    request.flags = flags;
    request.mode = mode;
    request.path_len = (uint32_t) n;
    request.tid = (int32_t) sys3(NR_gettid, 0, 0, 0);
    int directory = -1;
    if (path[0] != '/') {
        directory = dirfd == AT_FDCWD_ ? cwd_fd : dirfd;
        request.dirfd_sent = 1;
    }
    int passed;
    long result = exchange(&request, directory, path, n, out, out_length, &passed);
    if (op == SBXE_OP_OPEN && result >= 0) return passed >= 0 ? passed : -5;
    if (passed >= 0) sys3(NR_close, passed, 0, 0);
    return result;
}

/* The kernel's sigaction: the same layout on x86_64 and arm64. */
struct kernel_sigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    uint64_t mask;
};
#define SIGSYS_ 31
#define SIGSYS_BIT_ (1ULL << (SIGSYS_ - 1))
#define SA_SIGINFO_ 4
#define SA_NODEFER_ 0x40000000
#define SA_RESTORER_ 0x04000000

static long trampoline(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    typedef long (*call_fn)(long, long, long, long, long, long, long);
    return ((call_fn) SBXE_TRAMPOLINE_ADDRESS)(nr, a0, a1, a2, a3, a4, a5);
}

/* rt_sigaction with SIGSYS left out of the new handler's mask (lockdown.c, sigaction_call). */
static long sigaction_call(long signal_number, const struct kernel_sigaction *action, void *old, unsigned long size) {
    if (size != sizeof(uint64_t)) return -22;
    if (!action) return trampoline(NR_rt_sigaction, signal_number, 0, (long) old, (long) size, 0, 0);
    struct kernel_sigaction copy = *action;
    copy.mask &= ~SIGSYS_BIT_;
    return trampoline(NR_rt_sigaction, signal_number, (long) &copy, (long) old, (long) size, 0, 0);
}

#if defined(__x86_64__)
struct sigcontext_ { uint64_t r8, r9, r10, r11, r12, r13, r14, r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip; };
struct ucontext_ {
    unsigned long flags;
    void *link;
    struct { void *sp; int flags; size_t size; } stack;
    struct sigcontext_ mcontext;
    char rest[256 - sizeof(struct sigcontext_)];
};
/* The saved mask follows a fixed-size mcontext (23 general registers, fpstate pointer, 8 reserved). */
#define UC_SIGMASK(uc) ((uint64_t *) ((char *) (uc) + 40 + 23 * 8 + 8 + 8 * 8))
#define ARG(uc, i) ((long) ((i) == 0 ? (uc)->mcontext.rdi : (i) == 1 ? (uc)->mcontext.rsi : (i) == 2 ? (uc)->mcontext.rdx \
                    : (i) == 3 ? (uc)->mcontext.r10 : (i) == 4 ? (uc)->mcontext.r8 : (uc)->mcontext.r9))
#define SET_RESULT(uc, v) ((uc)->mcontext.rax = (uint64_t) (v))
#elif defined(__aarch64__)
struct ucontext_ {
    unsigned long flags;
    void *link;
    struct { void *sp; int flags; size_t size; } stack;
    uint64_t sigmask[16]; /* sigset_t padded to 1024 bits */
    struct { uint64_t fault_address; uint64_t regs[31]; uint64_t sp, pc, pstate; } __attribute__((aligned(16))) mcontext;
};
#define UC_SIGMASK(uc) (&(uc)->sigmask[0])
#define ARG(uc, i) ((long) (uc)->mcontext.regs[i])
#define SET_RESULT(uc, v) ((uc)->mcontext.regs[0] = (uint64_t) (v))
#endif

struct siginfo_ { int signo, errno_, code; int pad; void *call_addr; int syscall; unsigned arch; char rest[96]; };
#define SYS_SECCOMP_ 1

static long dispatch(long nr, struct ucontext_ *uc) {
    long a0 = ARG(uc, 0), a1 = ARG(uc, 1), a2 = ARG(uc, 2), a3 = ARG(uc, 3);
    switch (nr) {
    case NR_openat:
        return forward(SBXE_OP_OPEN, (int) a0, (const char *) a1, (int) a2, (unsigned) a3, 0, 0);
    case NR_newfstatat:
        if ((a3 & AT_EMPTY_PATH_) && a1 && ((const char *) a1)[0] == 0) return -38; /* fstat: never trapped */
        return forward(SBXE_OP_STAT, (int) a0, (const char *) a1, (int) (a3 & AT_SYMLINK_NOFOLLOW_), 0, (void *) a2, SBXE_STAT_SIZE);
    case NR_faccessat:
    case NR_faccessat2:
        return forward(SBXE_OP_ACCESS, (int) a0, (const char *) a1, 0, (unsigned) a2, 0, 0);
    case NR_readlinkat:
        if (a3 <= 0) return -22;
        return forward(SBXE_OP_READLINK, (int) a0, (const char *) a1, 0, (unsigned) a3, (void *) a2, (size_t) a3);
    case NR_statfs:
        return forward(SBXE_OP_STATFS, AT_FDCWD_, (const char *) a0, 0, 0, (void *) a1, SBXE_STATFS_SIZE);
    case NR_getcwd:
        if (!a0 || a1 <= 0) return -22;
        return forward(SBXE_OP_GETCWD, AT_FDCWD_, ".", 0, (unsigned) a1, (void *) a0, (size_t) a1);
#if defined(__x86_64__)
    case NR_open:
        return forward(SBXE_OP_OPEN, AT_FDCWD_, (const char *) a0, (int) a1, (unsigned) a2, 0, 0);
    case NR_stat:
    case NR_lstat:
        return forward(SBXE_OP_STAT, AT_FDCWD_, (const char *) a0, nr == NR_lstat ? AT_SYMLINK_NOFOLLOW_ : 0, 0, (void *) a1, SBXE_STAT_SIZE);
    case NR_access:
        return forward(SBXE_OP_ACCESS, AT_FDCWD_, (const char *) a0, 0, (unsigned) a1, 0, 0);
    case NR_readlink:
        if (a2 <= 0) return -22;
        return forward(SBXE_OP_READLINK, AT_FDCWD_, (const char *) a0, 0, (unsigned) a2, (void *) a1, (size_t) a2);
#endif
    case NR_rt_sigaction:
        return sigaction_call(a0, (const struct kernel_sigaction *) a1, (void *) a2, (unsigned long) a3);
    case NR_rt_sigprocmask: {
        /* The call's effect, made on the saved mask the kernel restores, with SIGSYS left open. */
        if ((unsigned long) a3 != sizeof(uint64_t)) return -22;
        uint64_t *saved = UC_SIGMASK(uc);
        uint64_t current = *saved, next = current;
        if (a1) {
            uint64_t asked = *(const uint64_t *) a1;
            if (a0 == 0) next = current | asked;
            else if (a0 == 1) next = current & ~asked;
            else if (a0 == 2) next = asked;
            else return -22;
        }
        if (a2) *(uint64_t *) a2 = current;
        *saved = next & ~SIGSYS_BIT_;
        return 0;
    }
    default:
        return -38; /* ENOSYS: the full handler, once adopted, answers the rest */
    }
}

static void on_sigsys(int signal_number, struct siginfo_ *info, void *context) {
    (void) signal_number;
    struct ucontext_ *uc = context;
    if (info->code != SYS_SECCOMP_ || info->errno_ != SBXE_TRAP_DATA) {
        /* Not ours (another filter's): end as the default action would. */
        die("a system call was refused by another seccomp filter");
    }
    SET_RESULT(uc, dispatch(info->syscall, uc));
}

#if defined(__x86_64__)
void sbxe_restorer(void);
__asm__(".text\n.globl sbxe_restorer\n.type sbxe_restorer,@function\nsbxe_restorer:\n  mov $15, %rax\n  syscall\n");
#endif

/* ---- The trampoline page ---- */

extern const char sbxe_trampoline_start[], sbxe_trampoline_end[];
SBXE_TRAMPOLINE_ASM

static void map_trampoline(void) {
    long page = sys6(NR_mmap, SBXE_TRAMPOLINE_ADDRESS, 4096, 3 /* RW */, 0x22 | 0x100000 /* PRIVATE|ANON|FIXED_NOREPLACE */, -1, 0);
    if (page != (long) SBXE_TRAMPOLINE_ADDRESS) {
        /* An image that was itself started through sbx-exec has it already (exec keeps nothing, so not here). */
        die("could not map the trampoline page at its fixed address");
    }
    memcpy((void *) page, sbxe_trampoline_start, (size_t) (sbxe_trampoline_end - sbxe_trampoline_start));
    if (sys3(NR_mprotect, page, 4096, 5 /* R|X */) != 0) die("could not make the trampoline page executable");
}

/* ---- Loading the target and its interpreter ---- */

#define PT_LOAD_ 1
#define PT_INTERP_ 3
#define PT_PHDR_ 6
#define ET_DYN_ 3
typedef struct {
    unsigned char ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} elf_header;
typedef struct {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
} elf_phdr;

struct loaded {
    uint64_t base;   /* load bias */
    uint64_t entry;
    uint64_t phdr;   /* where the program headers are in memory */
    uint16_t phnum;
};

#define PAGE 4096UL
#define PAGE_DOWN(x) ((x) & ~(PAGE - 1))
#define PAGE_UP(x) (((x) + PAGE - 1) & ~(PAGE - 1))

static void read_exactly(int fd, void *into, size_t n, uint64_t offset) {
    long got = sys4(NR_pread64, fd, into, n, offset);
    if (got != (long) n) die("could not read an ELF image");
}

static int protection(uint32_t flags) {
    return ((flags & 4) ? 1 : 0) | ((flags & 2) ? 2 : 0) | ((flags & 1) ? 4 : 0);
}

/* Maps fd as the kernel maps an ELF image; interp (PATH_MAX bytes) receives PT_INTERP's path or "". */
static void load(int fd, struct loaded *out, char *interp) {
    elf_header header;
    read_exactly(fd, &header, sizeof(header), 0);
    if (header.ident[0] != 0x7f || header.ident[1] != 'E' || header.ident[2] != 'L' || header.ident[3] != 'F' ||
        header.ident[4] != 2 /* 64-bit */ || header.phentsize != sizeof(elf_phdr) || header.phnum == 0 ||
        header.phnum > 64) {
        die("not a 64-bit ELF image");
    }
    elf_phdr phdrs[64];
    read_exactly(fd, phdrs, header.phnum * sizeof(elf_phdr), header.phoff);
    uint64_t low = ~0ULL, high = 0, phdr_vaddr = 0;
    int have_phdr = 0;
    if (interp) interp[0] = 0;
    for (int i = 0; i < header.phnum; i++) {
        if (phdrs[i].type == PT_LOAD_) {
            if (PAGE_DOWN(phdrs[i].vaddr) < low) low = PAGE_DOWN(phdrs[i].vaddr);
            if (phdrs[i].vaddr + phdrs[i].memsz > high) high = phdrs[i].vaddr + phdrs[i].memsz;
        } else if (phdrs[i].type == PT_INTERP_ && interp) {
            if (phdrs[i].filesz == 0 || phdrs[i].filesz >= SBXE_PATH_MAX) die("a bad PT_INTERP");
            read_exactly(fd, interp, phdrs[i].filesz, phdrs[i].offset);
            interp[phdrs[i].filesz] = 0;
        } else if (phdrs[i].type == PT_PHDR_) {
            phdr_vaddr = phdrs[i].vaddr;
            have_phdr = 1;
        }
    }
    if (low >= high) die("an ELF image with nothing to load");
    uint64_t span = PAGE_UP(high) - low;
    int dynamic = header.type == ET_DYN_;
    /* Reserve the whole span first, so the segments land together. */
    long reserved = sys6(NR_mmap, dynamic ? 0 : (long) low, (long) span, 0, 0x22 | (dynamic ? 0 : 0x100000), -1, 0);
    if (reserved < 0 || (!dynamic && (uint64_t) reserved != low)) die("could not reserve the image's address range");
    uint64_t bias = (uint64_t) reserved - low;
    for (int i = 0; i < header.phnum; i++) {
        if (phdrs[i].type != PT_LOAD_) continue;
        elf_phdr *p = &phdrs[i];
        uint64_t start = PAGE_DOWN(p->vaddr), offset = PAGE_DOWN(p->offset);
        uint64_t file_end = p->vaddr + p->filesz, mem_end = p->vaddr + p->memsz;
        int prot = protection(p->flags);
        if (p->filesz) {
            long mapped = sys6(NR_mmap, (long) (start + bias), (long) (PAGE_UP(file_end) - start), prot | 2,
                               0x12 /* PRIVATE|FIXED */, fd, (long) offset);
            if (mapped < 0) die("could not map a segment");
            /*
             * The rest of the last file page is zeroed to its end, as the kernel does: past .bss, glibc's
             * loader takes its first allocations from that tail and expects zeros there.
             */
            if (p->flags & 2) memset((void *) (file_end + bias), 0, (size_t) (PAGE_UP(file_end) - file_end));
            if (!(prot & 2)) sys3(NR_mprotect, start + bias, PAGE_UP(file_end) - start, prot);
        }
        if (PAGE_UP(mem_end) > PAGE_UP(file_end)) {
            long anon = sys6(NR_mmap, (long) (PAGE_UP(file_end) + bias), (long) (PAGE_UP(mem_end) - PAGE_UP(file_end)),
                             prot, 0x32 /* PRIVATE|ANON|FIXED */, -1, 0);
            if (anon < 0) die("could not map a segment's .bss");
        }
    }
    out->base = bias;
    out->entry = header.entry + bias;
    out->phnum = header.phnum;
    if (!have_phdr) {
        /* The headers sit in the first segment, at their file offset. */
        for (int i = 0; i < header.phnum; i++) {
            elf_phdr *p = &phdrs[i];
            if (p->type == PT_LOAD_ && header.phoff >= p->offset && header.phoff < p->offset + p->filesz) {
                phdr_vaddr = p->vaddr + (header.phoff - p->offset);
                have_phdr = 1;
                break;
            }
        }
    }
    if (!have_phdr) die("an ELF image whose program headers are not loaded");
    out->phdr = phdr_vaddr + bias;
}

/* ---- The new stack ---- */

#define AT_NULL_ 0
#define AT_PHDR_ 3
#define AT_PHENT_ 4
#define AT_PHNUM_ 5
#define AT_PAGESZ_ 6
#define AT_BASE_ 7
#define AT_FLAGS_ 8
#define AT_ENTRY_ 9
#define AT_UID_ 11
#define AT_EUID_ 12
#define AT_GID_ 13
#define AT_EGID_ 14
#define AT_PLATFORM_ 15
#define AT_HWCAP_ 16
#define AT_CLKTCK_ 17
#define AT_SECURE_ 23
#define AT_RANDOM_ 25
#define AT_HWCAP2_ 26
#define AT_EXECFN_ 31
#define AT_SYSINFO_EHDR_ 33
#define AT_MINSIGSTKSZ_ 51

#define STACK_SIZE (8UL << 20)
#define ENV_MAX 1024

struct builder {
    char *strings;  /* grows down from the top */
    char *floor;
};

static char *put(struct builder *b, const char *s) {
    size_t n = length_of(s) + 1;
    if (b->strings - n < b->floor) die("arguments and environment too large");
    b->strings -= n;
    memcpy(b->strings, s, n);
    return b->strings;
}

static char *put_two(struct builder *b, const char *a, const char *c) {
    size_t n = length_of(a), m = length_of(c);
    if (b->strings - (n + m + 1) < b->floor) die("arguments and environment too large");
    b->strings -= n + m + 1;
    memcpy(b->strings, a, n);
    memcpy(b->strings + n, c, m + 1);
    return b->strings;
}

static void number_text(char *out, long n) {
    char digits[24];
    int k = 0;
    if (n == 0) digits[k++] = '0';
    while (n > 0) {
        digits[k++] = (char) ('0' + n % 10);
        n /= 10;
    }
    while (k) *out++ = digits[--k];
    *out = 0;
}

__attribute__((noreturn)) static void jump(uint64_t entry, uint64_t *sp) {
#if defined(__x86_64__)
    /* rdx (the atexit function, none) is cleared last, so neither input may live in it. */
    __asm__ volatile("mov %0, %%rsp\n xor %%edx, %%edx\n jmp *%1\n" : : "r"(sp), "r"(entry) : "rdx", "memory");
#elif defined(__aarch64__)
    __asm__ volatile("mov sp, %0\n mov x0, xzr\n br %1\n" : : "r"(sp), "r"(entry) : "x0", "memory");
#endif
    __builtin_unreachable();
}

__attribute__((noreturn, used)) void sbxe_main(long *initial) {
    long argc = initial[0];
    char **argv = (char **) (initial + 1);
    char **envp = argv + argc + 1;
    char **cursor = envp;
    while (*cursor) cursor++;
    uint64_t *auxv = (uint64_t *) (cursor + 1);
    if (argc < 8 || !argv[7] || argv[7][0] != '-' || argv[7][1] != '-' || argv[7][2] != 0) {
        die("usage: sbx-exec <broker fd> <cwd fd> <target fd> <flags> <child library> <target path> -- <argv...>");
    }
    broker_fd = (int) parse_number(argv[1]);
    cwd_fd = (int) parse_number(argv[2]);
    int target_fd = (int) parse_number(argv[3]);
    const char *flags = argv[4];
    const char *child_library = argv[5];
    const char *target_path = argv[6];
    long program_argc = argc - 8;
    char **program_argv = argv + 8;

    map_trampoline();
    struct kernel_sigaction action;
    memset(&action, 0, sizeof(action));
    action.handler = (void *) on_sigsys;
    /*
     * SA_NODEFER, as the full handler: a trapped call made by another
     * signal's handler while this one waits for the broker is a nested entry,
     * not a death by SIGSYS. Each forward has its own answer socket and keeps
     * everything on the stack, so nesting is safe.
     */
    action.flags = SA_SIGINFO_ | SA_NODEFER_;
#if defined(__x86_64__)
    action.flags |= SA_RESTORER_;
    action.restorer = (void *) sbxe_restorer;
#endif
    if (sys4(NR_rt_sigaction, SIGSYS_, &action, 0, 8) != 0) die("could not install the minimal handler");

    /* The target, then its interpreter, opened through the broker like any path. */
    char interp_path[SBXE_PATH_MAX];
    struct loaded target, interp;
    load(target_fd, &target, interp_path);
    sys3(NR_close, target_fd, 0, 0);
    uint64_t start = target.entry, base = 0;
    if (interp_path[0]) {
        long interp_fd = forward(SBXE_OP_OPEN, AT_FDCWD_, interp_path, O_CLOEXEC_, 0, 0, 0);
        if (interp_fd < 0) die("the broker refused the target's interpreter");
        load((int) interp_fd, &interp, 0);
        sys3(NR_close, interp_fd, 0, 0);
        start = interp.entry;
        base = interp.base;
    }

    /* The new stack: strings at the top, then the vectors below them. */
    long stack = sys6(NR_mmap, 0, (long) STACK_SIZE, 3, 0x22 | 0x20000 /* MAP_STACK */, -1, 0);
    if (stack < 0) die("could not map the new stack");
    struct builder b = {(char *) stack + STACK_SIZE, (char *) stack + STACK_SIZE / 2};
    uint64_t *random = 0;
    for (uint64_t *a = auxv; a[0] != AT_NULL_; a += 2) {
        if (a[0] == AT_RANDOM_) random = (uint64_t *) a[1];
    }
    b.strings -= 16;
    char *random_copy = b.strings;
    if (random) memcpy(random_copy, random, 16);
    char *execfn = put(&b, target_path);
    char *new_argv[256];
    if (program_argc > 255) die("too many arguments");
    for (long i = 0; i < program_argc; i++) new_argv[i] = put(&b, program_argv[i]);
    char *new_envp[ENV_MAX];
    long envc = 0;
    const char *old_preload = 0;
    for (char **e = envp; *e; e++) {
        if (envc >= ENV_MAX - 8) die("too many environment variables");
        if (same_prefix(*e, "LD_PRELOAD=")) {
            old_preload = *e + 11;
            continue;
        }
        /* Replaced below; SBX_EXEC_HELPER and the rest pass on for the image's own execs. */
        if (same_prefix(*e, "SBX_BROKER") || same_prefix(*e, "SBX_TOKEN=") || same_prefix(*e, "SBX_CWD_FD=") ||
            same_prefix(*e, "SBX_FLAGS=") || same_prefix(*e, "SBX_ADOPT=")) {
            continue;
        }
        new_envp[envc++] = put(&b, *e);
    }
    /* libsbx_child.so first, so its constructor adopts before anything else of the image runs. */
    if (old_preload && old_preload[0]) {
        char joined[SBXE_PATH_MAX * 2];
        size_t n = length_of(child_library), m = length_of(old_preload);
        if (n + m + 2 > sizeof(joined)) die("LD_PRELOAD too long");
        memcpy(joined, child_library, n);
        joined[n] = ':';
        memcpy(joined + n + 1, old_preload, m + 1);
        new_envp[envc++] = put_two(&b, "LD_PRELOAD=", joined);
    } else {
        new_envp[envc++] = put_two(&b, "LD_PRELOAD=", child_library);
    }
    char number[24];
    number_text(number, broker_fd);
    new_envp[envc++] = put_two(&b, "SBX_BROKER_FD=", number);
    number_text(number, cwd_fd);
    new_envp[envc++] = put_two(&b, "SBX_CWD_FD=", number);
    new_envp[envc++] = put_two(&b, "SBX_FLAGS=", flags);
    new_envp[envc++] = put(&b, "SBX_ADOPT=1");

    /* Vectors, 16-byte aligned: argc, argv, NULL, envp, NULL, auxv. */
    uint64_t aux[2 * 32];
    int k = 0;
#define AUX(type, value) do { aux[k++] = (type); aux[k++] = (uint64_t) (value); } while (0)
    AUX(AT_PHDR_, target.phdr);
    AUX(AT_PHENT_, sizeof(elf_phdr));
    AUX(AT_PHNUM_, target.phnum);
    AUX(AT_BASE_, base);
    AUX(AT_ENTRY_, target.entry);
    AUX(AT_EXECFN_, execfn);
    AUX(AT_SECURE_, 0);
    if (random) AUX(AT_RANDOM_, random_copy);
    for (uint64_t *a = auxv; a[0] != AT_NULL_ && k < 2 * 30; a += 2) {
        switch (a[0]) {
        case AT_PAGESZ_: case AT_FLAGS_: case AT_UID_: case AT_EUID_: case AT_GID_: case AT_EGID_:
        case AT_HWCAP_: case AT_HWCAP2_: case AT_CLKTCK_: case AT_SYSINFO_EHDR_: case AT_PLATFORM_:
        case AT_MINSIGSTKSZ_:
            AUX(a[0], a[1]);
            break;
        default:
            break;
        }
    }
    AUX(AT_NULL_, 0);
#undef AUX
    size_t words = 1 + (size_t) program_argc + 1 + (size_t) envc + 1 + (size_t) k;
    uint64_t *sp = (uint64_t *) (((uint64_t) b.strings - words * 8) & ~15ULL);
    uint64_t *w = sp;
    *w++ = (uint64_t) program_argc;
    for (long i = 0; i < program_argc; i++) *w++ = (uint64_t) new_argv[i];
    *w++ = 0;
    for (long i = 0; i < envc; i++) *w++ = (uint64_t) new_envp[i];
    *w++ = 0;
    for (int i = 0; i < k; i++) *w++ = aux[i];
    jump(start, sp);
}

#if defined(__x86_64__)
__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        "  xor %ebp, %ebp\n  mov %rsp, %rdi\n  and $-16, %rsp\n  call sbxe_main\n  hlt\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n.type _start,%function\n_start:\n"
        "  mov x29, xzr\n  mov x30, xzr\n  mov x0, sp\n  bl sbxe_main\n  brk #0\n");
#endif
