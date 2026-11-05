/*
 * What sbx-exec (src/exec_helper.c) and the library share: the wire
 * protocol's structures, and the trampoline page the filter recognises by
 * instruction pointer, at one fixed address so that check holds in every
 * image of a tree (docs/design.md, "SBX_LOCK_EXEC and sbx-exec").
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_EXEC_SHARED_H
#define SBX_EXEC_SHARED_H

#include "protocol.h"

/*
 * The path calls the library's filter sends to the broker (lockdown.c,
 * emit_paths), one table: X(name) for each, named as in __NR_name. renameat,
 * which arm64 has, is apart from x86_64's older forms
 * (SBX_BROKERED_LEGACY_CALLS), which arm64 lacks.
 */
#define SBX_BROKERED_CALLS(X) \
    X(openat) X(newfstatat) X(faccessat) X(faccessat2) X(readlinkat) X(mkdirat) X(unlinkat) X(renameat2) \
    X(statfs) X(chdir) X(fchdir) X(getcwd) X(fchmodat)
#define SBX_BROKERED_LEGACY_CALLS(X) \
    X(open) X(creat) X(stat) X(lstat) X(access) X(readlink) X(mkdir) X(unlink) X(rmdir) X(rename) X(chmod)

/*
 * The calls sbx-exec's own handler routes to the broker while the loader
 * runs (exec_helper.c, dispatch); everything else waits for the full
 * handler. It must stay a subset of the library's (#767): sbx_test checks it.
 */
#define SBXE_HELPER_CALLS(X) X(openat) X(newfstatat) X(faccessat) X(faccessat2) X(readlinkat) X(statfs) X(getcwd)
#define SBXE_HELPER_LEGACY_CALLS(X) X(open) X(stat) X(lstat) X(access) X(readlink)

/* The trap data of a brokered call (lockdown.c's SBX_TRAP_DATA). */
#define SBXE_TRAP_DATA 0x5b0

/* The kernel's struct stat and struct statfs, as the broker sends them. */
#if defined(__x86_64__)
#define SBXE_STAT_SIZE 144
#else
#define SBXE_STAT_SIZE 128
#endif
#define SBXE_STATFS_SIZE 120

/*
 * The trampoline page: just below the helper's own image (linked 256 MB
 * above it, CMakeLists.txt) and above where programs, Wine's preloader and
 * Box64 map themselves. On arm64 it is inside a 39-bit address space and
 * under AddressSanitizer's shadow, which starts at 64 GB there. On x86_64
 * that shadow covers 0x7fff8000 to 0x10007fff7fff, and the low 2 GB are
 * Wine's, so the page is in the sanitizer's high application range: a
 * sanitized program the helper loads must be able to map its shadow.
 */
#if defined(__x86_64__)
#define SBXE_TRAMPOLINE_ADDRESS 0x200000000000UL
#else
#define SBXE_TRAMPOLINE_ADDRESS 0x5b0000000UL
#endif
/*
 * The code starts 64 bytes into the page, so the word before it is mapped:
 * clang's -fsanitize=function reads a signature there before an indirect
 * call, and finds none.
 */
#define SBXE_TRAMPOLINE_ENTRY (SBXE_TRAMPOLINE_ADDRESS + 64)

/*
 * sbxe_trampoline(nr, a0..a5) makes system call nr; the filter recognises
 * the address just after its syscall instruction (sbxe_trampoline_after,
 * as an offset from sbxe_trampoline_start, copied to the fixed page).
 */
#if defined(__x86_64__)
#define SBXE_TRAMPOLINE_ASM                                                   \
    __asm__(".text\n"                                                         \
            ".p2align 4\n"                                                    \
            ".globl sbxe_trampoline_start\n.hidden sbxe_trampoline_start\n"   \
            "sbxe_trampoline_start:\n"                                        \
            "  mov %rdi, %rax\n  mov %rsi, %rdi\n  mov %rdx, %rsi\n"          \
            "  mov %rcx, %rdx\n  mov %r8, %r10\n  mov %r9, %r8\n"             \
            "  mov 8(%rsp), %r9\n  syscall\n"                                 \
            ".globl sbxe_trampoline_after\n.hidden sbxe_trampoline_after\n"   \
            "sbxe_trampoline_after:\n  ret\n"                                 \
            ".globl sbxe_trampoline_end\n.hidden sbxe_trampoline_end\n"       \
            "sbxe_trampoline_end:\n");
#elif defined(__aarch64__)
#define SBXE_TRAMPOLINE_ASM                                                   \
    __asm__(".text\n"                                                         \
            ".p2align 4\n"                                                    \
            ".globl sbxe_trampoline_start\n.hidden sbxe_trampoline_start\n"   \
            "sbxe_trampoline_start:\n"                                        \
            "  mov x8, x0\n  mov x0, x1\n  mov x1, x2\n  mov x2, x3\n"        \
            "  mov x3, x4\n  mov x4, x5\n  mov x5, x6\n  svc #0\n"            \
            ".globl sbxe_trampoline_after\n.hidden sbxe_trampoline_after\n"   \
            "sbxe_trampoline_after:\n  ret\n"                                 \
            ".globl sbxe_trampoline_end\n.hidden sbxe_trampoline_end\n"       \
            "sbxe_trampoline_end:\n");
#endif

#endif
