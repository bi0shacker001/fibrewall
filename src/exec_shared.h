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

#define sbxe_request sbx_request
#define sbxe_reply sbx_reply
#define SBXE_PROTOCOL_VERSION SBX_PROTOCOL_VERSION
#define SBXE_PATH_MAX SBX_PATH_MAX
#define SBXE_OP_OPEN SBX_OPEN
#define SBXE_OP_STAT SBX_STAT
#define SBXE_OP_ACCESS SBX_ACCESS
#define SBXE_OP_READLINK SBX_READLINK
#define SBXE_OP_STATFS SBX_STATFS
#define SBXE_OP_GETCWD SBX_GETCWD

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
 * The trampoline page: below the helper's own image (linked at
 * 0x5c0000000) and above where programs, Wine's preloader and Box64 map
 * themselves, inside a 39-bit address space.
 */
#define SBXE_TRAMPOLINE_ADDRESS 0x5b0000000UL

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
