/*
 * A libFuzzer target for the broker's request path (review finding A-09).
 *
 * It includes broker.c so it can reach the static serve_one, and feeds it
 * fuzzer bytes as a request: struct sbx_request followed by the body. The
 * policy grants one throwaway directory and nothing else -- no network and no
 * signal tree -- so the fuzzer exercises parsing, validation and path
 * resolution without making a connection, sending a signal, or touching a
 * file outside its temporary directory. Build with
 * -DSBX_FUZZ=ON under clang; link flags add -fsanitize=fuzzer,address.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "broker.c"

#include <stdint.h>
#include <stdlib.h>

static struct sbx_policy *policy;
static int root_fd = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    char template[256];
    const char *tmp = getenv("TMPDIR");
    snprintf(template, sizeof(template), "%s/sbx-fuzz-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    const char *base = mkdtemp(template);
    if (!base) base = ".";
    policy = sbx_policy_new();
    sbx_policy_add(policy, base, SBX_READ | SBX_WRITE);
    root_fd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!policy || size < sizeof(struct sbx_request)) return 0;
    struct sbx_request request;
    memcpy(&request, data, sizeof(request));
    /*
     * SBX_SIGNAL is the one op that makes a real, arbitrary-target syscall
     * (kill). signal_one correctly lets a process signal itself, and the
     * sender here is this fuzzer process -- libFuzzer, which instruments the
     * "target == sender" comparison, learns this pid and drives a self-kill,
     * terminating the run. That is the broker behaving correctly, not a bug,
     * so skip the op rather than let the harness signal itself or other
     * processes on the machine. Every other op stays inside the throwaway
     * directory or is refused (no network grant).
     */
    if (request.op == SBX_SIGNAL) return 0;
    const char *body = (const char *) data + sizeof(request);
    size_t body_len = size - sizeof(request);

    /* fds[0] is the answer socket; serve_one replies on it (non-blocking). */
    int answer[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, answer) != 0) return 0;
    int fds[3];
    int fd_count = 0;
    fds[fd_count++] = answer[1];
    /*
     * When the request claims a directory descriptor, hand over the throwaway
     * root so the relative-path code runs and stays inside it. A duplicate so
     * serve_loop's close of each fd does not take root_fd.
     */
    int dir1 = -1, dir2 = -1;
    if (request.dirfd_sent && root_fd >= 0 && fd_count < 3) {
        dir1 = dup(root_fd);
        if (dir1 >= 0) fds[fd_count++] = dir1;
    }
    if (request.dirfd2_sent && root_fd >= 0 && fd_count < 3) {
        dir2 = dup(root_fd);
        if (dir2 >= 0) fds[fd_count++] = dir2;
    }

    serve_one(policy, &request, body, body_len, fds, fd_count, getpid(), NULL);

    close(answer[0]);
    close(answer[1]);
    if (dir1 >= 0) close(dir1);
    if (dir2 >= 0) close(dir2);
    return 0;
}
