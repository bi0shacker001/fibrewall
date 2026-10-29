/*
 * The confinement contract (include/sbx_contract.h): a dry-run report of
 * what a policy and options would enforce, and a checked lockdown that
 * refuses to install when a required guarantee would be missing. The
 * sandbox review's effective-enforcement report (Droidtop/tracker#651,
 * A-26).
 *
 * Every guarantee bit here is derived from the lockdown flags and options
 * as the filter (src/lockdown.c) and broker (src/broker.c) actually build
 * them. A bit is set only when the mechanism is installed; an unknown is
 * never reported as a guarantee. The mapping is the capability matrix in
 * docs/review/phase0-architecture.md.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx_contract.h"

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- SHA-256 (public-domain style, for the policy digest) ---- */

struct sha256 {
    uint32_t h[8];
    uint64_t length;
    unsigned char block[64];
    size_t fill;
};

static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_round(struct sha256 *s, const unsigned char *p) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t) p[i * 4] << 24 | (uint32_t) p[i * 4 + 1] << 16 | (uint32_t) p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], hh = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
        uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += hh;
}

static void sha256_init(struct sha256 *s) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof(iv));
    s->length = 0;
    s->fill = 0;
}

static void sha256_update(struct sha256 *s, const void *data, size_t n) {
    const unsigned char *p = data;
    s->length += n;
    while (n) {
        size_t take = 64 - s->fill;
        if (take > n) take = n;
        memcpy(s->block + s->fill, p, take);
        s->fill += take;
        p += take;
        n -= take;
        if (s->fill == 64) {
            sha256_round(s, s->block);
            s->fill = 0;
        }
    }
}

static void sha256_final(struct sha256 *s, unsigned char out[32]) {
    uint64_t bits = s->length * 8;
    unsigned char pad = 0x80;
    sha256_update(s, &pad, 1);
    unsigned char zero = 0;
    while (s->fill != 56) sha256_update(s, &zero, 1);
    unsigned char len[8];
    for (int i = 0; i < 8; i++) len[i] = (unsigned char) (bits >> (56 - 8 * i));
    sha256_update(s, len, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char) (s->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char) (s->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char) (s->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char) s->h[i];
    }
}

/* ---- The flag-to-guarantee mapping ---- */

/* The socket flags: any of them means the process can make some socket. */
#define NET_FLAGS (SBX_LOCK_LOG_SOCKET | SBX_LOCK_INET | SBX_LOCK_NET_BROKERED | SBX_LOCK_SOCKETS)

static void digest(const struct sbx_policy *policy, const struct sbx_lockdown_options *o, unsigned char out[32]) {
    struct sha256 s;
    sha256_init(&s);
    uint32_t flags = o->flags;
    sha256_update(&s, &flags, sizeof(flags));
    size_t len = 0;
    unsigned char *image = sbx_policy_serialize(policy, &len);
    if (image) {
        sha256_update(&s, image, len);
        free(image);
    }
    /* Options that shape what the worker holds: own-opened devices, sealed fds, passthrough claims. */
    for (unsigned i = 0; i < o->own_open_count; i++)
        if (o->own_opens && o->own_opens[i]) sha256_update(&s, o->own_opens[i], strlen(o->own_opens[i]) + 1);
    sha256_update(&s, &o->sealed_count, sizeof(o->sealed_count));
    for (unsigned i = 0; i < o->claim_count; i++)
        if (o->claims && o->claims[i]) sha256_update(&s, o->claims[i], strlen(o->claims[i]) + 1);
    sha256_final(&s, out);
}

static void name_bit(uint64_t bit, int residual, char *out, size_t cap) {
    const char *n = "a guarantee";
    if (!residual) {
        switch (bit) {
        case SBX_G_CONFINED_BEFORE_CODE: n = "confined before any worker code (use a confined spawn)"; break;
        case SBX_G_FS_MEDIATED: n = "the file system mediated (not with passthrough or unbrokered)"; break;
        case SBX_G_FS_NO_PREOPENED: n = "no preopened descriptors (not yet enforced)"; break;
        case SBX_G_NET_NONE: n = "no network (a socket flag is set)"; break;
        case SBX_G_NET_MEDIATED: n = "brokered network (SBX_LOCK_NET_BROKERED)"; break;
        case SBX_G_IPC_NONE: n = "no IPC (socketpair and shared memory are always allowed)"; break;
        case SBX_G_IPC_MEDIATED: n = "brokered IPC (not yet built)"; break;
        case SBX_G_SIGNALS_SELF: n = "signals to self only (SBX_LOCK_SIGNALS opens all of the uid)"; break;
        case SBX_G_EXEC_NONE: n = "no exec (SBX_LOCK_EXEC is set)"; break;
        case SBX_G_EXEC_CONFINED: n = "confined exec (SBX_LOCK_EXEC)"; break;
        case SBX_G_CHILDREN_NONE: n = "no child processes (fork is allowed on this backend)"; break;
        case SBX_G_TREE_TEARDOWN: n = "tree teardown (not yet built)"; break;
        case SBX_G_IDENTITY_SEPARATE: n = "a separate OS identity (the host supplies it, not the library)"; break;
        case SBX_G_IDENTITY_LEAST: n = "the least-privileged identity (the host supplies it)"; break;
        case SBX_G_IDENTITY_PER_INSTANCE: n = "a per-instance identity (the host supplies it)"; break;
        case SBX_G_NO_DEVICES: n = "no device descriptors (own_opens is non-empty)"; break;
        case SBX_G_LIMIT_MEMORY: n = "a memory limit (set it on the spawn, not the lockdown)"; break;
        case SBX_G_LIMIT_CPU: n = "a CPU limit (not yet built)"; break;
        case SBX_G_LIMIT_PROCESSES: n = "a process limit (set it on the spawn)"; break;
        case SBX_G_LIMIT_FILES: n = "a descriptor limit (set it on the spawn)"; break;
        case SBX_G_BROKER_BUDGET: n = "a broker budget (not yet built)"; break;
        case SBX_G_NOT_LEARNING: n = "enforcing, not learning (SBX_LOCK_LEARN is set)"; break;
        case SBX_G_NO_TRACE_CONTENT: n = "diagnostics without content (not guaranteed)"; break;
        case SBX_G_MITIGATIONS: n = "process mitigations (Windows only)"; break;
        }
        snprintf(out, cap, "required but not effective: %s", n);
    } else {
        switch (bit) {
        case SBX_R_HOST_UID: n = "runs as the host's uid"; break;
        case SBX_R_HOST_SELINUX_DOMAIN: n = "the host's SELinux domain"; break;
        case SBX_R_BINDER: n = "may hold a binder descriptor"; break;
        case SBX_R_GPU: n = "may hold a GPU descriptor"; break;
        case SBX_R_INHERITED_HANDLES: n = "may hold inherited descriptors"; break;
        case SBX_R_UID_SOCKETS: n = "may reach any socket of its uid"; break;
        case SBX_R_UID_SIGNALS: n = "may signal any process of its uid"; break;
        case SBX_R_NETWORK_ANY: n = "own inet sockets to any address"; break;
        case SBX_R_SHARED_PRINCIPAL: n = "shares its principal with other workers"; break;
        case SBX_R_PERSISTENT_GRANTS: n = "grants outlive the worker"; break;
        case SBX_R_KERNEL_SURFACE: n = "allowed system calls remain kernel surface"; break;
        }
        snprintf(out, cap, "forbidden residual present: %s", n);
    }
}

static uint64_t lowest(uint64_t set) { return set & ~(set - 1); }

int sbx_negotiate(const struct sbx_policy *policy, const void *options, const struct sbx_requirements *requirements,
                  struct sbx_report *report) {
    if (!options || !report || report->size < sizeof(*report)) return -EINVAL;
    if (requirements && requirements->size < sizeof(*requirements)) return -EINVAL;
    const struct sbx_lockdown_options *o = options;
    unsigned f = o->flags;

    uint64_t eff = 0, resid = 0, block = 0;

    if (!(f & (SBX_LOCK_PASSTHROUGH | SBX_LOCK_UNBROKERED))) eff |= SBX_G_FS_MEDIATED;
    else block |= SBX_G_FS_MEDIATED;

    if (!(f & NET_FLAGS)) eff |= SBX_G_NET_NONE;
    else block |= SBX_G_NET_NONE;
    if (f & SBX_LOCK_NET_BROKERED) eff |= SBX_G_NET_MEDIATED;
    if (f & SBX_LOCK_INET) resid |= SBX_R_NETWORK_ANY;
    if (f & SBX_LOCK_SOCKETS) resid |= SBX_R_UID_SOCKETS;

    if (!(f & SBX_LOCK_SIGNALS)) eff |= SBX_G_SIGNALS_SELF;
    else { block |= SBX_G_SIGNALS_SELF; resid |= SBX_R_UID_SIGNALS; }

    if (f & SBX_LOCK_EXEC) { eff |= SBX_G_EXEC_CONFINED; block |= SBX_G_EXEC_NONE; }
    else eff |= SBX_G_EXEC_NONE;

    if (!(f & SBX_LOCK_LEARN)) eff |= SBX_G_NOT_LEARNING;
    else block |= SBX_G_NOT_LEARNING;

    if (o->own_open_count == 0) eff |= SBX_G_NO_DEVICES;
    else {
        block |= SBX_G_NO_DEVICES;
        resid |= SBX_R_GPU;
#ifdef __ANDROID__
        resid |= SBX_R_BINDER;
#endif
    }

    /* IPC can never be none on this backend: socketpair and shared memory are always allowed (A-08, A-24). */
    block |= SBX_G_IPC_NONE;

    /* Not installed by a lockdown: identity, limits, teardown, broker budget, before-code, no-preopened. */
    resid |= SBX_R_HOST_UID | SBX_R_INHERITED_HANDLES | SBX_R_KERNEL_SURFACE;
#ifdef __ANDROID__
    resid |= SBX_R_HOST_SELINUX_DOMAIN;
#endif

    report->effective = eff;
    report->residual = resid;
    report->blocking = block;
#ifdef __ANDROID__
    snprintf(report->backend, sizeof(report->backend), "android-seccomp-broker");
#else
    snprintf(report->backend, sizeof(report->backend), "linux-seccomp-broker");
#endif
    report->backend_version =
        (uint32_t) SBX_VERSION_MAJOR << 16 | (uint32_t) SBX_VERSION_MINOR << 8 | (uint32_t) SBX_VERSION_PATCH;
    digest(policy, o, report->policy_digest);
    report->reason[0] = '\0';

    uint64_t required = requirements ? requirements->required : 0;
    uint64_t preferred = requirements ? requirements->preferred : 0;
    uint64_t forbidden = requirements ? requirements->forbidden : 0;
    report->unavailable = (required | preferred) & ~eff;

    uint64_t missing = required & ~eff;
    uint64_t hit = forbidden & resid;
    if (missing) {
        name_bit(lowest(missing), 0, report->reason, sizeof(report->reason));
        report->launch_result = -EPERM;
        return -EPERM;
    }
    if (hit) {
        name_bit(lowest(hit), 1, report->reason, sizeof(report->reason));
        report->launch_result = -EPERM;
        return -EPERM;
    }
    report->launch_result = 0;
    return 0;
}

int sbx_lockdown_checked(int broker_fd, const struct sbx_lockdown_options *options,
                         const struct sbx_requirements *requirements, struct sbx_report *report) {
    struct sbx_report local;
    struct sbx_report *r = report;
    if (!r) {
        memset(&local, 0, sizeof(local));
        local.size = sizeof(local);
        r = &local;
    }
    struct sbx_lockdown_options none;
    const struct sbx_lockdown_options *o = options;
    if (!o) {
        memset(&none, 0, sizeof(none));
        o = &none;
    }
    int negotiated = sbx_negotiate(NULL, o, requirements, r);
    if (negotiated != 0) return negotiated;  /* a required guarantee is missing; nothing installed */
    int result = sbx_lockdown(broker_fd, o);
    r->launch_result = result;
    return result;
}
