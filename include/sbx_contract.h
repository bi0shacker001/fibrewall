/*
 * The confinement contract: a consumer states the guarantees it requires,
 * prefers and forbids; the library reports what a given policy and options
 * would actually enforce on this backend, what they rule out, and what
 * authority would remain. A required guarantee that cannot be met fails
 * before any untrusted code runs. Nothing is downgraded silently.
 *
 * This is the effective-enforcement report of the sandbox review
 * (Droidtop/tracker#651, finding A-26). It is additive: sbx_lockdown()
 * and the rest of sbx.h are unchanged, and a host that does not use this
 * header keeps working as before.
 *
 * Built on Linux and Android. The Windows backend's report lands
 * separately; the guarantee and residual bits below are the shared
 * vocabulary, so they are defined on every platform.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_CONTRACT_H
#define SBX_CONTRACT_H

#include <stddef.h>
#include <stdint.h>

#include "sbx.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Guarantees: properties the worker cannot violate, each enforced by a
 * named mechanism. A bit is reported effective only when that mechanism is
 * installed, never because it was asked for. Bits are only ever added; a
 * bit's meaning never changes.
 */
#define SBX_G_CONFINED_BEFORE_CODE  (1ull << 0)  /* no worker instruction runs before enforcement */
#define SBX_G_FS_MEDIATED           (1ull << 1)  /* every path operation is decided by the broker */
#define SBX_G_FS_NO_PREOPENED       (1ull << 2)  /* no descriptor to a file outside the rules at launch (inventory checked) */
#define SBX_G_NET_NONE              (1ull << 3)  /* no network socket can be made, loopback included */
#define SBX_G_NET_MEDIATED          (1ull << 4)  /* every network endpoint is decided per call (brokered) */
#define SBX_G_IPC_NONE              (1ull << 5)  /* no IPC to processes outside the worker, beyond granted handles */
#define SBX_G_IPC_MEDIATED          (1ull << 6)  /* IPC endpoints decided per call */
#define SBX_G_SIGNALS_SELF          (1ull << 7)  /* signals only to the worker itself, or its own brokered tree */
#define SBX_G_EXEC_NONE             (1ull << 8)  /* no new program image */
#define SBX_G_EXEC_CONFINED         (1ull << 9)  /* every new image is confined from its first instruction */
#define SBX_G_CHILDREN_NONE         (1ull << 10) /* no child processes */
#define SBX_G_TREE_TEARDOWN         (1ull << 11) /* the whole tree dies when the authority goes */
#define SBX_G_IDENTITY_SEPARATE     (1ull << 12) /* an OS principal other than the host's */
#define SBX_G_IDENTITY_LEAST        (1ull << 13) /* the least-privileged such principal the system has */
#define SBX_G_IDENTITY_PER_INSTANCE (1ull << 14) /* no other worker shares the principal or its grants */
#define SBX_G_NO_DEVICES            (1ull << 15) /* no device descriptors (GPU, binder) held */
#define SBX_G_LIMIT_MEMORY          (1ull << 16)
#define SBX_G_LIMIT_CPU             (1ull << 17)
#define SBX_G_LIMIT_PROCESSES       (1ull << 18)
#define SBX_G_LIMIT_FILES           (1ull << 19) /* descriptors / handles */
#define SBX_G_BROKER_BUDGET         (1ull << 20) /* a worker's outstanding broker requests are bounded */
#define SBX_G_NOT_LEARNING          (1ull << 21) /* enforcing: learning mode is off */
#define SBX_G_NO_TRACE_CONTENT      (1ull << 22) /* diagnostics record no paths or arguments */
#define SBX_G_MITIGATIONS           (1ull << 23) /* platform process mitigations applied */

/*
 * Residual authority: what the worker still has that a guarantee above
 * would remove. Reported so a consumer can show it, and a strict consumer
 * can forbid it.
 */
#define SBX_R_HOST_UID              (1ull << 0)  /* runs as the host's uid */
#define SBX_R_HOST_SELINUX_DOMAIN   (1ull << 1)  /* the host app's SELinux domain (Android) */
#define SBX_R_BINDER                (1ull << 2)  /* may hold a binder/hwbinder descriptor */
#define SBX_R_GPU                   (1ull << 3)  /* may hold a GPU device descriptor (unfiltered ioctl) */
#define SBX_R_INHERITED_HANDLES     (1ull << 4)  /* may hold descriptors not in a declared inventory */
#define SBX_R_UID_SOCKETS           (1ull << 5)  /* may reach any socket of its uid (SBX_LOCK_SOCKETS) */
#define SBX_R_UID_SIGNALS           (1ull << 6)  /* may signal any process of its uid (SBX_LOCK_SIGNALS) */
#define SBX_R_NETWORK_ANY           (1ull << 7)  /* own inet sockets, any destination (SBX_LOCK_INET) */
#define SBX_R_SHARED_PRINCIPAL      (1ull << 8)  /* the principal is shared with other workers */
#define SBX_R_PERSISTENT_GRANTS     (1ull << 9)  /* grants outlive the worker */
#define SBX_R_KERNEL_SURFACE        (1ull << 10) /* always: allowed system calls remain kernel attack surface */

struct sbx_requirements {
    uint32_t size;      /* sizeof(struct sbx_requirements); fields are only ever appended */
    uint64_t required;  /* SBX_G_*: the launch fails, before any worker code, unless every one is effective */
    uint64_t preferred; /* SBX_G_*: reported either way; does not fail the launch */
    uint64_t forbidden; /* SBX_R_*: the launch fails if any of these would remain */
};

struct sbx_report {
    uint32_t size;             /* set by the caller to sizeof(struct sbx_report) */
    uint64_t effective;        /* SBX_G_* that this policy and options install */
    uint64_t unavailable;      /* SBX_G_* asked for (required or preferred) that are not effective */
    uint64_t residual;         /* SBX_R_* that remain */
    uint64_t blocking;         /* SBX_G_* the options themselves rule out (e.g. SBX_LOCK_SOCKETS rules out SBX_G_NET_NONE) */
    char backend[32];          /* the backend's name, e.g. "linux-seccomp-broker" */
    uint32_t backend_version;  /* SBX_VERSION_MAJOR<<16 | MINOR<<8 | PATCH */
    uint8_t policy_digest[32]; /* SHA-256 over the canonical flags, rules and requirements */
    int launch_result;         /* 0, or the negative errno the (attempted) launch failed with */
    char reason[128];          /* the first unmet requirement or forbidden residual, in words */
};

/*
 * A dry run: what a launch with these options and policy would enforce on
 * this backend, filled into *report, without starting or locking anything.
 * options points to a struct sbx_lockdown_options on Linux and Android.
 * Returns 0 when every required guarantee would hold and no forbidden
 * residual would remain, -EPERM when not (report->reason says which), or
 * another negative errno for a malformed argument.
 */
int sbx_negotiate(const struct sbx_policy *policy, const void *options, const struct sbx_requirements *requirements,
                  struct sbx_report *report);

#ifndef _WIN32
/*
 * sbx_lockdown with a contract. It first negotiates: if a required
 * guarantee would be missing or a forbidden residual would remain, it
 * returns -EPERM and installs nothing, so the caller must not run
 * untrusted code. Otherwise it locks down and fills *report with what was
 * installed. requirements may be NULL (no requirement), and report may be
 * NULL (no report). sbx_lockdown() is unchanged and equivalent to this
 * with no requirements and no report.
 */
int sbx_lockdown_checked(int broker_fd, const struct sbx_lockdown_options *options,
                         const struct sbx_requirements *requirements, struct sbx_report *report);
#endif

#ifdef __cplusplus
}
#endif

#endif
