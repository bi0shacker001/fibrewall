/*
 * PROPOSAL ONLY (Fibrewall review, Phase 0, deliverable D). Not built, not
 * installed, not part of the ABI until the owner approves it. It is here
 * so the proposed contract can be read and diffed as real C.
 *
 * The review's section 7: a consumer states the guarantees it requires,
 * prefers and forbids; the library negotiates them against what the
 * backend can actually enforce, applies them, and reports what was
 * installed, what was not, and what authority remains. A required
 * guarantee that can't be met fails the launch before any untrusted code
 * runs. Nothing is ever downgraded silently.
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
 * Guarantees: properties the worker cannot violate, each one enforced by
 * a named mechanism. A bit is reported as effective only when the
 * mechanism is installed and verified, never because it was asked for.
 * New bits are only ever added; a bit's meaning never changes.
 */
#define SBX_G_CONFINED_BEFORE_CODE  (1ull << 0)  /* no worker instruction runs before enforcement (Windows suspended spawn; Linux lockdown before exec) */
#define SBX_G_FS_MEDIATED           (1ull << 1)  /* every path operation is decided by the broker (no ambient file system) */
#define SBX_G_FS_NO_PREOPENED       (1ull << 2)  /* no descriptor or handle to a file outside the rules at launch (inventory checked) */
#define SBX_G_NET_NONE              (1ull << 3)  /* no network socket can be made, loopback included */
#define SBX_G_NET_MEDIATED          (1ull << 4)  /* every network endpoint is decided per call (brokered) */
#define SBX_G_IPC_NONE              (1ull << 5)  /* no Unix, abstract, Binder, named-pipe or other IPC to processes outside the worker, beyond handles granted */
#define SBX_G_IPC_MEDIATED          (1ull << 6)  /* IPC endpoints decided per call */
#define SBX_G_SIGNALS_SELF          (1ull << 7)  /* signals only to the worker itself (or its own tree, brokered) */
#define SBX_G_EXEC_NONE             (1ull << 8)  /* no new program image */
#define SBX_G_EXEC_CONFINED         (1ull << 9)  /* every new image is under the same enforcement from its first instruction */
#define SBX_G_CHILDREN_NONE         (1ull << 10) /* no child processes */
#define SBX_G_TREE_TEARDOWN         (1ull << 11) /* the whole tree dies when the authority goes (job kill-on-close; cgroup kill) */
#define SBX_G_IDENTITY_SEPARATE     (1ull << 12) /* an OS principal other than the host's (AppContainer SID, isolated uid, another uid) */
#define SBX_G_IDENTITY_LEAST        (1ull << 13) /* the least-privileged such principal the system has (LPAC; Android isolated process) */
#define SBX_G_IDENTITY_PER_INSTANCE (1ull << 14) /* no other worker shares the principal or its grants */
#define SBX_G_NO_DEVICES            (1ull << 15) /* no device descriptors (GPU, binder) held */
#define SBX_G_LIMIT_MEMORY          (1ull << 16)
#define SBX_G_LIMIT_CPU             (1ull << 17)
#define SBX_G_LIMIT_PROCESSES       (1ull << 18)
#define SBX_G_LIMIT_FILES           (1ull << 19) /* descriptors / handles */
#define SBX_G_BROKER_BUDGET         (1ull << 20) /* a worker's outstanding broker requests are bounded */
#define SBX_G_NOT_LEARNING          (1ull << 21) /* enforcing: learning mode is off */
#define SBX_G_NO_TRACE_CONTENT      (1ull << 22) /* diagnostics record no paths or arguments */
#define SBX_G_MITIGATIONS           (1ull << 23) /* platform process mitigations applied (Windows: the set in the report) */

/*
 * Residual authority: what the worker still has that a guarantee above
 * would remove. Reported so a consumer can show it, and so a strict
 * consumer can forbid it.
 */
#define SBX_R_HOST_UID              (1ull << 0)  /* runs as the host's uid (Linux/Android same-UID) */
#define SBX_R_HOST_SELINUX_DOMAIN   (1ull << 1)  /* the host app's SELinux domain */
#define SBX_R_BINDER                (1ull << 2)  /* holds a binder or hwbinder descriptor */
#define SBX_R_GPU                   (1ull << 3)  /* holds a GPU device descriptor (unfiltered ioctl) */
#define SBX_R_INHERITED_HANDLES     (1ull << 4)  /* holds descriptors/handles not in the declared inventory */
#define SBX_R_UID_SOCKETS           (1ull << 5)  /* may reach any Unix socket of its uid (SBX_LOCK_SOCKETS) */
#define SBX_R_UID_SIGNALS           (1ull << 6)  /* may signal any process of its uid (SBX_LOCK_SIGNALS) */
#define SBX_R_NETWORK_ANY           (1ull << 7)  /* own inet sockets, any destination */
#define SBX_R_SHARED_PRINCIPAL      (1ull << 8)  /* the container/uid is shared with other workers */
#define SBX_R_PERSISTENT_GRANTS     (1ull << 9)  /* grants outlive the worker (Windows static ACEs) */
#define SBX_R_KERNEL_SURFACE        (1ull << 10) /* always set: allowed system calls remain kernel attack surface */

struct sbx_requirements {
    uint32_t size;          /* sizeof(struct sbx_requirements): fields are only ever appended */
    uint64_t required;      /* SBX_G_*: launch fails, before any worker code, unless every one is effective */
    uint64_t preferred;     /* SBX_G_*: applied where the backend can; reported either way */
    uint64_t forbidden;     /* SBX_R_*: launch fails if any of these would remain */
};

struct sbx_report {
    uint32_t size;               /* set by the caller to sizeof(struct sbx_report) */
    uint64_t effective;          /* SBX_G_* installed and verified */
    uint64_t unavailable;        /* SBX_G_* asked for (required or preferred) and not effective */
    uint64_t residual;           /* SBX_R_* that remain */
    uint64_t blocking;           /* SBX_G_* the policy or options themselves rule out (e.g. SBX_LOCK_SOCKETS rules out SBX_G_NET_NONE) */
    char backend[32];            /* "linux-seccomp-broker", "windows-lpac-job", ... */
    uint32_t backend_version;    /* SBX_VERSION_MAJOR << 16 | MINOR << 8 | PATCH */
    uint8_t policy_digest[32];   /* SHA-256 of the canonical policy, options and requirements applied */
    int launch_result;           /* 0, or the negative errno the launch failed with */
    char reason[128];            /* the first unmet requirement, in words, for the consumer's UI and logs */
};

/*
 * Dry run: what a launch with this policy, these options and these
 * requirements would get on this system, without starting anything.
 * Returns 0 when every required guarantee would be met, -EPERM when not
 * (report says which and why), or another negative errno.
 */
int sbx_negotiate(const struct sbx_policy *policy, const void *options, const struct sbx_requirements *requirements,
                  struct sbx_report *report);

#ifndef _WIN32
/*
 * sbx_lockdown with a contract. On failure nothing is installed and the
 * caller must not run untrusted code. On success the report describes
 * what was installed. sbx_lockdown() stays as it is: equivalent to this
 * with required = 0 and no report.
 */
int sbx_lockdown_checked(int broker_fd, const struct sbx_lockdown_options *options,
                         const struct sbx_requirements *requirements, struct sbx_report *report);

/*
 * Confined spawn on Linux and Android (review A-04): the child installs the
 * lockdown on itself between fork and exec, with SBX_LOCK_EXEC, so the
 * program's first instruction (its loader's) already runs confined. Returns
 * once the program is executing, or with the child's errno when any part
 * of the lockdown failed (nothing ran).
 */
int sbx_spawn_confined(const struct sbx_spawn_spec *spec, int broker_fd, const struct sbx_lockdown_options *options,
                       const struct sbx_requirements *requirements, struct sbx_report *report, pid_t *pid_out);

/*
 * Per-worker policy in a shared broker (review A-06, A-22, A-27): the
 * listener asks the host for each attaching worker's own policy, by the
 * token it presented, instead of serving one policy to everyone.
 */
typedef struct sbx_policy *(*sbx_policy_for_fn)(void *context, const char *token, pid_t pid);
int sbx_broker_listen_each(sbx_policy_for_fn policy_for, void *context, const char *socket_path,
                           struct sbx_listener **out);
#else
/* sbx_spawn with a contract. LPAC required and unavailable fails instead of falling back (review A-13). */
int sbx_spawn_checked(const struct sbx_spawn_spec *spec, const struct sbx_requirements *requirements,
                      struct sbx_report *report, struct sbx_process *out);
#endif

#ifdef __cplusplus
}
#endif

#endif
