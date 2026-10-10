/*
 * sbx: a process sandbox in two halves, after Chromium's Linux syscall
 * broker (sandbox/linux/syscall_broker) and minijail's seccomp policies.
 *
 * sbx_lockdown() is called by the process to be confined, before it loads
 * code it does not trust. It installs a seccomp filter on every thread
 * under which no system call can name a file: each one that would traps
 * (SIGSYS), and the handler sends it over a Unix socket to the broker.
 * Sockets, program execution, ptrace, namespaces, signals to other
 * processes and the other kernel surfaces listed in src/lockdown.c are
 * refused outright. Calls on descriptors the process already holds (read,
 * write, mmap, ioctl, getdents) are untouched, so a GPU driver keeps its
 * device and an engine its window.
 *
 * The broker (src/broker.c) runs in another process. It answers each
 * request from a policy of path rules, then asks the host's decider (the
 * host's own permission system) if one is set, does the call itself and
 * sends back the result, with the descriptor for an open. The handler is
 * not a trust boundary: code that replaces it only loses its own file
 * access.
 *
 * Nothing here knows about any particular host. Linux (glibc or bionic),
 * aarch64 and x86_64.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_H
#define SBX_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- The confined half ---- */

/* Lockdown flags. */
#define SBX_LOCK_LOG_SOCKET 0x1u  /* allow socket(AF_UNIX, SOCK_DGRAM): Android's liblog, syslog */

/*
 * Confines the calling process. broker_fd is a connected SOCK_SEQPACKET
 * Unix socket whose other end a broker serves; the process keeps it.
 * Returns 0 when every thread is confined, or a negative errno when
 * nothing was installed (never half-installed). A caller that gets an
 * error must not go on to run the code it meant to confine.
 */
int sbx_lockdown(int broker_fd, unsigned flags);

/* ---- The broker half ---- */

/* Rule modes. A rule covers its path and everything under it; the longest matching rule decides. */
#define SBX_DENY 0u
#define SBX_READ 1u              /* open for reading, stat, access, readlink, chdir, list */
#define SBX_WRITE 2u             /* also open for writing, create, mkdir, unlink, rename */
/* Rule flags, or'ed into the mode. */
#define SBX_CASE_INSENSITIVE 0x10u  /* a name that does not exist matches one that differs only in case */
#define SBX_DECIDE 0x20u            /* ask the decider about every access under this rule, not only refusals */

struct sbx_policy;

struct sbx_policy *sbx_policy_new(void);
void sbx_policy_free(struct sbx_policy *policy);

/*
 * Adds a rule for path (absolute; canonicalised when it exists). Every
 * ancestor of a rule can be stat()ed and traversed, but not listed or
 * opened. /proc/self and /proc/thread-self mean the confined process's own
 * entries, which are always allowed; other processes' are always denied.
 * Returns 0 or a negative errno.
 */
int sbx_policy_add(struct sbx_policy *policy, const char *path, unsigned mode);

/*
 * Makes virtual_path (and everything under it) mean real_path for the
 * confined process: a host can hand over a folder under a fixed name
 * without the confined code knowing where it lives. Rules apply to the
 * real path. Returns 0 or a negative errno.
 */
int sbx_policy_alias(struct sbx_policy *policy, const char *virtual_path, const char *real_path);

/* One brokered request, as the decider and the audit see it. */
struct sbx_access {
    const char *op;        /* "open", "stat", "access", "readlink", "mkdir", "unlink", "rename", "statfs", "chdir", "getcwd" */
    const char *asked;     /* the path as the confined code named it */
    const char *resolved;  /* the real path the broker would act on ("" when it could not be resolved) */
    unsigned need;         /* SBX_READ, SBX_WRITE, or 0 for a lookup (stat, access F_OK, traversal) */
    int flags;             /* open flags for "open", else 0 */
    pid_t pid;             /* the confined process (the kernel's word) */
    int rule_verdict;      /* what the rules alone answered: 0 or a negative errno */
};

/*
 * The host's permission system. Called after the rules for every request
 * they refuse and for every request under a rule marked SBX_DECIDE, with
 * the rules' verdict in access->rule_verdict. Returns 0 to allow, a
 * negative errno to refuse, or SBX_KEEP to leave the rules' verdict. It
 * may grant what the rules refused (a document the person just picked) or
 * refuse what they allowed (a folder whose grant was revoked). It runs on
 * the broker's thread; the confined call waits for it.
 */
#define SBX_KEEP 1
typedef int (*sbx_decide_fn)(void *context, const struct sbx_access *access);
void sbx_policy_set_decider(struct sbx_policy *policy, sbx_decide_fn decide, void *context);

/* Receives every decision with its result (0 or a negative errno). Defaults to logging refusals on stderr. */
typedef void (*sbx_audit_fn)(void *context, const struct sbx_access *access, int result);
void sbx_policy_set_audit(struct sbx_policy *policy, sbx_audit_fn audit, void *context);

/*
 * Serves fd, the broker's end of the socket sbx_lockdown() was given,
 * until the other end closes it; then closes fd and frees the policy.
 * Call sbx_broker_prepare(fd) before the confined side can send anything.
 * sbx_broker_serve blocks; sbx_broker_start serves on a new detached
 * thread and returns 0 or a negative errno.
 */
int sbx_broker_prepare(int fd);
void sbx_broker_serve(struct sbx_policy *policy, int fd);
int sbx_broker_start(struct sbx_policy *policy, int fd);

#ifdef __cplusplus
}
#endif

#endif
