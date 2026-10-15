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
#define SBX_LOCK_LOG_SOCKET 0x1u  /* allow socket(AF_UNIX, SOCK_DGRAM) and connect: Android's liblog, syslog */
/*
 * No broker: path calls go to the kernel as they are, and only what
 * reaches past the process is refused (sockets, execve, ptrace, namespaces,
 * signals to other processes, io_uring, bpf and the rest). For a process
 * whose files another wall already guards, such as an Android isolated
 * process under its own UID. broker_fd is ignored.
 */
#define SBX_LOCK_UNBROKERED 0x2u
/*
 * Brokered for the claimed folders only (sbx_lockdown_options.claims):
 * every other path call is made by the handler with the kernel deciding,
 * as it would without the filter. Also for a process another wall already
 * guards: what the broker adds there is the host's folders, which that
 * wall keeps out of the process's own reach (an Android isolated process
 * given its app's files through the broker). Every path call still traps,
 * so local files (sbx_local_add) answer here too. truncate, link, chmod,
 * xattrs and the other path calls the broker does not make go to the
 * kernel, as in the unbrokered mode.
 */
#define SBX_LOCK_PASSTHROUGH 0x4u
/*
 * Network: socket(AF_INET or AF_INET6, SOCK_STREAM or SOCK_DGRAM), with
 * connect, bind and listen, and no other socket. For a process that talks
 * to the network itself, such as a sync daemon. bind is open because every
 * socket the process can make is an inet one; the filter cannot read the
 * address bind is given, so this flag cannot be combined with
 * SBX_LOCK_LOG_SOCKET (sbx_lockdown answers -EINVAL), whose Unix socket
 * could otherwise bind a name in the file system or the abstract namespace.
 * On Android, bionic's connect and accept also talk to netd over a Unix
 * socket and so fail here; code that calls the kernel itself (Go) does not.
 */
#define SBX_LOCK_INET 0x8u

#define SBX_SEALED_MAX 8
#define SBX_OWN_OPENS_MAX 16
#define SBX_CLAIMS_MAX 32
#define SBX_LOCALS_MAX 512

struct sbx_lockdown_options {
    unsigned flags;
    /*
     * Descriptors the process keeps but may no longer use: ioctl, mmap,
     * fcntl and dup on them are refused (EPERM); close is allowed. For a
     * descriptor a library opened during setup and holds on to, such as
     * Android's binder device after the graphics stack came up: binder
     * transactions are ioctls, so a sealed binder descriptor carries none.
     */
    const int *sealed_fds;
    unsigned sealed_count;  /* at most SBX_SEALED_MAX */
    /*
     * Device files the process opens itself, just before the filter goes
     * on, because the kernel ties what they hold to the process that
     * opened them, so a descriptor the broker opened would not do: binder
     * and hwbinder (a broker-opened /dev/hwbinder fails to mmap), and GPU
     * nodes that keep per-process state (kgsl, Mali, DRM render nodes).
     * After lockdown an open of exactly one of these paths is answered with
     * a duplicate, and stat or access of it from that descriptor (libhidl
     * checks /dev/hwbinder with access before it opens it): they are local
     * files (sbx_local_add), read and written. Paths that do not exist or
     * cannot be opened are skipped.
     * Each platform's list is the host's (see docs/design.md).
     */
    const char *const *own_opens;
    unsigned own_open_count;  /* at most SBX_OWN_OPENS_MAX */
    /*
     * With SBX_LOCK_PASSTHROUGH: the absolute folders (each with
     * everything under it) whose paths go to the broker. Name both a
     * folder's aliases and its real path, as the confined code may use
     * either. A relative path is judged by the folder it lands in.
     */
    const char *const *claims;
    unsigned claim_count;  /* at most SBX_CLAIMS_MAX */
};

/*
 * Confines the calling process. broker_fd is a connected SOCK_SEQPACKET
 * Unix socket whose other end a broker serves; the process keeps it.
 * options may be NULL for the defaults. Returns 0 when every thread is
 * confined, or a negative errno when nothing was installed (never
 * half-installed). A caller that gets an error must not go on to run the
 * code it meant to confine.
 */
int sbx_lockdown(int broker_fd, const struct sbx_lockdown_options *options);

/*
 * Gives the process a local file: an open of exactly path (absolute, of
 * any name) is answered with a duplicate of fd, read only, and stat and
 * access from it, by the handler, with no broker and no rule. For files
 * the host handed over that the process could not open by name (code and
 * data an Android app passes to its isolated process). Takes fd, and
 * closes it on error. Replaces the descriptor of an earlier path.
 * Callable before or after sbx_lockdown, from any thread but not from a
 * signal handler. At most SBX_LOCALS_MAX paths, own-opened devices
 * included. Returns 0 or a negative errno. A path call is answered from
 * here only while the filter traps it (brokered or passthrough).
 */
int sbx_local_add(const char *path, int fd);

/* ---- Starting a sandboxed program (the native kind) ---- */

#define SBX_SPAWN_FDS_MAX 16
#define SBX_SPAWN_LIMITS_MAX 8

struct sbx_limit {
    int resource;           /* RLIMIT_* */
    unsigned long value;    /* soft and hard */
};

struct sbx_spawn_spec {
    const char *path;       /* the program (on Android: a file in the app's native-library directory) */
    char *const *argv;
    char *const *envp;      /* NULL: an empty environment */
    const int *fds;         /* handed over as descriptors 3, 4, ... in this order; 0-2 are inherited */
    unsigned fd_count;
    const struct sbx_limit *limits;
    unsigned limit_count;
};

/*
 * Starts spec->path as a new process holding only descriptors 0-2 and the
 * handed ones, with the limits set and SIGKILL as its parent-death signal.
 * Returns 0 and the pid once the program is executing, or a negative
 * errno (the child's, if it got as far as failing to execute).
 */
int sbx_spawn(const struct sbx_spawn_spec *spec, pid_t *pid_out);

/* Called by the spawned program first: makes it non-dumpable again (exec reset that). */
int sbx_spawned_init(void);

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
 * Adds a rule for path (absolute). When the path exists and resolves
 * elsewhere (a symlink such as /dev/qemu_pipe), the rule covers both the
 * name as given and what it resolves to. Every
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
