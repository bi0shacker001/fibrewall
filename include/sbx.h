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
 * Windows (x86_64) has no trap: there sbx_spawn() starts the program in an
 * AppContainer inside a job object, and the confined program asks the
 * broker for files with sbx_open() (docs/design.md, "Windows").
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_H
#define SBX_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- On every system: handles and the client call ---- */

#ifdef _WIN32
typedef void *sbx_handle;  /* a HANDLE */
#ifdef _MSC_VER
typedef int pid_t;         /* struct sbx_access's process: the Windows process id */
#endif
#else
typedef int sbx_handle;    /* a descriptor */
#endif

/* sbx_open flags. */
#define SBX_OPEN_READ 0x1u
#define SBX_OPEN_WRITE 0x2u
#define SBX_OPEN_CREATE 0x4u     /* create the file when it is missing */
#define SBX_OPEN_TRUNCATE 0x8u   /* empty it (with SBX_OPEN_WRITE) */
#define SBX_OPEN_EXCLUSIVE 0x10u /* with SBX_OPEN_CREATE: -EEXIST when it exists */
#define SBX_OPEN_APPEND 0x20u    /* every write goes to the end (with SBX_OPEN_WRITE) */
#define SBX_OPEN_DIRECTORY 0x40u /* a folder, for listing; not with the writing flags */

/*
 * Opens path (absolute, UTF-8) for the confined program, as the broker
 * decides. Linux and Android: open(), which the lockdown traps and the
 * broker answers, so it works before lockdown too. Windows: a request on
 * the channel sbx_spawn() gave the program; a path open the program makes
 * itself is refused by its token. Returns 0 and the handle in *out, or a
 * negative errno (-EACCES when refused). Thread-safe.
 */
int sbx_open(const char *path, unsigned flags, sbx_handle *out);

#ifndef _WIN32

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
/*
 * Network through the broker, for a process that may not create an
 * internet socket itself (an Android isolated process; see docs/design.md,
 * "A UID of its own for every confined process"). socket(AF_INET or
 * AF_INET6) asks the broker, which creates the socket under its own
 * identity and hands it over; connect, bind, listen and accept on such a
 * socket are done by the broker, on the same socket, after the grants
 * (sbx_policy_set_net) and the decider; reads, writes and the rest are the
 * process's own. Unix sockets are allowed, but may not be bound or
 * listened on, and a connect to a system socket the host named
 * (sbx_policy_add_system_socket: the resolver, netd's fwmarkd) is the
 * broker's, so libc's name lookups and connects work. Every other Unix
 * connect goes to the kernel. Not with SBX_LOCK_INET or
 * SBX_LOCK_UNBROKERED. A blocking connect or accept waits in the broker on
 * a thread of its own, so it holds up no other call.
 */
#define SBX_LOCK_NET_BROKERED 0x10u

/*
 * Learning mode, for training a policy (docs/design.md, "Learning mode"):
 * nothing the filter would refuse with EACCES or EPERM is refused. Each
 * such call is sent to the broker as a record, which reaches the host's
 * audit function as an access whose op is "syscall", whose asked is the
 * call's name and first arguments, whose rule_verdict is the errno a
 * real lockdown answers, and whose allowed_by names the flag that would
 * allow the call (NULL when none does); then the call is made. Three refusals stay: a
 * call through another architecture's entry, a new SIGSYS handler, and
 * clone with namespace flags. Paths still go through the broker, whose
 * decider a learning host makes record and allow. A learning process has
 * NO protection: never a default, and a host says so every time. Needs the
 * broker (not with SBX_LOCK_UNBROKERED).
 */
#define SBX_LOCK_LEARN 0x20u
/*
 * link, symlink and truncate by path go to the broker instead of being
 * refused: link needs both names writable, symlink the new name (its
 * target is stored as given and judged when something follows it),
 * truncate the file. For Wine (dosdevices links, SetEndOfFile on a name).
 * Without the broker (SBX_LOCK_UNBROKERED, SBX_LOCK_PASSTHROUGH) these
 * calls go to the kernel already, so the flag changes nothing there.
 */
#define SBX_LOCK_PATHOPS 0x100u
/*
 * inotify marks (inotify_add_watch) are allowed, with the kernel deciding:
 * the process may then learn the names of files changing in folders the
 * rules do not grant, though it can open none of them. For Wine's change
 * notifications. fanotify stays refused.
 */
#define SBX_LOCK_INOTIFY 0x200u
/*
 * Unix sockets of the process's own: socket(AF_UNIX, SOCK_STREAM or
 * SOCK_SEQPACKET) is allowed, and bind and connect go to the broker, which
 * decides a path like any other (bind needs it writable, connect readable;
 * relative paths are the process's current directory's) or an abstract
 * name by sbx_policy_add_unix_name, and makes the call on the process's
 * socket. The server then sees the broker's credentials (SO_PEERCRED), the
 * same UID. listen and accept are the process's own (the kernel refuses
 * listen on an unbound socket). For wineserver, X, PulseAudio and a host's
 * renderer sockets. Datagram Unix sockets stay SBX_LOCK_LOG_SOCKET's only,
 * and with this flag their connect is decided by the broker too. The
 * filter cannot tell an inet address from a Unix one, so with
 * SBX_LOCK_INET as well, inet bind and connect also go to the broker,
 * under sbx_policy_set_net's grants (and SBX_LOCK_INET may then be
 * combined with SBX_LOCK_LOG_SOCKET). Needs the broker; not with
 * SBX_LOCK_NET_BROKERED.
 */
#define SBX_LOCK_UNIX 0x80u
/*
 * Sockets allowed outright, with no broker and no per-call cost: Unix
 * sockets of every type, inet stream and datagram ones, and route netlink
 * (NETLINK_ROUTE, how Wine and Go list network interfaces); bind, connect
 * and the rest go to the kernel. The process can then reach every socket
 * its UID may (the host's own, in the file system or the abstract
 * namespace) and create socket files wherever the UID may write. For a
 * containment sandbox that restricts the file system view only (the
 * owner's policy for Wine, Droidtop/tracker#584). With SBX_LOCK_UNIX as
 * well, bind and connect are judged by the broker as that flag says.
 * Not with SBX_LOCK_NET_BROKERED.
 */
#define SBX_LOCK_SOCKETS 0x400u
/*
 * Signals to any process the kernel allows (the same UID): kill, tgkill,
 * tkill, rt_sigqueueinfo and rt_tgsigqueueinfo go to the kernel. Without
 * it a signal may go to this process only (the pid sbx_lockdown saw). The
 * pidfd calls stay refused. For a tree of processes that signal each other
 * (wineserver and its clients).
 */
#define SBX_LOCK_SIGNALS 0x800u
/*
 * The containment preset (Droidtop/tracker#584, owner, 2026-10-23): the
 * file system view is the one thing restricted, through the broker; link,
 * symlink and truncate are brokered like the rest, and sockets, signals,
 * inotify, shared memory and descriptors are allowed outright. Clear
 * escapes stay refused whatever the flags: ptrace, process_vm_*, new
 * namespaces, mounts, bpf, perf_event_open, io_uring, module loading, the
 * keyring. A host may add or remove any flag of it.
 */
#define SBX_LOCK_CONTAIN (SBX_LOCK_PATHOPS | SBX_LOCK_INOTIFY | SBX_LOCK_SOCKETS | SBX_LOCK_SIGNALS)

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
 * half-installed); -EDEADLK means a thread has SIGSYS blocked, which would
 * kill the process on its first trapped call (once confined, no thread can
 * block it). A caller that gets an error must not go on to run the
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

/*
 * sbx_local_add with a mode: SBX_READ, or SBX_READ | SBX_WRITE for a file
 * the host opened for writing and hands over to be written by name (an
 * open asking to write is then answered too, and O_TRUNC empties the
 * file). Every open of the path is a duplicate of the one descriptor, so
 * they share one position; the open's other flags are not applied.
 * Adding the same path again replaces both the descriptor and the mode.
 */
int sbx_local_add_mode(const char *path, int fd, unsigned mode);

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

#else /* _WIN32 */

/* ---- Starting a confined program (Windows) ---- */

#define SBX_SPAWN_HANDLES_MAX 16

struct sbx_spawn_spec {
    const char *path;       /* the program, absolute (UTF-8); its folder needs an SBX_STATIC rule */
    char *const *argv;      /* argv[0] first; quoted into a command line */
    char *const *envp;      /* "NAME=value" (UTF-8); NULL: none. SBX_BROKER is added, and the
                               parent's SystemRoot, SystemDrive, USERPROFILE, LOCALAPPDATA,
                               APPDATA, TEMP and TMP where envp lacks them (Windows makes the
                               container's own folders from them). */
    const sbx_handle *handles; /* inherited with the same values; each must be inheritable */
    unsigned handle_count;
    sbx_handle std_in, std_out, std_err; /* NULL: none; each must be inheritable */
    const char *container;  /* the AppContainer profile's name; created when missing */
    int less_privileged;    /* nonzero: a less-privileged AppContainer where the system has one */
    unsigned long long memory_limit; /* bytes of committed memory; 0: no limit */
    /*
     * The broker's rules, or NULL for no broker. Taken by the call, even
     * when it fails: the broker frees it when the program closes its end.
     */
    struct sbx_policy *policy;
};

struct sbx_process {
    sbx_handle process;     /* the program's process handle */
    sbx_handle job;         /* its job: closing it ends the program */
    unsigned long pid;
    int less_privileged;    /* whether it runs in a less-privileged AppContainer */
};

/*
 * Starts spec->path suspended in an AppContainer with no capabilities,
 * with child processes refused, in a job object (one process, no
 * breakaway, killed when the job closes, UI limits, the memory limit),
 * inheriting only the listed handles. Applies the policy's SBX_STATIC
 * grants, starts the broker on a thread, then lets the program run.
 * Returns 0, or a negative errno with nothing started (never half-confined).
 */
int sbx_spawn(const struct sbx_spawn_spec *spec, struct sbx_process *out);

/*
 * The Windows error code behind the last sbx_spawn failure (0 when it was
 * not a Windows error), for a host's log: errno values cannot say which
 * system call refused.
 */
unsigned long sbx_spawn_error(void);

/* Waits for the program to end, sets *exit_code (may be NULL), then closes the job and the process handle. */
int sbx_process_wait(struct sbx_process *process, int *exit_code);

/* Ends the program (closes its job) and closes the handles. */
void sbx_process_close(struct sbx_process *process);

#endif /* _WIN32 */

/* ---- The broker half ---- */

/* Rule modes. A rule covers its path and everything under it; the longest matching rule decides. */
#define SBX_DENY 0u
#define SBX_READ 1u              /* open for reading, stat, access, readlink, chdir, list */
#define SBX_WRITE 2u             /* also open for writing, create, mkdir, unlink, rename */
/* Rule flags, or'ed into the mode. */
#define SBX_CASE_INSENSITIVE 0x10u  /* a name that does not exist matches one that differs only in case */
#define SBX_DECIDE 0x20u            /* ask the decider about every access under this rule, not only refusals */
/*
 * With SBX_READ: on Windows, granted to the AppContainer itself at spawn
 * (an ACL entry for its SID, read and execute, inherited by everything
 * under the folder), so the loader can open the program's own code by
 * path. It stays on the folder. Linux and Android ignore it: the rule is an
 * ordinary brokered one there. Never with SBX_WRITE.
 */
#define SBX_STATIC 0x40u

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
 * On Windows the path is a drive or UNC path, matched case-insensitively,
 * and a rule covers the name as given (the broker checks where each open
 * really leads). Returns 0 or a negative errno.
 */
int sbx_policy_add(struct sbx_policy *policy, const char *path, unsigned mode);

#ifndef _WIN32
/*
 * Makes virtual_path (and everything under it) mean real_path for the
 * confined process: a host can hand over a folder under a fixed name
 * without the confined code knowing where it lives. Rules apply to the
 * real path. Returns 0 or a negative errno.
 */
int sbx_policy_alias(struct sbx_policy *policy, const char *virtual_path, const char *real_path);
#endif

/* One brokered request, as the decider and the audit see it. */
struct sbx_access {
    const char *op;        /* "open", "stat", "access", "readlink", "mkdir", "unlink", "rename", "statfs", "chdir",
                              "getcwd", "list", "chmod", "utimens"; with SBX_LOCK_LEARN "syscall"; with
                              SBX_LOCK_NET_BROKERED also "socket",
                              "connect", "bind", "listen", "accept" */
    const char *asked;     /* the path as the confined code named it */
    const char *resolved;  /* the real path the broker would act on ("" when it could not be resolved) */
    unsigned need;         /* SBX_READ, SBX_WRITE, or 0 for a lookup (stat, access F_OK, traversal) */
    int flags;             /* open flags for "open", else 0 */
    pid_t pid;             /* the confined process (the kernel's word) */
    int rule_verdict;      /* what the rules alone answered: 0 or a negative errno */
    const char *allowed_by; /* for "syscall": the lockdown flag that would have allowed the call
                               ("SBX_LOCK_INET", ...), or NULL when none does; NULL for every other op */
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

#ifndef _WIN32
/*
 * What a process locked down with SBX_LOCK_NET_BROKERED may do on the
 * network: none by default. The decider sees each socket call as an access
 * whose op is "socket", "connect", "bind", "listen" or "accept", whose
 * asked and resolved are the address in words ("203.0.113.5:443",
 * "[2001:db8::1]:80", "*:8384" for any address, a system socket's path), with
 * rule_verdict what the grants alone answered; it is asked about refusals,
 * and about every call when SBX_NET_DECIDE is granted. Sockets are TCP and
 * UDP only. A UDP sendto to an address names it in memory the broker never
 * sees: SBX_NET_CONNECT covers every destination of a datagram.
 */
#define SBX_NET_CONNECT 0x1u  /* outbound: connect TCP and UDP sockets, to any address the decider allows */
#define SBX_NET_LISTEN 0x2u   /* inbound: bind a port, listen, accept */
#define SBX_NET_RESOLVE 0x4u  /* the system resolver's Unix socket */
#define SBX_NET_DECIDE 0x8u   /* ask the decider about every socket call, not only refusals */
void sbx_policy_set_net(struct sbx_policy *policy, unsigned grants);

/*
 * A system service's Unix socket that the broker connects for the process,
 * under the broker's own identity, when the process holds grant (one of
 * the SBX_NET_* grants above, or 0 for always): on Android
 * "/dev/socket/dnsproxyd" for SBX_NET_RESOLVE (name lookups) and
 * "/dev/socket/fwmarkd" for SBX_NET_CONNECT | SBX_NET_LISTEN (bionic's
 * connect and accept report each inet socket there first, and an isolated
 * process may not reach it). The service then sees the broker's UID, with
 * the broker's permissions. At most SBX_SYSTEM_SOCKETS_MAX. Returns 0 or a
 * negative errno.
 */
#define SBX_SYSTEM_SOCKETS_MAX 8
int sbx_policy_add_system_socket(struct sbx_policy *policy, const char *path, unsigned grant);

/*
 * An abstract Unix socket name (without its leading NUL byte) that a
 * process locked down with SBX_LOCK_UNIX may bind (mode SBX_WRITE) or
 * connect to (SBX_READ). Abstract names belong to no folder, so no other
 * rule covers them; none is allowed by default. At most
 * SBX_UNIX_NAMES_MAX. Returns 0 or a negative errno.
 */
#define SBX_UNIX_NAMES_MAX 16
int sbx_policy_add_unix_name(struct sbx_policy *policy, const char *name, unsigned mode);
#endif

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
#ifndef _WIN32
int sbx_broker_prepare(int fd);
void sbx_broker_serve(struct sbx_policy *policy, int fd);
int sbx_broker_start(struct sbx_policy *policy, int fd);

/*
 * One broker for a tree of processes: listens on a SOCK_SEQPACKET socket
 * at socket_path (absolute, under 108 bytes, in a folder only the host's
 * UID can enter; it must not exist yet) and serves every connection that
 * opens with token (16 to 127 bytes, random for each launch) from a
 * process of the broker's own UID (SCM_CREDENTIALS). Each connection is
 * served on its own thread with the one policy, so its decider and audit
 * are called from several threads. A process attaches with
 * sbx_attach() or libsbx_child.so; the processes it forks share its
 * connection, and each request names its own sender. Takes the policy
 * on success (freed when the listener is closed and the last connection
 * ends); returns 0 and the listener, or a negative errno.
 */
struct sbx_listener;
int sbx_broker_listen(struct sbx_policy *policy, const char *socket_path, const char *token,
                      struct sbx_listener **out);

/* Stops accepting and removes the socket; connections already made are served until they close. */
void sbx_listener_close(struct sbx_listener *listener);

/*
 * Attaches the calling process to a listening broker and confines it:
 * connects to socket_path, sends token, and on the broker's answer calls
 * sbx_lockdown on that connection with options. The connection is kept
 * open across exec (its number is put in SBX_BROKER_FD), for the images
 * the process runs. Returns 0, or a negative errno with nothing installed.
 */
int sbx_attach(const char *socket_path, const char *token, const struct sbx_lockdown_options *options);

/*
 * sbx_attach from the environment, as libsbx_child.so's constructor
 * calls it before main: SBX_BROKER (the socket's path), SBX_TOKEN,
 * SBX_FLAGS (lockdown flags, decimal or 0x hex) and SBX_OWN_OPENS
 * (device paths separated by ':', see own_opens). Returns 1 when
 * SBX_BROKER is not set (nothing to attach to), 0 when attached, or a
 * negative errno (the constructor then ends the process before main). On
 * success the token's value is overwritten in the environment strings and
 * SBX_BROKER and SBX_TOKEN are removed.
 */
int sbx_attach_from_environment(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
