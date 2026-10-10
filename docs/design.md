# Design

## What it is for

The library runs code you do not trust (a plugin, a game engine, a game's
scripts) in a process that can reach:

- the files a host allows;
- descriptors the host hands over;
- nothing else.

It is a general library. It knows nothing about any one host, so a host's
own concepts stay in that host as a thin layer on top. For example: plugin
tiers, permission wording, consent prompts.

## What the platform allows (why this shape)

An unprivileged process on Android can confine itself only with
**seccomp-bpf**, plus Android's own `isolatedProcess` UID where the code
can live without the GPU. The other mechanisms are not available there:

| Mechanism | Android | Desktop Linux |
| --- | --- | --- |
| seccomp-bpf, `TSYNC`, `RET_TRAP`/`ERRNO` | yes, every supported kernel | yes |
| `SECCOMP_RET_USER_NOTIF` | kernel 5.0+ only (not 4.19 handhelds) | yes |
| Landlock | no: off in GKI kernels, and not in bionic's app seccomp allowlist | 5.13+ |
| unprivileged user namespaces | no: `CONFIG_USER_NS` off, and SELinux forbids an app any capability in one | usually |
| `openat2(RESOLVE_BENEATH)` | 5.6+ only | yes |

Every device has seccomp-bpf, so the design rests on it alone. A seccomp
filter sees system-call numbers and integer arguments, never the memory a
pointer names, so it cannot tell one path from another. Paths therefore go
to a **broker** in another process, as in Chromium's
`sandbox/linux/syscall_broker`.

## The confined side (`src/lockdown.c`)

`sbx_lockdown(broker_fd, flags)` does three things:

1. installs a SIGSYS handler;
2. sets `PR_SET_NO_NEW_PRIVS`;
3. adds a filter with `SECCOMP_FILTER_FLAG_TSYNC`.

Either every thread is confined, or nothing is installed and an error comes
back. A caller that gets an error must not run the untrusted code.

The filter:

- **Traps to the broker.** open, creat, stat/lstat/newfstatat, access and
  faccessat(2), readlink(at), mkdir(at), unlink(at), rmdir, rename(at/at2),
  statfs, chdir, fchdir, getcwd.
- **Refuses with ENOSYS, so callers fall back.** statx, openat2, clone3.
- **Refuses with EACCES.** Any other path call: truncate, link, symlink,
  mknod, chmod/chown, utimes on a path, xattrs on a path, inotify and
  fanotify marks, file handles. Also execve(at), socket (a Unix datagram
  socket for the system log can be allowed with `SBX_LOCK_LOG_SOCKET`),
  bind, connect, ptrace, process_vm_readv/writev, process_madvise, bpf,
  perf_event_open, io_uring. Also a call through another architecture's
  entry (x32 or `int 0x80` on x86_64).
- **Refuses with EPERM.**
  - Namespaces and mounts: clone with any `CLONE_NEW*` flag, unshare,
    setns, mount and the new mount API, pivot_root, chroot.
  - The keyring, kcmp, the pidfd calls, tkill.
  - kill, tgkill and the sigqueue calls aimed at any process but this one.
  - A new SIGSYS handler.
- **Allows everything else,** including every call on a descriptor.

Android's own app filter stays underneath. Filters stack, and the most
restrictive answer wins.

The handler is **not** the trust boundary. Code that replaces it, or calls
the kernel directly, only loses its own file access. The broker decides.
The handler is async-signal-safe: no heap and no locks. Each request gets a
fresh reply socketpair, so threads share nothing.

The confined process cannot change directory for real (it may not be able
to open what it enters). So the handler keeps the current directory as a
descriptor the broker gave it, sends it with each relative request, and
answers `getcwd` through the broker.

## The broker (`src/broker.c`)

For each request the broker:

1. makes the path absolute against the directory descriptor that came with
   it;
2. normalises it lexically and maps it through the aliases;
3. rewrites `/proc/self` and `/proc/thread-self` to the sender, whose pid
   comes from `SCM_CREDENTIALS`;
4. folds case under a case-insensitive rule;
5. checks the rules on that path;
6. resolves the path as the kernel would, and checks the rules again on the
   result;
7. asks the host's decider when the rules refused, or when the matching
   rule is marked `SBX_DECIDE`;
8. audits the result.

A refusal is always `EACCES`. It never says whether the path exists.

The call itself is made **relative to the resolved parent directory**. The
broker opens that directory with `O_PATH|O_DIRECTORY`, confirms through
`/proc/self/fd` that it is still the directory that was checked, and acts
on the final name with `O_NOFOLLOW`. An opened descriptor is checked once
more on what it names. So a symlink swapped in during a request cannot
make the broker create, truncate, rename or remove anything outside the
rules. The test runs that race thousands of times.

Rules:

- Modes: `SBX_READ` (read, stat, list, chdir) and `SBX_WRITE` (also write,
  create, mkdir, unlink, rename).
- The longest matching rule decides.
- Ancestors of a rule can be looked up but not listed.
- A process's own `/proc/<pid>` is always allowed; other processes' entries
  never are.
- Flags: `SBX_CASE_INSENSITIVE` and `SBX_DECIDE`.

`sbx_policy_alias` maps a fixed virtual folder onto a real one, and
`getcwd` answers with the virtual name.

The decider is how a host's permission system takes part in every file
access without the library knowing what a plugin is. It can grant one file
the rules refuse, such as a document the person just picked. It can refuse
what the rules allow, such as a folder whose grant was revoked. It runs on
the broker's thread, and the confined call waits for it.

## What it does not stop

- **Anything on a descriptor the process already holds.** It runs with the
  process's own UID. Run it under a separate UID (Android `isolatedProcess`)
  wherever the code can do without the GPU.
- **Binder.** seccomp cannot read binder transactions. A confined ART
  process can still ask system services for things as its app. The planned
  `native` launcher closes this: a process with no ART that never opens
  `/dev/binder`.
- **Kernel bugs** in the system calls left open, the GPU driver's ioctls
  above all. Also denial of service (rlimits help) and timing side
  channels.

## Planned

- **minijail policy files** (BSD-3, vendored unmodified under
  `third_party/`), for deny-by-default allowlists per kind of process.
- **The `native` launcher.** It sets up descriptors, limits, code loaded
  from memfd, GPU driver warm-up and shared frame buffers, then locks down
  and runs an engine. It has no ART and no binder.
- **A broker `connect` grant**, which hands back a connected socket.
- **An Android AAR** with a Kotlin API over the same C core.
- **Desktop-only hardening**: Landlock and namespaces, under the same
  broker.
