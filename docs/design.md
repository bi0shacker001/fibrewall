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

## A UID of its own: an opt-in mode per process (design, 2026-10-16)

Code running under the host's own UID is not confined from the host: Android
lets it reach every component of the host's package, exported or not, and
every permission the host holds, whatever the host checks, and binder
cannot be filtered by seccomp. So a host can choose, per process, to run
confined code under an **isolated UID** (`android:isolatedProcess`, `bindIsolatedService` from
API 29, UIDs 90000-99999, SELinux domain `isolated_app`), and the host grants
what the code may do through the broker, never by sharing its UID. What the
platform allows an isolated process, from AOSP (sepolicy and frameworks as
of Android 8.0 to 15; read from LineageOS's byte-identical mirrors, branch
`lineage-15.1` = 8.1 to `lineage-22.2` = 15):

| Capability | Isolated UID | Source |
| --- | --- | --- |
| Create an INET socket | **no**, any version | `private/isolated_app_all.te` (8 to 13: `isolated_app.te`): `neverallow isolated_app_all { self ... untrusted_app_all }:{ socket tcp_socket udp_socket ... } create`; `ProcessList` gives an isolated process no gids, so no `inet` (3003) |
| Use a TCP or UDP socket the host created and passed (SCM_RIGHTS): read, write, connect, bind, options | **API 30+**; never `ioctl` | `private/isolated_app.te` from Android 11: `allow isolated_app { ephemeral_app priv_app untrusted_app_all }:{ tcp_socket udp_socket } { rw_socket_perms_no_ioctl }`; port checks use the socket's own (host) label |
| `listen` / `accept` on a passed socket | **no** | not in `rw_socket_perms_no_ioctl`; `selinux_socket_accept` checks the caller |
| The GPU (EGL, Vulkan on a hardware driver) | **no**, 8 to 15 | `neverallow { isolated_app_all -isolated_compute_app } gpu_device:chr_file ...`; `isolated_compute_app` is assigned by the system only to its own services (`ActiveServices.generateAdditionalSeInfoFromService`) |
| Service manager lookups | `activity`, `display`, `webviewupdate` only | sepolicy neverallow on `service_manager find`; `ServiceManager.cpp`: `!service->allowIsolated && is_multiuser_uid_isolated` |
| Call a system binder the host hands over | the call is made, as the **isolated** UID: permission, AppOps and calling-package checks fail | `ActivityManager.checkComponentPermission`: "Isolated processes don't get any permissions"; `enforceNotIsolatedCaller` |
| Read and write a file descriptor the host opened | **yes** (no open, no execute, no ioctl; no `map` on 8.1) | `isolated_app_all.te`: `allow isolated_app_all { app_data_file ... }:file { append read write getattr lock map }` |
| Hold an Android permission, or a Shizuku grant | **never** | isolated UIDs have no package; Shizuku's `attachApplication` requires `getPackagesForUid(callingUid)` to contain the caller's package |

**Which hosts use it.** The isolated UID is opt-in, not the library's default.
droidtop runs every plugin under one (owner, 2026-10-16: "every plugin is
isolated, regardless of access"). A host whose code needs the GPU does not:
Enginehost's cores and windowcast keep their app's own UID and SELinux domain,
open their GPU device before the lockdown (`own_opens`), and are confined by
seccomp and the broker alone (owner, 2026-10-16: "For things that NEED gpu, in
other applications, we can forego android's isolation. But nothing in droidtop
will need that").

Two other mechanisms were weighed and set aside. An **app zygote**
(`useAppZygote`, API 29) gives isolated children the same `isolated_app`
domain (faster starts, nothing more). The **SDK Runtime** has its own UID
with network and GPU, but loads only declared SDK packages, never arbitrary
code, and is being retired. A second APK has its own UID and permissions
but is not a library feature (and was declined by droidtop's owner).

So, within one app, a confined process can be given:

1. **Sockets** (`SBX_LOCK_NET_BROKERED`, built): `socket(AF_INET or
   AF_INET6)` traps and the broker creates the socket under the host's UID
   and hands it over (`SBX_SOCKET`); `connect`, `bind`, `listen` and
   `accept` on it trap and the broker does them on the same socket
   (`SBX_CONNECT`, `SBX_BIND`, `SBX_LISTEN`, `SBX_ACCEPT`) after the grants
   (`sbx_policy_set_net`: `SBX_NET_CONNECT`, `SBX_NET_LISTEN`,
   `SBX_NET_RESOLVE`) and the decider, which sees the address in words. A
   blocking connect or accept waits on a broker thread of its own. Reads
   and writes are the process's own. Unix sockets stay the process's, but
   may not be bound or listened on; a connect to a system socket the host
   named (`sbx_policy_add_system_socket`: Android's `dnsproxyd` for name
   lookups, `fwmarkd`, which bionic's `connect` and `accept` report each
   socket to) is the broker's, and the caller's socket is replaced by the
   one the broker connected. Traffic is the host's UID's, so Android's
   per-app network rules see the host. Below API 30 an isolated process
   may not use a socket it was given; a byte relay for those versions is
   planned. A UDP `sendto` names its destination in memory the broker
   never sees, so `SBX_NET_CONNECT` covers every datagram destination.
2. **Drawing without the GPU**: the isolated process renders on the CPU into
   shared memory the host passes (`ashmem`/`memfd`, or an `AHardwareBuffer`
   allocated by the host), and the host composites it. Hardware GPU work
   inside an isolated process is impossible on Android. A confined process
   that keeps its app's own SELinux domain keeps the GPU through
   `own_opens` (it opens the device itself before the lockdown and the
   filter then collapses the rest), as windowcast and Enginehost do; that
   mechanism cannot reach `gpu_device` from `isolated_app`. droidtop's
   owner decided, for its plugins (2026-10-16, verbatim): "Plugins
   shouldn't be drawing stuff themselves anyway", so an isolated plugin
   draws on the CPU, or not at all.
3. **A binder relay** (planned, `sbx_relay`): to use a system service as the
   host's identity, the confined process gets a binder whose every
   transaction a relay in the host's process checks and forwards to the
   real service. The relay is allowlist-only: the host names each service
   and, within it, each transaction code it forwards (and may inspect the
   arguments); there is no pass-through mode, and a transaction not listed
   is refused. Anything that could name a component of the host's own
   package (starting, binding or querying its services, receivers,
   activities and providers) is refused whatever the list says. The
   service sees the host's UID, with the host's permissions, for exactly
   the listed calls. It is how a Shizuku binder obtained by the host can be
   used from a confined process, since Shizuku authorizes by the caller's
   UID and package and an isolated UID can never be granted. droidtop's
   owner decided (2026-10-16, verbatim): "every plugin is isolated,
   regardless of access. We have to assume that plugins are untrusted
   third party code from our perspective, so full access does NOT mean
   they get to fuck with stuff not prescribed by the API"; so droidtop
   runs every plugin isolated and gives full access only this relay, with
   the list its declared API points prescribe.

What cannot be had at all, by any means inside one app: a confined process
with an identity of its own that holds Android permissions or a Shizuku
grant. Such code either uses the relay (the host's identity, filtered) or
runs under the host's UID (not confined from the host).

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
  statfs, chdir, fchdir, getcwd, chmod/fchmodat (the broker keeps the
  permission bits, `0777`, under a write rule) and utimensat with a path
  (its two times travel in the request; `futimens`, on a descriptor, is
  untouched).
- **Refuses with ENOSYS, so callers fall back.** statx, openat2, clone3,
  fchmodat2.
- **Refuses with EACCES.** Any other path call: truncate, link, symlink,
  mknod, chown, utime/utimes/futimesat, xattrs on a path, inotify and
  fanotify marks, file handles. Also execve(at), socket (a Unix datagram
  socket for the system log can be allowed with `SBX_LOCK_LOG_SOCKET`, or
  inet sockets with `SBX_LOCK_INET`), bind and connect (open again with
  the sockets those flags allow), ptrace, process_vm_readv/writev, process_madvise, bpf,
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

**Process-bound devices.** Some device files cannot come from the broker,
because the kernel ties what they hold to the process that opened them. A
broker-opened `/dev/hwbinder` fails to `mmap` in the confined process. GPU
nodes that keep per-process state behave the same way: kgsl, Mali, DRM
render nodes. `sbx_lockdown_options.own_opens` names such paths. The
process opens them itself just before the filter goes on, and after that
an open of exactly one of those paths gets a duplicate. Each host keeps the
list for its platform. Enginehost's is `/dev/hwbinder`, `/dev/kgsl-3d0`,
`/dev/mali0` and `/dev/dri/renderD128`; `/dev/vndbinder` is left out,
because an app cannot open it at all. A native-kind process that never
needs binder seals those descriptors instead.

**Local files.** `sbx_local_add(path, fd)` gives the process a file under
a name of the host's choosing, read only: an open of exactly that path gets
a duplicate, and stat and access answer from the descriptor, in the
handler, with no broker and no rule. It works before or after lockdown, so
a host can hand over code and data as it loads them.
`sbx_local_add_mode(path, fd, SBX_READ | SBX_WRITE)` hands over a file the
host opened for writing, to be written by name (droidtop's `open` for a
Flutter plugin, whose `dart:io` can only open paths): every open of the
path is a duplicate of that one descriptor, sharing its position, and
`O_TRUNC` empties the file; adding the path again replaces the descriptor
and the mode, which is how the host lets one go. Own-opened devices are
local files too (read and written). This is how droidtop's isolated plugin
processes see the files it hands them as descriptors at virtual paths:
every library that opens a path is covered, not only the ones a PLT hook
reached.

**Passthrough** (`SBX_LOCK_PASSTHROUGH`) is for a process another wall
already guards, where the broker's job is to add folders, not to take the
kernel's place: an Android isolated process, whose UID and SELinux domain
keep every app's files out, given its own folder through a broker in the
app. Only paths under `claims` go to the broker. The handler makes every
other path call itself, with the kernel deciding, as if there were no
filter. Its calls name an absolute path (a relative one is rewritten as
`/proc/self/fd/<directory>/<path>`, which the kernel walks from that same
directory) and carry a directory argument that is no descriptor, the one
value the filter lets through untrapped. Code that uses that value itself
gets only what the kernel would give the process anyway. A relative path
is claimed when the folder it lands in is (the directory's name from
`/proc/self/fd`, joined to it). chmod and utimensat with a path follow
the same split (droidtop's Android `FileUtils.setPermissions` on a claimed
alias got `ENOENT` from the kernel before they did). truncate, link,
xattrs and the other path calls the broker does not make go to the
kernel, as in the unbrokered mode.

**Listing in passthrough.** getdents64 names no path, but an Android
isolated process may not read a folder its app opened for it (`avc:
denied { read } ... isolated_app`), so a folder the broker handed over
could be opened and not listed. In passthrough getdents64 traps. The
handler lists the folder itself first, its own call marked in the upper
half of the count (which the kernel ignores, `unsigned int count`) so the
filter lets it through; only when the kernel refuses it (`EACCES`) does it
send the descriptor to the broker (`SBX_LIST`), which lists it when the
folder it names may be read, from that same open file description: the
position moves for both, and `lseek`/`rewinddir` work as before. One reply
carries at most `SBX_LIST_MAX` (32 KiB) of records; a longer read is
answered short, as the kernel may answer it.

**Network** (`SBX_LOCK_INET`) is for a process that talks to the network
itself, such as droidtop's Syncthing plugin (Droidtop/tracker#553): it
dials peers and listens for them, so the host cannot open its sockets for
it. socket is allowed for `AF_INET` and `AF_INET6` with `SOCK_STREAM` or
`SOCK_DGRAM`, and connect and bind are open. Raw sockets, netlink and every
Unix socket stay refused; socketpair is untouched, as in every mode. The
filter cannot read the address bind is given, so bind is open only because
inet sockets are then the only ones the process can make. That is why the
flag cannot be combined with `SBX_LOCK_LOG_SOCKET`: its Unix datagram
socket could bind a name in the file system or the abstract namespace, and
`sbx_lockdown` answers `-EINVAL`. The kernel's own network checks (an
Android app's `inet` group) still apply underneath.

On Android, bionic's `connect` and `accept` report each inet socket to
netd over a Unix stream socket (`/dev/socket/fwmarkd`), which this flag
refuses, so they fail there; the test measures this (an `info` line on the
emulator). Code that makes the calls itself, as Go does, is unaffected. C
code in such a process needs another answer from its host before it can
use bionic's calls.

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

The rules decide on the **resolved** path. A caller may name a place
through an alias, either the system's own (`/sdcard`, `/data/user/0`) or
one of the policy's, but what gets acted on is always what the path
resolves to. Only a path that does not resolve is decided on its lexical
form.

**The broker never stats on the confined code's behalf.** It resolves
symlinks with `readlink()` alone, and makes exactly the call it was asked
for. It runs in the same SELinux domain an app's code does, and a
`getattr` can be refused there where the asked-for call is allowed. On the
emulator, the broker's stat of `/system/bin/hwservicemanager` was refused,
although libhidl only `access()`es it. That sent libhidl down its
passthrough path and aborted the allocator (Enginehost's lockdown
prototype, Droidtop/tracker#26).

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
- **Binder in an ART process.** seccomp cannot read binder transactions,
  and ART needs binder. A confined ART process can still ask system
  services for things as its app.

  A process without ART can lose binder even when its graphics stack
  opened it. Every transaction is an `ioctl` on the binder descriptor.
  `sbx_lockdown`'s sealed descriptors refuse ioctl, mmap, fcntl and dup on
  a descriptor the process keeps. On the emulator (API 28 and 34), libEGL
  and the gralloc mapper opened `/dev/hwbinder` and `/dev/binder` during
  setup. The probe then drew and imported a second buffer with both
  sealed (`tests/android/gpu_probe.c`).
- **Kernel bugs** in the system calls left open, the GPU driver's ioctls
  above all. Also denial of service (rlimits help) and timing side
  channels.

## Testing

`tests/sbx_test.c` runs every escape attempt twice: once unconfined as a
control, then confined. A test cannot pass because the host refused
something on its own. It also runs what must keep working and a symlink
race. CI runs it on Linux (gcc, clang, ASan and UBSan) and on the Android
emulator at API 28 (kernel 4.4) and API 34 (kernel 6.1).

`tests/android/gpu_probe.c` measures the native kind on a real device. A
re-executed child brings up EGL and imports a buffer its parent allocated.
It then locks down with its binder descriptors sealed, draws timed frames,
and imports a second buffer after lockdown. The parent checks the pixels.
On every push to main, CI publishes both binaries for both ABIs as the
rolling prerelease `probe-latest`, so a rig can run them with adb alone:

```sh
adb push sbx_test-arm64-v8a gpu_probe-arm64-v8a /data/local/tmp/
adb shell 'cd /data/local/tmp && chmod 755 sbx_test-arm64-v8a gpu_probe-arm64-v8a && TMPDIR=/data/local/tmp ./sbx_test-arm64-v8a; ./gpu_probe-arm64-v8a; ./gpu_probe-arm64-v8a --no-seal'
```

## Planned

- **minijail policy files** (BSD-3, vendored unmodified under
  `third_party/`), for deny-by-default allowlists per kind of process.
- **The `native` launcher.** It sets up descriptors, limits, code loaded
  from memfd, GPU driver warm-up and shared frame buffers, then locks down
  and runs an engine. It has no ART and no binder.
- **A byte relay for sockets below API 30**, where an isolated process may
  not use a socket it was given (the rest of `SBX_LOCK_NET_BROKERED` is
  built).
- **A binder relay** (`sbx_relay`) with a per-service, per-transaction
  allowlist, from the same section.
- **An Android AAR** with a Kotlin API over the same C core.
- **Desktop-only hardening**: Landlock and namespaces, under the same
  broker.
