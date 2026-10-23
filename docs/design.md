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
- **Traps and makes it on the thread's saved mask:** `rt_sigprocmask`, with
  SIGSYS always left open ("SIGSYS stays open", below).
- **Allows everything else,** including every call on a descriptor.

Android's own app filter stays underneath. Filters stack, and the most
restrictive answer wins.

**SIGSYS stays open** (2026-10-22). A trapped call on a thread that has
SIGSYS blocked does not reach the handler: the kernel resets SIGSYS to its
default action and the whole process dies by signal 31, with no tombstone,
since debuggerd's handler is reset too. Enginehost's LÖVE core died exactly
this way about 40 ms after lockdown, 143 times in a row on BlueStacks
(Droidtop/tracker#550), and a plain Linux reproduction (block SIGSYS, then
open an allowed file) dies the same way. Libraries block signals on their
threads routinely, often all of them. So:

- `rt_sigprocmask` traps, and the handler makes the call on the interrupted
  thread's saved mask (`uc_sigmask`), which the kernel installs when the
  handler returns: the effect of the call, with SIGSYS always left out.
  `pthread_sigmask`, bionic's own thread start and a library that blocks
  "everything" all go through it. The old mask comes back as asked; a bad
  `how` or size is `EINVAL`, as from the kernel.
- `sbx_lockdown` answers `-EDEADLK` when a thread already has SIGSYS blocked
  (read from each thread's `SigBlk` before the filter goes on), since that
  thread would kill the process on its first trapped call. Nothing is
  installed. A thread that has exited is skipped: it can still be listed,
  with its last mask, for a moment after `pthread_join` returns. A thread
  that blocks SIGSYS between that check and the filter is the one gap left.
- **Handler masks** (2026-10-23). While a signal handler runs, the kernel
  blocks the signals in its mask, and libraries install handlers with every
  signal masked (ART's signal chain among them). A trapped call made inside
  one, or an `rt_sigprocmask` there, killed the process by signal 31 just
  the same: Enginehost's LÖVE core still looped on it with the thread masks
  fixed, and learning recorded nothing, since the record travels through the
  same trap. So `sbx_lockdown` first takes SIGSYS out of every installed
  handler's mask (raw `rt_sigaction`, since ART interposes `sigaction()`).
  After it, `rt_sigaction` traps, and the handler installs the new handler
  with SIGSYS left out of its mask, through the library's trampoline, which
  the filter lets through for `rt_sigaction` alone, after refusing a new
  SIGSYS handler. A handler whose mask SIGSYS was taken from can now be
  interrupted by SIGSYS, which only ever comes from our own traps.
- A process locked down `SBX_LOCK_UNBROKERED` traps nothing and is
  unaffected.

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

## Layers, containment, and Wine and proot under the broker (design, 2026-10-22, Droidtop/tracker#584)

Status: design only, nothing here is built. It adds three things to the
broker above and no second mechanism: the policy (rules, aliases, decider)
stays the one place that decides, and every enforcement point described
below evaluates that same policy.

Why: droidtop's Wine prefix is a whole directory tree that is copied per
prefix, and Wine and proot run with the app's full reach (an incident on
2026-09-02 emptied internal storage through a prefix's `dosdevices/z:`
link; droidtop's SPEC 5b "Destructive-operation audit"). Owner,
2026-10-17: "using the sandbox broker actually isn't a bad idea. It gives us
more containment as well. Something running in a wine or proot context
couldn't, say, suddenly nuke the entire internal storage (still angry about
that)." And: "We also need some deduplication system for it, too."

Constraints that shape it (all from the platform section above and
droidtop's targets):

- No kernel copy-on-write without root. ext4 and f2fs have no reflinks;
  overlayfs needs mount rights; there are no user namespaces on the
  Retroid Pocket 5. Layers are therefore the broker's own, in user space.
  overlayfs may be used as an optional speed-up where the host already has
  root (never required, never the only path; see "Optional kernel help").
- The broker only sees what the filter traps. A layer is a view the broker
  builds, so every process that must see it is brokered.
- Android's own isolation stays on top where it exists. This section is the
  library's own wall, and it applies whether or not Android's applies
  (owner: "Our sandbox always applies").

### 1. Copy-on-write layers

#### Model

A **layered tree** is mounted at a virtual path (for Wine, the prefix path
the program was told: `WINEPREFIX`). It has one **upper** directory (the
game's layer, read-write) and an ordered list of up to 8 **lowers**
(read-only bases, topmost first). For Wine: lower 0 is the base prefix of
one Wine build; a second lower may later hold a component set (a DXVK
version) shared by several games. The policy call is

    sbx_policy_add_layer(policy, virtual_root, lowers, lower_count, upper, flags)

Rules apply to the real paths, as for an alias (see "The broker"): the
upper is granted `SBX_READ | SBX_WRITE`, every lower `SBX_READ`. The
confined process never sees a real path of either. Flags:
`SBX_LAYER_CASE_INSENSITIVE` (the broker folds case against the merged
listing, which is what Wine's slow path does itself by scanning a directory),
`SBX_LAYER_BASE_MODES` (see "Modes").

A name resolves top-down: upper, then each lower in order. The first layer
that has the name answers, unless the entry there is a **whiteout**, in
which case the name does not exist. A directory exists in the merged tree
if any layer has it as a directory; its contents are the union, unless the
upper's copy is **opaque**, which hides the lowers' contents.

A lower is immutable while any layer refers to it: the broker never opens
it for writing, and the host marks its files read-only (mode `0444`, `0555`
for directories) so that the host's own code cannot write into it by
accident either. Layers that have no lower are an ordinary directory; the
mount is a no-op, so an existing full prefix keeps working unchanged.

#### On-disk representation

Nothing depends on extended attributes (Android's SELinux policy and f2fs
make them unreliable for app files).

- **Whiteout**: a symbolic link in the upper, named as the deleted entry,
  whose target is the reserved string `.sbx-whiteout`. There is exactly one
  directory entry per name, so a delete and a re-create replace it with one
  `rename(2)`, which is atomic. A confined process cannot make a symlink
  with that target (`EINVAL`), and the merged view never shows one:
  `lstat` answers `ENOENT`, listings omit it.
- **Opaque directory**: a file `.sbx-opaque` inside the upper's directory.
  Names beginning `.sbx-` are the broker's: a confined process may not
  create, rename or remove one, and listings hide them.
- **Copy-up temporary**: `.sbx-tmp.<boot-id>.<n>` in the destination
  directory (same file system as the final name, so the rename is atomic).
- **Layer record**: `.sbx-layer` at the upper's root: format version and the
  identity (id and content hash) of each lower. A layer whose lower is
  missing or different is not mounted (the host reports it; see droidtop
  SPEC 5b), never mounted wrongly.

#### Lookup and the merged view

The broker already resolves a path component by component with `readlink`
alone and acts relative to an `O_PATH` parent (see "The broker"). With
layers, each component is looked up in the layers in order using
`fstatat(AT_SYMLINK_NOFOLLOW)` on the layer's own parent descriptor; this
is the broker's stat of its own files, not on the confined code's behalf,
so the rule above ("never stats on the confined code's behalf") is about
asked-for paths and stays true.

A symlink found in a lower is resolved in the merged tree, not in the
lower: an absolute target is looked up from the confined process's virtual
root, a relative one from the link's merged directory, so a link in a base
that points at another base file reaches the layer's copy if there is one.
The resolved path is then checked against the rules as before (a link out of
the layered tree is judged where it lands; this is how `dosdevices/z: -> /`
is refused when the device root is not granted).

Results are cached per layered tree (a dentry cache keyed by the merged
path: positive, negative and whiteout entries), invalidated per directory by
any mutation made through the broker, and dropped when the host calls
`sbx_layer_changed()`. The host edits an upper directly only before a launch
(see droidtop SPEC 5b), so no cross-process invalidation is needed at run
time.

**Identity.** `st_dev` is one synthetic value for the whole layered tree;
`st_ino` is the file's own when the layers share a file system, else a hash
of (source device, inode). The prefix root is the upper's directory, so
wineserver, which names its server directory from the prefix's device and
inode, gets a distinct, stable name per layer. An inode changes when a file
is copied up (overlayfs without `xino` does the same); nothing in Wine
keeps an identity across a write-open of a file.

**Modes.** With `SBX_LAYER_BASE_MODES` the broker reports a lower's regular
files as `mode | 0200` and directories as `mode | 0300`, since the host made
them read-only on disk, and a copy-up gives the copy that mode. `access(W_OK)`
on a lower file therefore answers yes, as it would on a normal prefix, and
the write succeeds by copy-up.

#### Copy-up

Triggers (the first of these on a name that exists only in a lower):
`open` for writing, with `O_TRUNC` or `O_CREAT` or neither; `truncate`;
`chmod`; `utimensat`; `rename` or `unlink` or `rmdir` of it (see below);
`link` with it as the source.

Procedure, for a file `F` in directory `D`, under a lock held for the path
(striped by hash, so two processes writing the same file wait for each
other and the second finds the copy):

1. Make every missing ancestor in the upper (`mkdirat`, with the lower's
   mode and times). An ancestor that is a whiteout makes this `ENOENT`.
2. Open the lower's file read-only.
3. Create `.sbx-tmp.*` in the upper's `D` with `O_EXCL`.
4. Copy the data (`copy_file_range`, falling back to `sendfile` and then
   read/write; holes preserved with `SEEK_DATA`/`SEEK_HOLE`), then mode and
   times. With `O_TRUNC` nothing is copied.
5. `fsync` the temporary file.
6. `renameat` it over `F` in the upper. If `F` is a whiteout this replaces
   it, which is the re-create case.
7. Open the final name as the caller asked and hand that descriptor over.

Crash safety: before step 6 the upper has no `F` (the merged view still
shows the lower's, unchanged); after it the upper's `F` is complete,
because the data was flushed first. The only debris is a `.sbx-tmp.*`,
removed the next time any copy-up enters that directory (the boot-id in the
name tells a stale one from a live one), and when the host opens a layer.
Directory fsync is not done by default (a lost rename is the same as the
crash before step 6); `SBX_LAYER_DURABLE` adds it for hosts that need the
write to survive power loss.

A write-open of a large lower file copies it all, because the broker only
learns that the descriptor will be written when it is asked to open it. The
wanted layout keeps bases small (Wine's own files; no game data), and the
broker logs and counts every copy-up with its size (`op` "copyup" in the
audit), so a host finds a surprising one in its rig.

#### mmap

The descriptor handed over for a read-only open of a lower file is the
lower's own file. `mmap` of it works unchanged: `PROT_READ`, `PROT_EXEC` (a
DLL or `.so` loaded from the base) and `MAP_PRIVATE` with `PROT_WRITE`
(kernel copy-on-write of the mapping; the file is not changed). A writable
`MAP_SHARED` mapping needs a descriptor opened for writing, and that open
copied the file up first, so it maps the upper's copy. A descriptor opened
before a copy-up keeps showing the lower's bytes after another open has
written the upper's copy; this is overlayfs's documented behaviour and is
accepted. The filter does not need to change for any of this: `mmap` is
untouched except on sealed descriptors.

#### Unlink, rmdir

- Name only in the upper: `unlinkat` it.
- Name in a lower (alone or also in the upper): atomically replace the
  upper's entry with a whiteout (create the whiteout with a temporary
  name, `rename` it over the name). No copy-up of the data.
- `rmdir` of a merged directory is allowed only when the merged listing is
  empty. The upper's directory then holds only whiteouts and `.sbx-opaque`;
  the broker unlinks those named entries one at a time (never a tree walk,
  never following a link), removes the directory, and leaves a whiteout if a
  lower has it. A crash between these steps leaves a directory that is
  still empty in the merged view.
- A directory removed and made again at the same name gets `.sbx-opaque`
  before it becomes visible (made under a temporary name, then renamed; a
  whiteout is removed first, so a crash there leaves the name deleted).

#### Rename

- File, name in the upper only: `renameat` in the upper.
- File with a lower copy: copy-up of the source, `renameat` in the upper,
  then a whiteout at the old name, in that order. A crash after the rename
  and before the whiteout shows the file at both names (a duplicate, never
  a loss). The other order (whiteout first) could lose the file, so it is
  not used.
- Directory that exists in a lower: overlayfs answers `EXDEV` and leaves
  the caller to copy. Wine does not retry, so the broker copies the
  directory up first (a copy, never a delete) when it has at most
  `SBX_LAYER_RENAME_MAX` entries (default 4096), renames it, and leaves a
  whiteout; above the limit it answers `EXDEV`. The destination, if it
  exists, follows `rename(2)` (a directory only over an empty directory).
- Flags: `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are applied to the merged
  view's answer (`EEXIST`, `ENOENT`); `RENAME_EXCHANGE` of two names that
  need copy-up copies both up first.

#### Hard links, symlinks, truncate

The filter refuses `link`, `symlink` and path `truncate` today
(`src/lockdown.c:1116-1121`, reply `EACCES`), and Wine uses all three
(`dosdevices` links, `NtSetInformationFile` link and rename information,
`SetEndOfFile` on a name). A new flag `SBX_LOCK_PATHOPS` makes them trap to
the broker as `SBX_LINK`, `SBX_SYMLINK` and `SBX_TRUNCATE`; without it they
stay refused as now, so no existing host changes behaviour.

- `link(old, new)`: copy-up of `old` if it is only in a lower, then `linkat`
  inside the upper. Both names then share the upper's inode. Two names that
  were hard links inside a lower are separate files after a copy-up of
  either (a prefix has none that matter; stated so it is not a surprise).
  A link to a file outside the layered tree is refused as a cross-rule link.
- `symlink(target, new)`: created in the upper. The target is stored as
  given, never rewritten, and judged when followed (a link to a place the
  rules do not grant is a link that cannot be followed).
- `truncate(path, n)`: copy-up (without data when `n == 0`), then
  `truncate` of the upper's copy by the broker.

**Built (2026-10-23, without layers):** `SBX_LOCK_PATHOPS` traps `linkat`,
`symlinkat` and `truncate` (and `link`, `symlink` on x86_64) to the broker.
Without layers, `link` needs **both** names writable (a link to a file the
process may only read would let it write that file), `symlink` the new
name, and `truncate` the file, which the broker opens non-blocking (a FIFO
cannot hold it) and truncates. `linkat` with `AT_SYMLINK_FOLLOW` is decided
on what the link resolves to. Copy-up joins these when layers are built.
`SBX_LOCK_INOTIFY` lets `inotify_add_watch` through to the kernel: the
owner's containment policy for Wine allows change notifications
(Droidtop/tracker#584, 2026-10-23), at the cost that the process can learn
the names of files changing in folders the rules do not grant (it can open
none of them). `init_module`, `finit_module` and `delete_module` are on the
refused list in every mode (the kernel refuses them anyway without
`CAP_SYS_MODULE`; this keeps them refused if the process ever had it).

Not brokered, still refused: `mknod`, `chown` and friends, xattrs on a path,
`inotify`/`fanotify` marks without `SBX_LOCK_INOTIFY` (Wine's change notifications fail with the same
error it already handles when `inotify` is unavailable; a later
`SBX_WATCH` could add a mark on an `inotify` descriptor the process hands
over, as the socket calls do).

#### Directory listing

`getdents64` names no path, so the filter lets it through, and a merged
directory cannot be listed by the kernel. The design reuses the mechanism
that passthrough listing already has (see "Listing in passthrough"; the
handler in `src/lockdown.c` lists a folder itself first and falls back to
`SBX_LIST` when the kernel refuses):

- For a directory that exists in a lower as well as the upper (or only in a
  lower), the broker hands over an `O_PATH` descriptor of the upper's
  directory (or of the lower's) instead of a readable one. `openat`,
  `fstatat`, `fchdir` and `fstat` work on it; `getdents64` on it fails with
  `EBADF` in the kernel.
- The handler already tries the kernel first. With `SBX_LOCK_PATHOPS` it
  forwards `SBX_LIST` on `EBADF` as well as on `EACCES`.
- The broker builds the merged list once per open directory description (a
  snapshot: layers in order, a name seen in a higher layer hiding the same
  name below it, whiteouts and `.sbx-` names dropped, `d_type` and a
  synthetic `d_ino` filled in, opaque upper directories not descending).
  The snapshot is served in `SBX_LIST_MAX` pieces; the read position is
  kept in the descriptor's own file position, which the broker sets to the
  index of the next record, so `lseek(fd, 0, SEEK_SET)` and `rewinddir`
  restart the snapshot with no new request type. (To be checked on ext4 and
  f2fs with 4.19 and 6.1 kernels: that `lseek` on a directory descriptor
  accepts small arbitrary offsets there. If one refuses, the snapshot is
  keyed by the description's inode and a `getdents` at position 0 starts a
  new one.)
- A directory that exists only in the upper, and has no lower counterpart,
  is handed over as an ordinary readable descriptor: its listing is the
  kernel's own and costs nothing. Most of what a running game touches (its
  saves, its temporary files) is of this kind.
- The snapshot is shared by all descriptors of the same directory until a
  mutation of that directory through the broker drops it, because Wine
  scans a directory again for each case-mismatched lookup.

#### Cost of the layers themselves

On disk: a layer holds only what the game changed (registry hives, files
it installed, its drive links and the components droidtop wrote for it) plus
one symlink per whiteout. Copy-up is the one-off cost of a first write per
file. Reads of base files are the lower's own descriptors: no copy, no
broker work after the open. The per-open cost is the broker's lookup, one
`fstatat` per layer per component on a cache miss.

### 2. Path containment

The broker's rules already refuse every path not granted (modes and
longest-match rule, "The broker"; a refusal is `EACCES`; unlink and rename
need `SBX_WRITE` on the resolved path). What this section adds is the
**granted set** a host builds for a program such as Wine, and the rule about
wide grants. The library takes no side on which folders; droidtop builds the
list (droidtop SPEC 5a).

A process that holds nothing but the following can reach nothing else, so
it cannot delete or rewrite anything else:

1. **Its prefix**: the layered tree (upper `SBX_READ | SBX_WRITE`, lowers
   `SBX_READ`).
2. **The runtime it executes**: the Wine build, the emulators, the
   graphics drivers it loads and the system files Android gives every app,
   all `SBX_READ`. The Android part (system, vendor, apex, the device nodes
   a graphics driver opens) is a **platform preset**,
   `sbx_policy_add_platform_readonly(policy, platform)`, one list in the
   library that Enginehost's rules and droidtop's Wine rules both use
   (owner, 2026-10-22, "8: Yes"), so the list is written once; a host adds
   only what is its own. The writable parts of the runtime are named one by one
   (the guest's temporary directory, the sockets, the shared-memory files
   for controllers, the shader caches), `SBX_WRITE`. No other part of the
   host's private folder is granted. In particular **another game's layer and
   the host's databases, keys and settings are outside the set**, so one
   game cannot read or rewrite another's.
3. **The game's folder**, `SBX_READ` only, with the subfolders the host
   names writable (droidtop: any folder called `saves` or `savegames`, and
   the folders the person adds per game; owner, 2026-10-22: "Determinant? A
   folder named 'saves' or 'savegames', yes. Users can configure it
   otherwise"). A longer `SBX_WRITE` rule under a `SBX_READ` one is the
   existing longest-match behaviour; nothing new is needed. The audit shows
   a refused write by path, which is how a host finds a folder to add.
4. **The shares the person declared**, each with the mode the person chose.
5. **Device nodes the process opens before the filter** (`own_opens`, see
   "Process-bound devices"): the GPU nodes of the platform.

The set is learned before it is enforced. A host can run a launch with the
decider returning allow and writing every access the rules would have
refused to its log (`rule_verdict` is already in `struct sbx_access`), play
through the game's start, and fix the list from that. droidtop does this
first for Wine on the rig and on the BlueStacks emulator and records the
list in its SPEC; only then are the rules enforcing.

#### Wide grants

A **wide grant** is a rule that covers a place the process would not
otherwise reach and that holds things beyond the program's own: the device
root `/`, an internal-storage volume root (`/storage/emulated/N`,
`/sdcard`), a removable volume root, or any directory above the host's own
private folder or above another granted set. The library cannot know which
those are for a host; droidtop classifies them (droidtop SPEC 5a) and the
library provides the one thing both sides need: a rule can be given a
**revocable tag** (`sbx_policy_add_tagged(policy, path, mode, tag)`) and the
decider is asked about every access under it (the rule is `SBX_DECIDE`
implicitly), so a grant switched off while the game runs stops working at
once, and the audit names the tag a refusal came from.

Two rules for wide grants, which the library enforces and the host cannot
forget:

- A wide grant never overrides a deny. A rule `SBX_DENY` on a longer path
  wins (the longest rule decides), so a host that grants `/storage/emulated/0`
  can still deny its own private folder under it, or another game's layer.
  droidtop always adds those denies; "everything on the device's storage"
  never means droidtop's own secrets.
- A symlink never widens a grant. A link is judged by where it resolves,
  which is why `z: -> /` in a prefix does nothing when `/` is not granted.
  The broker never follows a link out of a granted tree on the host's
  behalf. (The 2026-09-02 incident was a host-side delete that followed
  `z:`. A host's own recursive operations on a prefix still need their own
  fence; the library offers the layer operations in section 4, which never
  follow a link.)

### 3. Wine and proot under the broker

#### What changes on the confined side

Today a confined process cannot run another program, cannot use Unix
sockets, and cannot ptrace, and the SIGSYS handler is set once in the
process that called `sbx_lockdown` (see "The confined side"). Wine is a
tree of processes that talk over Unix sockets and exec each other, and
proot is a ptrace tracer. Three additions, each a flag, so no existing host
changes behaviour:

1. **`SBX_LOCK_EXEC`**: `execve` and `execveat` are allowed. The filter
   cannot read the path, so it does not check it, and this is safe by the
   model above: the filter is inherited across `exec` and `PR_SET_NO_NEW_PRIVS`
   keeps it, so an image the process runs is confined exactly as the
   process was, and everything it does that names a path still traps. What
   is lost across `exec` is the handler, not the filter: signal handlers
   are reset. An image without the handler dies with SIGSYS at its first
   path call (fails closed).
2. **`libsbx_child.so` and `sbx_attach_from_environment()`**: a small
   library whose constructor reads `SBX_BROKER` (the path of a Unix socket
   the host's broker listens on, in a directory only the host's UID can
   enter) and `SBX_TOKEN` (a random token for this launch), connects, and
   calls `sbx_lockdown` with the flags in `SBX_FLAGS` before `main` of the
   image. The broker accepts a connection only from the host's own UID
   (`SO_PEERCRED`) with the token. Put on `LD_PRELOAD`, it re-installs the
   handler in every dynamically linked image the tree starts, including
   after `exec`, with no change to the program. An image that drops
   `LD_PRELOAD` (or is static) fails closed as above. Many processes share
   one broker, each with its own connection and own pid in `SCM_CREDENTIALS`;
   the broker serves them from a small pool of threads (default 4), with a
   lock per directory for mutations and the copy-up lock above.
3. **`SBX_LOCK_UNIX`**: `socket(AF_UNIX, SOCK_STREAM or SOCK_DGRAM)`,
   `bind` and `connect` to a **path or abstract name** trap to the broker as
   `SBX_BIND`/`SBX_CONNECT` (already defined for sockets, with the Unix
   address as the body). The broker checks the socket path against the
   rules (a path must be writable to bind and readable to connect) or the
   abstract name against `sbx_policy_add_unix_name(policy, name, mode)`, and
   does the call on the process's own socket, which travels to it as a
   descriptor, as the inet calls already do. `socketpair` stays as it is. This
   is what lets wineserver's socket, the X server, PulseAudio and the host's
   renderer sockets exist.

**`SBX_LOCK_UNIX`, built (2026-10-23).** As planned, with these choices
made in the code. Only stream and seqpacket Unix sockets are made (a
datagram socket can `sendto` any path without a `connect`, so it stays
`SBX_LOCK_LOG_SOCKET`'s alone). The broker reaches a path through the
checked parent's descriptor (`/proc/self/fd/<parent>/<name>`), so a folder
swapped after the check is not followed and `sun_path`'s 108 bytes do not
limit the real path. A relative path is the process's current
directory's, which travels as a descriptor. The peer sees the broker's
credentials (`SO_PEERCRED`), the same UID. With `SBX_LOCK_INET` as well,
inet `bind` and `connect` also trap (the filter cannot read the family) and
go the brokered network's way under `sbx_policy_set_net`'s grants; `listen`
and `accept` stay the process's own. Not with `SBX_LOCK_NET_BROKERED`.

`SBX_LOCK_PATHOPS` (section 1) is the fourth. A process started with all
four is "a program tree": it can run its own helpers and talk to the
sockets the host named, and nothing else.

Signal handlers: Wine builds that use Syscall User Dispatch for Windows
programs that call the kernel directly install their own `SIGSYS` handler,
which the filter refuses (a new `SIGSYS` handler gets `EPERM`). The library
keeps the handler and records the program's `rt_sigaction(SIGSYS)` request
(answered success), calling it for any `SIGSYS` that is not a seccomp trap
(`si_code` `SYS_USER_DISPATCH`). Needed for an x86_64 Wine on an x86_64
device (the BlueStacks rig) only; whether it arises on arm64 (Box64 and
FEXCore emulate the guest's system calls in user space) is checked first.

#### What goes through the broker (Wine)

Through the broker, one round trip each: `openat`, `newfstatat`/`fstatat`,
`faccessat`, `readlink`, `mkdirat`, `unlinkat`, `renameat2`, `statfs`,
`chdir`, `getcwd`, `fchmodat`, `utimensat` with a path, and, with
`SBX_LOCK_PATHOPS`, `linkat`, `symlinkat`, `truncate`; with `SBX_LOCK_UNIX`,
`socket`, `bind`, `connect` on Unix sockets; `getdents64` only on the
merged directories above. `statx` and `openat2` keep answering `ENOSYS`
(libc falls back; the failed call costs a filter return, no round trip).

Untouched: everything on a descriptor (`read`, `write`, `pread`, `mmap`,
`ioctl`, `fcntl` and `flock`, `fstat`, `ftruncate`, `futimens`, `sendmsg`,
`recvmsg`, `poll`), the clock and futex calls, `clone` without namespace
flags, and `execve` (checked by nothing but the inherited filter). So a game
that opens its assets once and reads them pays at open only.

Still refused, with the effects to expect: `inotify` marks (directory change
notification in Wine; games that rely on it, rare, see "Hard links, symlinks,
truncate"), `ptrace`, `process_vm_*`, raw and netlink sockets.

Wine's `libredirect-bionic-wx.so` (droidtop SPEC 5b: every guest process
preloads it) redirects paths such as `/usr` and `/tmp` into the guest root
in user space, before the system call. The broker sees the redirected,
real path. The redirect is a convenience of the runtime, not a wall; the
broker is the wall, and its rules are written against real paths.

GPU: Vortek and VirGL render in the host process behind a Unix socket the
rules grant, so the Wine process needs no GPU node. A Wrapper (Turnip,
Qualcomm) driver runs in the Wine process and opens `/dev/kgsl-3d0` (or
the platform's node), which is an `own_opens` entry opened by the
constructor before the filter, as Enginehost does; the driver `.so` files
are granted read-only (they are loaded from paths in the host's private
files). The Android isolated UID is not used for Wine, since Wine needs
the GPU (see "A UID of its own"); the broker and filter are its whole
wall.

#### Performance

Nothing has been measured; these are the expectations to confirm, and the
budget that decides whether the design stands.

- A trapped call is a signal, two `sendmsg`/`recvmsg` pairs through a
  socketpair made for the call, a path resolution, and (for an open) a
  descriptor over `SCM_RIGHTS`. With the dentry cache a repeat lookup does
  no file-system work. The first-launch cost is dominated by Wine loading
  DLLs and walking its prefix: thousands of opens and stats once.
- **Budget**: cold start of a game's first Wine process at most 10 percent
  slower than unconfined; frame time unchanged (frames do not open files);
  a game that opens or stats per frame is measured separately and gets a
  `sbx_local_add` for the hot immutable files if needed.
- To measure (in `tests/`, `bench_layers.c`, run on the rig and the
  emulator by `sbx_test`): per-call latency of `open` and `stat` brokered
  against plain, on a layered and an unlayered tree, 1 and 8 threads; a
  prefix walk of 20 000 files; copy-up of 1 KB, 1 MB and 64 MB files;
  merged listing of a 3 000-entry directory, first and repeated.
- The handler-side shortcut that the passthrough mode has (making the call
  itself, with the kernel deciding) is **not** used here: that mode is safe
  only where another wall (an isolated UID) already holds, and the code
  could use the same escape value itself.

#### proot

proot is the other half of droidtop's runtime (no-root Linux containers,
`ProotRuntime`). It is a ptrace tracer that rewrites the paths of the
processes it traces, so the filter cannot go on proot itself (it would lose
`ptrace`). The design puts the wall on the traced processes, which are the
guest's, and leaves proot, which droidtop starts, unconfined:

1. droidtop's proot build already carries patches
   (`build-scripts/proot-patches/`, droidtop SPEC 3 "The no-root backend").
   One more: in the child proot forks for a traced program, after
   `PTRACE_TRACEME` and before `execve`, call `sbx_attach_from_environment()`
   with `SBX_LOCK_EXEC | SBX_LOCK_PATHOPS | SBX_LOCK_UNIX`. The filter is then
   on every guest process and, by inheritance, on all they start.
2. Ordering. On the kernels this must be checked on (Android's 4.19 and
   later; arm64 and x86_64), a ptrace syscall-enter stop is reported
   before seccomp runs. proot rewrites the guest's path to the host path
   at that stop, then the filter traps, and the handler sends the
   **already translated** path to the broker, which is what its rules
   are written against. This is the first thing to prove (a spike, below).
3. Results that proot translates back at the syscall-exit stop
   (`readlink`, `getcwd`, `/proc/self/exe`) will not be translated for a
   call the handler answered. The broker therefore translates them: the
   container's binds are given to the policy as aliases (`sbx_policy_alias`
   already maps a virtual folder to a real one and answers `getcwd` with the
   virtual name) and the broker applies the reverse mapping to a link target
   it returns.
4. Static guest binaries (Go programs, some musl tools) have no preload
   and would die at the first path call. proot already rewrites every
   `execve` it sees; the patch in item 1 also makes proot's own loader
   (which maps the program in the child) install the handler before the
   program's entry. To be confirmed that the loader is used for every
   `execve` in droidtop's build; if not, static binaries are the known gap.
5. The fake root (`--root-id`), `--link2symlink` and `--sysvipc` are
   proot's and unchanged. `link` of a guest hard link arrives as a
   symlink creation by proot's own rewrite and is brokered like any other.

The proot guest's granted set is: the container's rootfs (read-write; this
is its own storage), the binds `EnvironmentMounts.binds` lists (home,
shared storage, extra folders, with the modes the person set), the
sockets droidtop binds (`ContainerLayout.SOCKET_DIR`), and the device
nodes it opens. Layers for the rootfs (one base per image, a thin upper per
container, the OCI layers as lowers) fit the same model and are the way to
dedupe containers later; they are not part of this design.

**Fallback if the spike fails.** If the ordering in item 2 does not hold on
a target kernel, the same policy is evaluated in proot itself after it
translates a path (the library's policy engine linked into the proot
patch, `sbx_policy_check(path, need)`). That keeps one policy and one
audit, but it is only as strong as proot's own call coverage and it can be
raced by a multi-threaded guest changing the path between the check and the
call. Containment against accident and against ordinary software, not
against code that races. Owner, 2026-10-22: "Yes, but we need a better
solution": the spike goes ahead, this check is a **stopgap** for a failed
spike and not the answer, and **a stronger mechanism for proot is an open
item** (Droidtop/tracker#584). Nothing here may be described as equal to
the filter.

#### What the host changes (droidtop)

The library does not know droidtop. For orientation, the host side of this
design is in droidtop's SPEC 5a and 5b: the launcher passes the broker's
socket and token through the guest's environment (the launcher component
already takes an environment map, `WineXSession.kt:240-244`), a shared
binding of the library replaces the plugin host's private one, and the
prefix is created as a layer.

### 4. Library API summary (additions)

Broker side:

    sbx_policy_add_layer(policy, virtual_root, lowers, n, upper, flags)
    sbx_policy_add_tagged(policy, path, mode, tag)        /* revocable; decider sees it */
    sbx_policy_add_unix_name(policy, name, mode)          /* abstract Unix sockets */
    sbx_broker_listen(policy, socket_path, token)         /* many connections, one policy, a thread pool */
    sbx_layer_changed(policy, virtual_root)               /* host edited the upper; drop caches */

Host-side layer operations, the same code the broker uses, callable by the
host with no confined process (the host needs them to prepare and to
manage a layer without a second implementation): `sbx_layer_open(mount, path,
flags, mode)` (merged view, copy-up), `sbx_layer_copy_up(mount, path)`,
`sbx_layer_unlink(mount, path)` (writes a whiteout), `sbx_layer_list(mount,
path)`, `sbx_layer_check(upper)` (record and stale temporaries),
`sbx_layer_forget(upper)` (see below).

Confined side: flags `SBX_LOCK_EXEC`, `SBX_LOCK_PATHOPS`, `SBX_LOCK_UNIX`;
`sbx_attach_from_environment()` and `libsbx_child.so`.

`sbx_layer_forget` removes a layer: it unlinks the upper's entries one by
one with `unlinkat` (never `rmdir` of a non-empty tree, never following a
link, never leaving the upper's directory, and refusing a directory that
is a mount point or has a different device from the upper's root) and
reports the first failure. The same hazard class as the 2026-09-02 incident
is what this function exists to prevent.

### 5. Real copy-on-write where it exists, and optional kernel help

The layers are for devices without kernel copy-on-write. Where a base and a
new prefix sit on a file system with reflinks (`FICLONE`), the host makes
the new prefix as a whole copy-on-write copy of the base and mounts no layer
(owner, 2026-10-22: "If we have CoW, it's a whole new prefix. If we don't,
we want a layer system"); the library supplies the probe,
`sbx_fs_can_reflink(dir)` (clone a small file inside `dir`, report, remove
it), so hosts do not each write one. Containment (section 2) is the same
either way; only the dedup mechanism differs.

On a device where the host already has root (Shizuku or Sui, never `su`;
droidtop SPEC 5b), an overlayfs mount of the same base and upper is a faster
path to the same view, because the kernel then serves the merge. It would
mean a Wine process outside the broker's view of the prefix, so the
broker's own checks (the granted set) still apply and the layer format on
disk is the broker's: overlayfs needs `trusted.overlay.*` attributes that
the broker's whiteout symlinks are not, so the two are not interchangeable
by pointing one at the other's directory. Not built, not required, and
nothing in section 1 or 3 waits on it.

### 6. Tests

`tests/sbx_test.c` already runs each escape twice (unconfined, then
confined). The same pattern covers: whiteout and re-create across a crash
(a process killed between each step of copy-up and unlink, by hooks in the
broker under a test flag, then the merged view checked); opaque
directories; rename of a file, a directory and over a whiteout; hard link
from a lower; mmap of a lower's file executable and private-writable;
`ENOENT` for a whiteout and `EINVAL` for creating one; a listing of
3 000 names before and after a mutation; two processes copying up the same
file; a symlink in a lower that points outside (refused); a wide grant with
a deny underneath; a tagged grant revoked mid-run; `exec` of a program
without the handler (dies, nothing leaked); proot ordering spike on the
emulator at API 28 and 34.

### 7. Order of work

1. Layers and the new broker operations, tested on Linux CI.
2. The proot ordering spike on the emulator and the rig (item 2 above
   decides proot's design).
3. `SBX_LOCK_EXEC`, `SBX_LOCK_UNIX`, `libsbx_child.so` with a plain Wine on
   the emulator, audit-only, to learn the granted set.
4. Enforce; benchmark against the budget.

### Decided and open (Droidtop/tracker#584)

Decided by droidtop's owner on 2026-10-22: Wine has no prompt and no "run
anyway"; running unprotected is only a gated, never-recommended toggle in
the host, so the library needs nothing for it beyond a host choosing not
to lock a process down. The proot ordering spike goes ahead. A wide
storage grant leaves out the host's private folders and other prefixes. The
platform read-only list is the library's and shared with Enginehost.

Open: a stronger mechanism for proot than the spike's outcomes (section 3).


## Learning mode (built 2026-10-22, Droidtop/tracker#550)

The owner, 2026-10-22: "we need something like a permissive mode to train
the sandbox". Like SELinux permissive or AppArmor complain mode: a process
runs with nothing refused, and everything that would have been refused is
recorded, so a host can build and review a policy for code it did not write
before it confines that code for real. It is a debugging and training mode.
It is never a default, and a host must say plainly, every time, that a
learning run has no protection.

**What stays the same.** The filter, the handler and the broker run as in a
real lockdown. Paths still go through the broker, so every path the code
names is seen with its operation, flags and resolved form. The calls that
fall back with `ENOSYS` (statx, openat2, clone3, fchmodat2) still do: they
exist to steer path calls through the broker, and allowing them would hide
the paths a profile is for. SIGSYS stays open ("SIGSYS stays open", above),
which learning needs as much as a real run: a thread with SIGSYS blocked
would otherwise die on its first recorded call.

**Paths: the decider.** The broker already asks the host's decider about
every request the rules refuse (`rule_verdict` < 0). A learning host gives
a decider that records the access and returns 0. No library change is
needed for files, folders, listing or the brokered network. The record
carries `op`, `asked`, `resolved`, `need`, `flags` and `rule_verdict`, which
is everything a rule needs.

**Calls the filter refuses: `SBX_LOCK_LEARN`.** A lockdown flag. With it,
every action that would refuse a call outright (`EACCES` or `EPERM`: exec,
sockets beyond the flags given, ptrace, namespaces, mount, the keyring,
signals to other processes, a new SIGSYS handler, sealed-descriptor calls,
another architecture's entry) traps instead, with its own trap data
(`SBX_TRAP_LEARN`). The handler then:

1. sends the broker a record: the call's number, its six arguments and the
   errno the real filter would have answered (`SBX_LEARN`, one message, no
   reply);
2. makes the call through the library's own syscall trampoline, which the
   learning filter lets through by instruction pointer;
3. returns the call's real result.

A learning filter lets the trampoline make any call. A real filter lets it
make `rt_sigaction` alone, after refusing a new SIGSYS handler ("SIGSYS stays
open"): code that jumps there can install a handler, which it could do
anyway, and nothing else. The broker passes each record to the host's
audit function as an access whose `op` is `"syscall"`, `asked` is the
call's name and first three arguments (`socket(0x2, 0x1, 0)`, or `syscall
<number>(...)` for one the library has no name for), and `rule_verdict` is
the errno it would have had. The record is answered before the call is
made, so records arrive in order.

Three refusals stay refusals, unrecorded, as in a real lockdown: a call
through another architecture's entry, a new SIGSYS handler (the library's
handler must stay in place, or nothing after it is recorded), and clone
with namespace flags (a clone made from inside the handler would run the
child on the handler's stack).
An exec is recorded and allowed, but the new program keeps the filter and
not the handler, so it dies by SIGSYS on its first trapped call: a learning
run shows that a core execs, not what the program it runs would need.

**What the library does not do.** It does not deduplicate, count, name
the game's folders, or write files. Those depend on what the host knows (its
game, save and cache folders, the core's build) and belong to the host: a
learning decider and audit function see every record in order, on the
broker's thread.

**A profile, then a policy.** A host turns its records into a reviewable
profile per core build. Paths are generalised to the host's folders (the
game folder, the save folder, the cache, the core's own files), calls are
named, and each entry carries a count. A tool proposes a policy diff from
the profiles for a person to review. Nothing a learning run records is ever
applied by itself.

**Tests.** `sbx_test.c` runs a learning lockdown and checks, for exec,
socket, ptrace, unshare and a path the rules refuse: the call succeeds as it
would unconfined, exactly one record arrives with the call and the errno a
real lockdown answers, and a new SIGSYS handler is still refused. A real
lockdown in the same run still refuses all of them, and the trampoline is
not let through by its filter.

## Windows (design, 2026-10-23, Droidtop/tracker#606)

Computer-side plugins (droidtop's Python plugins reused in droidtop-agent
and Pythia) run on Windows too, and the owner's rule is that a call that is
not allowed cannot run. Python is not trusted: `ctypes`, raw sockets and
`subprocess` must all end at a refusal from the kernel. Windows comes first
("Windows, for now", owner, 2026-10-23). **macOS is later**, not built and
not designed beyond this line: a deny-by-default Seatbelt profile under the
same broker and the same client call, when the owner asks for it.

### What Windows offers, and why this shape

Windows has no seccomp and no way to trap a system call in user space, and
a running process cannot be moved into an AppContainer. So confinement is
decided **at spawn**, by the trusted parent, and the confined process asks
the broker **explicitly** for what it needs: an open by path that the
AppContainer's token does not allow is simply refused by the kernel, never
forwarded. The reference is Chromium's Windows sandbox (a restricted token
or AppContainer, a job object, a broker that opens and duplicates handles),
without its interception layer: Chromium patches `NtCreateFile` and friends
to forward calls, and we do not, because the plugin API already asks for
files explicitly (`droidtop.host.open`) and an interception layer is a
second path mechanism to keep correct.

| Wall | Mechanism | What it stops |
| --- | --- | --- |
| Identity | an **AppContainer** with **no capabilities**; a **less-privileged AppContainer** (LPAC, `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY`, Windows 10 1703+) where available | every file, registry key, named object and device whose ACL does not name the container's SID (LPAC: not even the `ALL APPLICATION PACKAGES` grants most of the system carries); every network connection, loopback included (no `internetClient`, `privateNetworkClientServer`) |
| Process tree | `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` = restricted, and a **job object**: one active process, no breakaway, kill on close, die on unhandled exception | new processes (both walls refuse them), outliving the host |
| UI | the job's UI limits: desktop, display settings, exit Windows, global atoms, user handles, clipboard read and write, system parameters | reaching other windows and the clipboard |
| Memory | the job's per-process memory limit (`sbx_spawn_spec.memory_limit`) | exhausting the computer's memory |
| Handles | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: the child inherits exactly the handles in the spec (standard handles and the broker channel) | inheriting the parent's other handles |

### The broker on Windows

The broker runs on a thread of the trusted parent. Its channel is a
**message-mode named pipe** the parent creates under a random name, with
one instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`),
and connects to itself at once; the child inherits the client end. No one
can connect to it by name afterwards, and the container could not open it
by name anyway. The child finds its end through the environment variable
`SBX_BROKER` (the handle's value).

A request is `{version, op, flags, path}` (UTF-8, at most `SBX_PATH_MAX`
bytes); the reply is `{result, handle}`. For an allowed open the broker:

1. converts the path to an absolute one (`GetFullPathNameW`) and refuses a
   device or `\\?\` form, then matches it against the rules,
   **case-insensitively** (Windows rules are case-insensitive by default);
2. opens the parent folder under **its own identity**, and checks the
   folder's final path (`GetFinalPathNameByHandleW`) still lies under the
   rule: a junction or symlink anywhere above the leaf that leads out is
   refused;
3. opens the leaf **relative to that folder handle** (`NtCreateFile` with a
   root directory) without following a reparse point; a leaf that is a
   reparse point is refused when writing, and when reading is followed only
   if its final path lies under the same rule;
4. asks the decider, as on Linux, and reports to the audit;
5. duplicates the handle into the child (`DuplicateHandle` with exactly the
   access asked for: read, write, or a folder's list access; never
   `DELETE`, `WRITE_DAC` or `WRITE_OWNER`), closing its own copy.

A handle carries only its own access. A folder handle does not open what is
under it: an open relative to it is still checked against the container's
token, and refused. So every file is a request, and the broker's checks are
the only way in.

Only open is brokered at first, which is what the plugin API needs
(`droidtop.host.open`, reading and writing within a granted folder, and a
folder's listing through a folder handle). mkdir, unlink and rename are
added the same way when a host needs them; they cannot be done through a
handle the broker gave, because the container lacks access to the folder.

### Static read-only grants

The confined program must load its own code (the bundled Python runtime
and its standard library) through the loader, which opens by path and
cannot ask the broker. Such a folder is marked
`sbx_policy_add(policy, path, SBX_READ | SBX_STATIC)`: at spawn, the folder
gets an access-control entry for the container's SID granting read and
execute, inherited by everything under it. On Linux and Android
`SBX_STATIC` is ignored and the rule is an ordinary brokered read rule.

The entry stays on the folder after the process ends, keyed to the
container's SID (Windows applications and Chromium do the same); it grants
nothing to any other container or user. A static grant can only be
`SBX_READ`: `sbx_spawn` refuses a static rule that also allows writing.

### API

The cross-platform shape: confinement at spawn, a client call for files,
and a portable handle type. Linux and Android keep `sbx_lockdown`, the trap
and `SCM_RIGHTS` exactly as they are.

```c
typedef int sbx_handle;        /* POSIX: a descriptor */
typedef void *sbx_handle;      /* Windows: a HANDLE */

/* Client (the confined process). Linux and Android: open(), which the
   lockdown traps and the broker answers. Windows: a request on the
   inherited channel. Returns 0 and *out, or a negative errno. */
int sbx_open(const char *path, unsigned flags, sbx_handle *out);
/* flags: SBX_OPEN_READ, _WRITE, _CREATE, _TRUNCATE, _EXCLUSIVE, _APPEND, _DIRECTORY */

/* Windows: confinement at spawn. */
struct sbx_spawn_spec {
    const char *path;                 /* UTF-8 */
    char *const *argv, *const *envp;  /* envp NULL: only SBX_BROKER */
    const sbx_handle *handles; unsigned handle_count;  /* inherited as they are */
    sbx_handle std_in, std_out, std_err;               /* NULL: none */
    const char *container;            /* the AppContainer profile's name, created when missing */
    int less_privileged;              /* LPAC where the system has it */
    unsigned long long memory_limit;  /* bytes; 0: no limit */
    struct sbx_policy *policy;        /* the broker's rules; NULL: no broker */
};
struct sbx_process { sbx_handle process, job; unsigned long pid; int less_privileged; };
int sbx_spawn(const struct sbx_spawn_spec *spec, struct sbx_process *out);
int sbx_process_wait(struct sbx_process *process, int *exit_code); /* then closes the job: the tree dies */
```

`sbx_spawn` keeps its Linux form (`pid_t *`, descriptors 3 and up,
`RLIMIT_*`); the spec is per system, as each system's limits and handles
are. On Windows the broker is started by `sbx_spawn` itself when the spec
has a policy, since it needs the child's process handle to duplicate into;
it serves until the child closes its end, then frees the policy. Rule paths
on Windows are absolute drive or UNC paths. `sbx_policy_alias`,
`sbx_policy_set_net` and system sockets are Linux and Android only.

**Fail closed.** `sbx_spawn` returns an error, and starts nothing, when any
wall cannot be put up: no AppContainer support, a profile or static grant
that cannot be made, a job that cannot be assigned. There is no unconfined
mode. A host runs no computer-side plugins on a system whose backend is not
built or whose escape tests do not pass.

**Not decided here**: what the broker allows. The permission checks and the
bundled Python belong to the droidtop-agent / Pythia lane (its broker in
Rust calls this library's spawn and serves or wraps its decider). The
client call's shape above is proposed to that lane on Droidtop/tracker#606.

### Tests

`tests/sbx_test_win.c` runs on GitHub's Windows runners in CI. It starts
itself as a child twice with the same attempts: unconfined, as a control in
which each attempt must succeed (or the host refused it on its own, and the
attempt proves nothing), then confined, where each must fail. The attempts:

- read a file outside the rules by path, and write one in a folder the
  broker allows (the token refuses both);
- list the user's profile folder; write in the static read-only grant;
- create a process, and create one with `CREATE_BREAKAWAY_FROM_JOB`;
- connect to a TCP port the parent listens on at 127.0.0.1;
- create a key under `HKEY_CURRENT_USER\Software`;
- open the parent process for reading its memory;
- open a named event the parent created in its session's namespace;
- read the clipboard;
- commit more memory than the job allows.

Then, confined only, what must work and what the broker must refuse:
`sbx_open` of an allowed file reads it; creating and writing in a writable
rule; refused outside the rules, through `..`, writing in a read-only rule,
and through a junction planted in a writable folder that leads out; and an
open relative to a folder handle the broker gave is refused by the token.

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
- **macOS**: a deny-by-default Seatbelt profile under the same broker and
  `sbx_open`, after Windows and only when the owner asks (Droidtop/tracker#606).
- **Layers, path containment and a tree of confined programs** (Wine and
  proot under the broker), designed in "Layers, containment, and Wine and
  proot under the broker"; nothing of it is built.
