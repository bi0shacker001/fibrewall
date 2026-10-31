# Fibrewall Phase 0 — Deliverable A: verified findings register

Reviewed `bi0shacker001/fibrewall` at `2dfda43` (v0.1.7), read-only. Line numbers are that revision. Every A-NN below is Confirmed unless its line says otherwise; the verdict and nuance are per finding.

## A-01 .. A-14

### A-01: Same-UID Android workloads keep ambient host authority
- **Priority:** P0 for strict-isolation consumers · **Verdict:** Confirmed
- **Evidence:**
  - `docs/design.md:38-42` ("not confined from the host… binder cannot be filtered by seccomp"), `:83-90` (Enginehost cores and windowcast keep the app UID for the GPU) and `:1617-1619` ("can still ask system services for things as its app").
  - Enginehost `docs/engine-sandbox.md:71-74` lists DownloadManager, Intents and exported services as reachable.
  - `sbx_lockdown` (`src/lockdown.c:2121-2306`) neither records nor checks the uid or SELinux domain.
  - Missed by the review: `SBX_LOCK_SOCKETS`, which is in `SBX_LOCK_CONTAIN`, reaches every Unix socket of the UID (`include/sbx.h:209-220`).
- **Consumers / platforms:** C-02 (Enginehost GPU cores: same UID, by design); C-01 for droidtop's `PluginOpenService` tier; C-07. Android, and desktop Linux (where nothing is ever UID-separated).
- **Impact:** a compromised same-UID worker keeps all the app's identity-based authority: Binder calls as the app, its exported components, and Unix sockets of the UID. File and syscall confinement don't change that.
- **Remediation:** report the identity class (`SBX_G_IDENTITY_SEPARATE` / `SBX_R_HOST_UID`). A strict consumer requires it, and lockdown fails when the uid isn't in the isolated range or the SELinux context isn't `isolated_app`. Long term: the Binder relay, and split-process rendering.
- **Regression test:** `tests/android/` (instrumented):
  - (a) same-UID, with the separate identity required: lockdown fails and nothing is installed;
  - (b) inside an `isolatedProcess`: lockdown succeeds;
  - control: without the requirement both succeed, and the report marks (a) `SBX_R_HOST_UID`.
- **Dependencies:** D (report); A-08; A-16; A-26.
- **Approval:** API; a design statement of the assurance class.

### A-02: Descriptors held before lockdown bypass later path decisions
- **Priority:** P1 · **Verdict:** Confirmed, and understated
- **Evidence:**
  - Calls on held descriptors are untouched by design (`include/sbx.h:11-13`, `docs/design.md:1614-1616`).
  - `sbx_local_add`/`_mode` answer each open with a `dup` of one descriptor, and there is no removal API (`include/sbx.h:332-344`, `:446-454`; `src/lockdown.c:348-370`).
  - `own_opens` devices, with 3 spares each, are kept `O_RDWR` for the process's life (`src/lockdown.c:2233-2249`).
  - A decider's refusal affects only future requests (`include/sbx.h:607-618`).
  - `sbx_spawn` closes everything except 0-2 and the handed descriptors (`src/spawn.c:109-112`). `sbx_lockdown` and the attach path take no inventory (`src/attach.c`, `src/child.c`), and the broker connection is deliberately inheritable.
  - Missed: `ioctl` is never filtered on held descriptors, so an inherited terminal on 0-2 keeps `TIOCSTI` input injection where the kernel still allows it. That is a classic sandbox escape; kernels from 6.2 can turn it off with `dev.tty.legacy_tiocsti=0`.
- **Consumers / platforms:** all. Most of all C-03 (a tree inherits the host's descriptors), C-05/C-06, and C-04 on desktop. Linux and Android; Windows uses an explicit handle list.
- **Impact:** any descriptor present at lockdown is a capability the policy can't see or withdraw. A revoked grant keeps working through descriptors already handed out.
- **Remediation:**
  - an inventory at lockdown and attach (`/proc/self/fd`), refusing undeclared descriptors in strict mode, or closing them;
  - refuse `ioctl` `TIOCSTI` and `TIOCLINUX` on every descriptor;
  - document revocation: future requests only; immediate revocation means ending the worker (F-05);
  - a removal API for local files.
- **Regression test:** open an outside-the-rules file before lockdown, then read it after. Today the read succeeds; under the strict inventory, the lockdown fails. `ioctl(0, TIOCSTI)` on a pty is refused. Controls: unconfined.
- **Dependencies:** A-24; D.
- **Approval:** behaviour (strict inventory), API.

### A-03: The containment preset is not a strict isolation preset
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:** `SBX_LOCK_CONTAIN` is `PATHOPS | INOTIFY | SOCKETS | SIGNALS | EXEC` (`include/sbx.h:253`):
  - `SOCKETS`: every Unix socket type, inet stream and datagram and route netlink; `bind` and `connect` unjudged; reaches every socket of the UID (`include/sbx.h:209-220`);
  - `SIGNALS`: signals any process of the UID (`include/sbx.h:222-228`).

  It was designed that way, under the owner's 2026-10-23 ruling that Wine's sandbox restricts only the file system view.
- **Consumers:** C-03 (its intended user). Any consumer that reads "contain" as isolation is wrong.
- **Impact:** network, peer-process signalling and IPC to the host's sockets stay open. That's correct for compatibility containment and wrong for anything strict.
- **Remediation:**
  - document its effective guarantees (file system mediated, exec confined) and residual authority (`SBX_R_UID_SOCKETS`, `SBX_R_UID_SIGNALS`, `SBX_R_NETWORK_ANY`);
  - have the report (D) list them, so the preset name can't be mapped to an assurance level;
  - no behaviour change.
- **Regression test:** T-14: a contract that requires `SBX_G_NET_NONE` with `SBX_LOCK_CONTAIN` fails to launch, and the report names `SBX_LOCK_SOCKETS` as blocking.
- **Dependencies:** D.
- **Approval:** documentation and API.

### A-04: Starting a program on Linux doesn't by itself mean early lockdown
- **Priority:** P0 for consumers relying on spawn or attach · **Verdict:** Confirmed for `sbx_spawn` and attach; false for images a confined process execs
- **Evidence:**
  - `sbx_spawn` (`src/spawn.c:95-125`) closes descriptors, sets `PDEATHSIG` and rlimits, then `execve`s. No lockdown is installed; the program must lock itself down later (`sbx_spawned_init`, `include/sbx.h:485`).
  - Attach: `libsbx_child.so` calls `sbx_attach_from_environment` in a default-priority constructor (`src/child.c:17`). Before it run:
    - the dynamic loader;
    - the executable's `DT_PREINIT_ARRAY`;
    - ifunc resolvers;
    - constructors of libraries initialised earlier, other preloads included.
  - Missed by the review: **a static executable ignores `LD_PRELOAD`.** Started by the attach route, it never attaches and runs fully unconfined. Nothing fails closed: the host's listener simply never sees a connection.
  - By contrast, an image that a confined process execs under `SBX_LOCK_EXEC` keeps the inherited filter from its first instruction. The loader runs under sbx-exec's minimal handler (`src/exec_helper.c`), and a static target keeps that handler (`docs/design.md:980-982`). That part of the review's concern does not apply.
- **Consumers / platforms:** C-03 (the first process of a Wine tree is attached), C-04 and C-07 using `sbx_spawn`. Linux and Android. Windows is suspended, assigned, then resumed, so it's fine.
- **Impact:** code in the first program's loader, preinit, ifuncs or other constructors runs unconfined. A static first program is never confined.
- **Remediation:** `sbx_spawn_confined` (D): fork, install the lockdown with `SBX_LOCK_EXEC` in the child, then exec through sbx-exec, so the program's first instruction is already confined and no constructor ordering is involved. Document attach as compatibility, where the host must also check the attach arrived (the listener sees the pid) before trusting it.
- **Regression test:**
  - a static binary started with `sbx_spawn_confined` can't read the secret; the control is the same binary through attach, which reads it today;
  - an executable with a `DT_PREINIT_ARRAY` entry that opens the secret: refused under `sbx_spawn_confined`.
- **Dependencies:** D; A-17.
- **Approval:** API.

### A-05: Learning mode removes significant enforcement
- **Priority:** P1 · **Verdict:** Confirmed, intentional
- **Evidence:**
  - `SBX_LOCK_LEARN` (`include/sbx.h:136-151`): every would-be refusal is recorded and then made, except a few (namespace `clone`, a new SIGSYS handler, foreign-architecture entry, exec).
  - It's a plain flag: nothing in the library separates a developer launch from a production one, and nothing marks a learning process persistently.
  - Enginehost turns it on by a debug system property per core (`runtime_sandbox.c:173`).
- **Consumers:** C-02 (in use), C-01 (droidtop pins a version without it).
- **Impact:** a learning run has no protection. A property left set, or a flag passed by mistake, ships an unprotected worker that looks "locked down".
- **Remediation:**
  - learning requires a separate call or an explicit developer token, never just a flag in production options;
  - the report never sets `SBX_G_NOT_LEARNING` while learning, so a strict consumer requires that bit and can't run learning by accident;
  - learning output never becomes policy (already true).
- **Regression test:** learning with `SBX_G_NOT_LEARNING` required fails to launch. Control: without the requirement it runs, and the report shows the bit missing.
- **Dependencies:** D.
- **Approval:** API.

### A-06: Brokered networking runs under the broker's authority
- **Priority:** P1 (P0 for consumers relying on per-destination control) · **Verdict:** Confirmed, and worse than stated
- **Evidence:**
  - Under `SBX_LOCK_NET_BROKERED` the broker creates, connects, binds, listens and accepts as itself (`include/sbx.h:118-133`).
  - Grants are per policy (`sbx_policy_set_net`), not per worker. The decider sees only the pid (A-22).
  - **`NET_MARK` bypass, missed by the review:** `connect` is allowed when the upper 32 bits of the address-length argument equal `0x5b3`, and `accept4` likewise in its flags (`src/lockdown.c:770-779`, filter `:1898-1908`). That marker is how the handler makes its own calls. Unlike the trampoline (checked by instruction pointer), nothing ties it to the handler: any code can pass it.
  - So a worker holding a socket the broker made can connect it to any address, skipping the grants and the decider (verified in code). On Android 11+ an isolated process may connect a socket it was given.
  - droidtop uses `SBX_LOCK_NET_BROKERED` for isolated plugins with network access, but grants every destination (connect, listen and resolve, with no per-call decider), so the bypass gives them nothing more today.
- **Consumers / platforms:** C-01 (in use, unaffected today), and anything planning per-destination network control: C-05, #651's zones, C-07. Linux and Android.
- **Impact:** the per-destination network control the broker exists to provide can be skipped by any code in the worker. Separately, the broker acting as itself is a confused-deputy risk in shared brokers.
- **Remediation:**
  - tie `NET_MARK` (and `LIST_MARK`, `PASS_DIRFD`) to the trampoline's instruction pointer, as is already done for `rt_sigaction`, `execveat` and learning;
  - per-worker grants (D: `sbx_broker_listen_each`);
  - a per-request identity in `struct sbx_access` (A-22).
- **Regression test:** `NET_BROKERED` with a decider that refuses a test port. A raw `connect` with the marker on a broker-made socket is refused after the fix (succeeds today). Control: a plain `connect` is refused by the decider.
- **Dependencies:** A-22; D.
- **Approval:** a filter change.

### A-07: Network policy is incomplete at the protocol level
- **Priority:** P1 · **Verdict:** Design gap
- **Evidence:**
  - `SBX_NET_CONNECT`, `_LISTEN`, `_RESOLVE` and `_DECIDE` are all the network grants there are (`include/sbx.h:632-635`).
  - TCP and UDP, IPv4 and IPv6, loopback and remote are told apart only by a host decider reading the words it is given.
  - `sendto` on an unconnected datagram socket is not decided (`include/sbx.h:629-630`).
  - `SBX_LOCK_INET` is any endpoint, loopback included.
  - Inherited sockets are untouched (A-02).
- **Consumers:** C-01, C-05, C-06, C-07, #651's `net.local` and `net.internet`.
- **Impact:** a consumer can't say "outbound TCP to these hosts only" in the library's terms. Where it relies on a decider, datagram `sendto` slips past it.
- **Remediation:** structured network grants (direction, protocol, family, an address class or prefix, ports, loopback) checked in the broker; trap `sendto` and `sendmsg` that carry a destination under `NET_BROKERED`; report the actual breadth (`SBX_R_NETWORK_ANY`) where endpoint rules can't be enforced.
- **Regression test:** a grant for TCP to 127.0.0.1:port only: a UDP `sendto` elsewhere is refused, another port is refused, IPv6 is refused. Control: the granted endpoint works.
- **Dependencies:** A-06; F-01.
- **Approval:** API.

### A-08: IPC is a major potential bypass class
- **Priority:** P0 for strict-isolation claims · **Verdict:** Confirmed, and understated
- **Evidence:**
  - Unfiltered in every mode (`build_filter`, `src/lockdown.c:1776-2070`): `socketpair`, `pipe`, `memfd_create`, `eventfd`, `sendmsg`/`recvmsg` (so `SCM_RIGHTS`), SysV `shm*`/`msg*`/`sem*`, and POSIX `mq_*`. The design says as much (`docs/design.md:288`, `:863`).
  - The sealing bypass (A-24) and the `NET_MARK` bypass (A-06), both missed by the review.
  - `NET_BROKERED` allows `socket(AF_UNIX)`, and a Unix connect to anything but a host-named system socket goes to the kernel unjudged (`src/lockdown.c:818-834`; `include/sbx.h:128-129`). On desktop that means the session D-Bus, X11/Wayland and the host's abstract sockets.
  - `LOG_SOCKET`: any datagram Unix socket of the UID.
  - `UNIX`: datagram `sendto` with a name is not trapped.
  - `SOCKETS`, and so `CONTAIN`: every socket of the UID.
  - `TIOCSTI` on an inherited terminal (A-02).
  - Windows: the handle list is exact (`src/windows.c:893-908`). Named pipes, ALPC/COM/RPC and window messages are limited only by the AppContainer token, UIPI and job UI limits; there is no separate desktop. Two instances under one container name share its named-object namespace (A-12, A-27).
  - Android: SysV is off in Android kernels and the app seccomp policy, so it is a desktop exposure.
- **Consumers / platforms:** all.
- **Impact:**
  - desktop Linux: a same-UID worker reaching the session D-Bus can ask `systemd --user` to start a transient unit, which is unconfined code execution;
  - Android: sealing can be undone (A-24);
  - everywhere: shared memory is a channel no policy sees.
- **Remediation:**
  - IPC as an explicit capability class (F-01), with strict flags refusing SysV and `mq_*`, refusing `socketpair` or `SCM_RIGHTS` transfer, and refusing `TIOCSTI`/`TIOCLINUX`;
  - `NET_BROKERED` routes every Unix connect through `unix_one`;
  - trap `sendto` and `sendmsg` with a name;
  - the A-06 fix;
  - Windows: per-instance containers, LPAC required, an alternate desktop, and a documented residual list of endpoints reachable through `ALL APPLICATION PACKAGES`.
- **Regression tests:**
  - the sealing re-import test (A-24);
  - the marker forgery test (A-06);
  - a SysV segment from the parent can't be attached in strict mode;
  - `TIOCSTI` refused;
  - under `NET_BROKERED`, a Unix connect to a parent-bound path outside the rules gets `EACCES`;
  - Windows: a named pipe across two instances sharing one container name.
- **Dependencies:** A-01; A-06; A-16; A-24; A-27; F-01; D.
- **Approval:** filter semantics and new flags.

### A-09: Broker input parsing and identity need dedicated fuzzing
- **Priority:** P1 · **Verdict:** Confirmed: there is no fuzzing anywhere
- **Evidence:**
  - The parsers are bounded (`serve_loop`, `src/broker.c:1825-1870`): truncated or credential-less messages are dropped; at most 3 descriptors are kept; exact length checks in every sub-parser (`:1748-1817`); unknown ops get `-ENOSYS`; a single protocol version, with no negotiation.
  - The listener token compare is constant-time (`:1911-1916`).
  - **Identity is a pid, not a pidfd.** `/proc/<pid>` access (`:446-497`) isn't qualified by start time, so a pid reused between send and decision is served as the original.
  - **The client chooses the reply socket**, and `reply()` sends blocking (`:807-830`). Passing the broker's own end can fill its queue, so that serve thread deadlocks, and in listener mode that stalls the whole tree.
  - `SBX_OPEN` and `SBX_EXEC` open with the client's flags, so a FIFO blocks the broker thread. `SBX_TRUNCATE` already forces `O_NONBLOCK` (`:1064`).
  - A dropped request gets no reply, so the client hangs (self-DoS only).
  - Under `SOCKETS`/`CONTAIN`, workers can pass each other their broker descriptors, which is cross-policy confusion, untested.
  - Windows (`src/windows.c:577-609`): fixed buffer, oversize drained, all lengths checked.
- **Consumers:** all.
- **Impact:** memory-safety bugs look unlikely, but nothing proves it. The realistic impacts are a broker-thread deadlock, pid-reuse confusion, and cross-policy use of a passed descriptor.
- **Remediation:**
  - a libFuzzer harness on `serve_one`, and on a refactored Windows `parse_request`, in CI under ASan;
  - reply with `MSG_DONTWAIT`, and accept only a fresh socketpair end as the answer socket;
  - `SO_PEERPIDFD`/`SCM_PIDFD` (6.5+), or pid plus start time;
  - `O_NONBLOCK` and a non-regular-file check on broker opens;
  - `dirfd_sent` must be 0 or 1;
  - answer `-EINVAL` instead of dropping;
  - version negotiation.
- **Regression tests:**
  - answer socket = the broker end, 20 times: the broker keeps serving;
  - length extremes get `-EINVAL` under ASan;
  - a FIFO open doesn't stall a second request;
  - a 9000-byte message gets `-EINVAL`;
  - new `tests/fuzz_broker.c` and a CI job.
- **Dependencies:** A-19; A-21; A-22; A-27.
- **Approval:** protocol changes, CI.

### A-10: Path resolution remains a high-value escape surface
- **Priority:** P1 · **Verdict:** Partially confirmed; one concrete Windows gap
- **Linux defences, strong:**
  - lexical normalisation, aliases and `/proc/self` rewriting;
  - per-component `readlink` resolution (40 hops);
  - the operation runs through a verified `O_PATH` parent with `O_NOFOLLOW` on the leaf;
  - `confirm_opened` re-decides the opened descriptor (`src/broker.c:564-855`);
  - tested: `..`, symlinks, `/proc` forms, dirfd, the symlink-swap race, case folding (`tests/sbx_test.c:296-308`, `:537-567`, `:443-447`).
- **Windows gap, missed by the review:** `answer_open` picks the rule lexically and bounds the open to that rule's folder (`src/windows.c:536-552`). `open_contained` then checks only that the result lies inside the bound (`:501`), never that the rule for the final path allows the access.
  - Example: write access to `C:\data` with a read-only or deny rule on `C:\data\private`. Asking for `C:\data\PRIVAT~1\f` (an 8.3 name), or going through a junction or hard link inside `C:\data`, gets a write handle in the protected folder.
  - Linux's `confirm_opened` catches the equivalent.
- **Also:**
  - a write or overwrite disposition on a leaf reparse point runs before the reparse check (`:480` vs `:486`);
  - Linux case-insensitive filesystems (vfat, Android shared storage, ext4 casefold) can bypass a deny sub-rule that differs only in case or Unicode form.
- **Untested:** pre-existing hard links, bind mounts, ancestor renames, Unicode, short names, UNC, file symlinks and mount points, and nested deny rules on both platforms.
- **Consumers / platforms:** C-04 (Windows agents with granted folders), C-03, C-01 and C-02 on shared storage. Windows mainly.
- **Impact:** a protected sub-folder inside a writable grant can be written. That isn't an escape from all grants, but it defeats stated sub-rules.
- **Remediation:**
  - Windows: after opening, take the final path, map it back to drive form, and re-run `rule_for` with the same need, refusing on mismatch;
  - refuse a reparse-point leaf before any create or overwrite;
  - Linux: detect case-insensitive filesystems and fold case, or document that deny sub-rules aren't supported there.
- **Regression tests:**
  - Windows: a write rule on `save` with a deny rule on `save\private`. `sbx_open("save\\PRIVAT~1\\k")` gets `-EACCES` (skip if 8.3 names are off). The same through a junction. A truncate on a file-symlink leaf is refused, with both unchanged.
  - Linux: a casefold or vfat mount, where available.
- **Dependencies:** A-11; A-23.
- **Approval:** a `windows.c` behaviour change.

### A-11: Filesystem grants need more granular operation rights
- **Priority:** P1 · **Verdict:** Confirmed, with implementation gaps the review doesn't name
- **Evidence:**
  - The rights are `SBX_DENY`, `SBX_READ` (open-read, stat, access, readlink, chdir, list) and `SBX_WRITE` (adds write, create, mkdir, unlink, rename) (`include/sbx.h:548-561`).
  - Open flags map to write if the access mode isn't read-only, or `O_CREAT`/`O_TRUNC`/`O_APPEND` is set (`src/broker.c:664-666`). The flags then reach `openat` unchanged (`:840`).
  - Exec needs only read (`:1006`). Write-only (drop box) grants aren't possible.
  - **Not checked on the resulting descriptor:**
    - Create modes aren't masked: `O_CREAT` and `mkdir` modes may carry setuid, setgid or sticky bits (`src/broker.c:877`, `:956`), while `SBX_CHMOD` masks to 0777 (`:988`).
    - Descriptor calls are never filtered: `fchmod`, `fchown`, `fsetxattr`, `futimens`, `flock`, `fcntl` locks and `FS_IOC_SETFLAGS`. A read-only descriptor to a same-UID file therefore allows chmod (setuid included), chown within the UID's groups, user xattrs, time changes, locks the host then waits on, and inode flags.
    - `O_APPEND` can be cleared with `fcntl(F_SETFL)`.
- **Consumers:** all, especially C-03 and C-05.
- **Impact:** "read-only" means "can't write the bytes", not "can't change the file".
- **Remediation:**
  - rights for read, create, append, truncate, delete, rename, execute, traverse, list, metadata and lock (F-01);
  - mask create modes to 0777;
  - for strict profiles, filter `fchmod`, `fchown`, `fsetxattr`, `futimens` and `FS_IOC_SETFLAGS` on descriptors (or open read-only grants on a read-only mount where available, or through Landlock);
  - say what is enforced on the descriptor, versus only at open.
- **Regression tests:**
  - a read-only rule: `open(O_RDONLY)`, then `fchmod(04755)`, is refused in strict mode (allowed today);
  - `open(O_CREAT, 04755)` under a write rule creates the file without setuid.
- **Dependencies:** F-01; A-10.
- **Approval:** API and filter.

### A-12: Windows static grants persist beyond the worker
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `grant_static` adds an inheritable read ACE for the container SID (`src/windows.c:693-724`). It covers everything under the folder and is never removed.
  - Nothing is rolled back when a spawn fails partway.
  - The container profile is created by name, reused and never deleted. Its SID comes from the name (`:664-679`).
  - The Windows test leaves its own static grant on the build folder.
- **Consumers / platforms:** C-04 (Python runtime folders). Windows.
- **Impact:**
  - a later instance under the same name (any plugin given that name) inherits every earlier static grant;
  - grants accumulate on the folders;
  - two instances share each other's grants (A-27).
- **Remediation:**
  - a per-instance container name (a nonce);
  - `sbx_container_remove` deletes the ACEs naming the SID and the profile;
  - rollback on a failed spawn;
  - the report sets `SBX_R_PERSISTENT_GRANTS` when the grants stay.
- **Regression test:** spawn and exit, then check that no ACE for the SID remains on the folder (after the fix). Two instances, A and B, under one name: B can't read A's static folder (after the fix). Control: the same instance can.
- **Dependencies:** A-27; D.
- **Approval:** API and behaviour.

### A-13: A requested LPAC can quietly become a plain AppContainer
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `less = spec->less_privileged && has_less_privileged()` (`src/windows.c:939`). The check is only the OS version (`:652-660`).
  - The outcome appears only in `sbx_process.less_privileged` (`:1022`, `include/sbx.h:517`). The Windows test never checks that field.
- **Consumers / platforms:** C-04, C-05. Windows.
- **Impact:** a consumer that requires LPAC, and doesn't read the field, runs in a plain AppContainer. That container matches every `ALL APPLICATION PACKAGES` ACE on the system.
- **Remediation:**
  - required vs preferred (D: `SBX_G_IDENTITY_LEAST` in `required` fails the spawn when unavailable);
  - check the token afterwards (`TokenIsLessPrivilegedAppContainer`) rather than the version.
- **Regression test:** LPAC required on a system without LPAC (simulated by forcing the probe off) fails with nothing started. On a system with LPAC, the child's token reports less-privileged. Control: preferred falls back, and the report says so.
- **Dependencies:** D.
- **Approval:** API.

### A-14: Windows process mitigations are not configured
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:** the only attributes set are security capabilities, child-process policy, handle list and the less-privileged packages policy (`src/windows.c:955-962`). No `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` bits are set.
- **Consumers / platforms:** C-04, C-05, C-07. Windows.
- **Impact:** missing protections that are cheap and supported:
  - extension-point and image-load restrictions;
  - strict handle checks;
  - Win32k lockdown for non-UI workers;
  - dynamic-code prohibition where there is no JIT;
  - CET.
- **Remediation:** a mitigation set in the spec:
  - a safe default: DEP, ASLR, strict handle checks and extension points off;
  - opt-in: image load only from system or signed locations, prohibited dynamic code (not for Python ctypes callbacks or JIT), Win32k off (not for UI or GPU), CET;
  - each one reported.
- **Regression test:** spawn with each mitigation, then check it with `GetProcessMitigationPolicy` in the child. With dynamic code prohibited, `VirtualAlloc(PAGE_EXECUTE_READWRITE)` fails. Control: without it, it succeeds.
- **Dependencies:** D.
- **Approval:** API and default behaviour.

## A-15 .. A-28

### A-15: GPU access is a substantial attack surface
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `src/lockdown.c:24` and `include/sbx.h:10-12`: every call on a held descriptor is allowed.
  - `src/lockdown.c:2225-2246`: `own_opens` paths are opened `O_RDWR`, with 3 spares (`:250`), and kept.
  - `src/lockdown.c:1996-2002`: `ioctl` and `mmap` are filtered only for `sealed_fds`, never for own-opens.
  - The only own-opens test uses `/dev/zero` (`tests/sbx_test.c:2793`).
- **Consumers / platforms:** C-02 (Enginehost own-opens `/dev/kgsl-3d0`, `/dev/mali0`, `/dev/dri/renderD128`, `/dev/hwbinder`; `docs/design.md:231`); C-01 GPU plugins. Android.
- **Impact:** a compromised GPU worker has the full ioctl and mapping surface of the kernel GPU driver. A driver bug escapes every file and broker control.
- **Remediation:**
  - a "GPU-capable" assurance class, with residual `SBX_R_GPU` reported;
  - an optional per-device ioctl request-number allowlist, where drivers have stable numbers;
  - split-process rendering (`docs/design.md:96-100`) as the stronger model.
- **Regression test:** own-open a stand-in device and assert the report lists it as residual. A real ioctl allowlist test goes in `tests/android/gpu_probe.c` (device only).
- **Dependencies:** F-03 report; A-16; A-28.
- **Approval:** the report and any ioctl-filter flag (API).

### A-16: Binder and graphics lifecycle is not a complete authorization model
- **Priority:** P1 · **Verdict:** Design gap, confirmed
- **Evidence:**
  - `include/sbx.h:276-301`: the only choices are a whole descriptor (`own_opens`) or none (`sealed_fds`).
  - `docs/design.md:1617-1627`: a confined ART process "can still ask system services for things as its app".
  - `sbx_relay` is planned, not built (`docs/design.md:107-117`, `:1662`); `src/` has no transaction mediation.
- **Consumers / platforms:** C-01 (whose acceptance criterion is at stake), C-02 ART engines. Android.
- **Impact:** a same-UID ART worker can make any Binder call its app may. This is the concrete form of A-01.
- **Remediation:** the per-service, per-transaction relay (`sbx_relay`). Until it exists, report `SBX_R_BINDER` whenever a binder node is held unsealed.
- **Regression test:** `tests/android/` on a device or emulator: a confined ART process transacts with an unrelated service. Refused with the relay; the unconfined control succeeds.
- **Dependencies:** F-07 (brokered services); A-01; A-08.
- **Approval:** new feature (relay).

### A-17: Process-tree containment across exec and fork
- **Priority:** P1 · **Verdict:** Partially confirmed
- **Built and tested, on Linux gcc/clang/asan, arm64 and both emulators:**
  - dynamic exec chains 3 deep (`exec_check`, `tests/sbx_test.c:1852`);
  - `#!` scripts, nested shells and pipes under `SBX_LOCK_CONTAIN`, plus learning and attach variants (`program_tree_check`, `:1985`);
  - fail-closed adoption (`exec_helper_check`, `:1701`);
  - fork with signal-tree membership (`signal_tree_check`, `:1525`).
- **Not tested:**
  - Wine, PRoot;
  - fork/exec races;
  - `vfork` and `clone(CLONE_VM)`;
  - `setsid` and process groups;
  - a static target. It runs with sbx-exec's 6-call minimal handler, and other path calls get `ENOSYS`, so it is more restricted, not an escape (`docs/design.md:980-982`).
- **Not built:** a per-process read-back of the effective profile, which the review's acceptance requires.
- **Consumers / platforms:** C-03, C-04 subprocesses, C-07. Linux and Android, x86_64 and aarch64.
- **Impact:** the dynamic-ELF tree looks sound. The headline tree consumers (Wine, PRoot) are unvalidated.
- **Remediation:** the adversarial tree tests below; a self-report call (F-03); a Wine or Box64 tree in CI.
- **Regression tests** (`tests/sbx_test.c`, next to `program_tree_check`):
  - static exec: runs; out-of-set path calls give `ENOSYS`. Control: unconfined reads the secret.
  - `CLONE_VM` child: opening outside the rules gets `EACCES`.
  - `setsid`, then a signal outside the tree: `EPERM`.
- **Dependencies:** A-04; F-03; F-08.
- **Approval:** tests need none; the read-back API needs approval.

### A-18: Resource exhaustion is incompletely controlled
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `src/spawn.c:115-117`: rlimits only, on the `sbx_spawn` path only, at most 8 (`include/sbx.h:459-464`).
  - `sbx_lockdown` and `sbx_attach` set no limits. No cgroups anywhere in `src/`.
  - Windows `make_job` (`src/windows.c:848-865`) has: one active process, kill on close, die on unhandled exception, an optional per-process memory limit, and UI limits. It has no CPU time, CPU rate or I/O limit.
- **Consumers / platforms:** C-05 and C-06 (which require limits), C-07. All.
- **Impact:** a worker can exhaust CPU, wall time, disk, descriptors and log volume, denying service to its neighbours.
- **Remediation:**
  - Linux: a cgroup v2 child (`memory.max`, `pids.max`, `cpu.max`), tied to the tree's lifecycle;
  - Windows: CPU rate control, job CPU time and handle limits;
  - a portable `resource_budgets` struct, with the budgets actually enforced reported.
- **Regression tests:**
  - `sbx_spawn` with `RLIMIT_NOFILE` gives `EMFILE` past the limit;
  - Windows: memory beyond `memory_limit` fails;
  - cgroup tests, gated on availability.
- **Dependencies:** F-01; A-19.
- **Approval:** API and backend.

### A-19: Broker saturation can become a denial of service
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - one serve thread per connection (`src/broker.c:1823-1868`, `:2060-2092`);
  - one detached thread per blocking `connect` or `accept`, with no cap (`net_wait_start`, `:1214-1242`);
  - no per-worker budget, queue limit, timeout or cancellation;
  - `tree_note` silently drops new members when its 1024 slots are full (`:174-179`);
  - deciders run inline (`:1170-1180`).
- **Consumers / platforms:** C-05, C-06, C-01 multi-plugin hosts, C-07. Linux and Android. Windows: one pipe instance per worker, so it is bounded, but has no timeout.
- **Impact:** one worker can make thousands of blocking connects, exhausting the broker process's threads, memory and descriptors, so every worker it serves stalls.
- **Remediation:**
  - cap `net_wait` threads per connection and in total (`EAGAIN` past the cap);
  - an outstanding-request budget per worker;
  - a decider timeout;
  - `tree_note` refuses on overflow instead of dropping;
  - a bounded thread pool.
- **Regression test:** a worker opens 2000 blocking connects to a silent peer. The broker's thread count stays bounded, and a second worker is still served within a timeout. The control, without a cap, shows the growth.
- **Dependencies:** A-18; A-22.
- **Approval:** an observable behaviour change.

### A-20: Audit logs and trace rings can expose sensitive data
- **Priority:** P1 · **Verdict:** Partially confirmed: the review overstates the trace ring
- **Evidence:**
  - The default audit prints full asked and resolved paths to stderr (`src/broker.c:108-113`, Windows `src/windows.c:291-296`).
  - Learning records carry all 6 arguments (`src/protocol.h:105-110`) and print 3 as hex (`src/broker.c:1683-1702`).
  - The trace ring stores the syscall number, `arg0` (a value, never dereferenced), `ip` and `tid`, but no paths (`include/sbx.h:372-379`). Fault records hold module and symbol names (`:393-414`).
  - Inconsistency: on Linux, `sbx_policy_set_audit(policy, NULL, …)` restores the path-printing default (`src/broker.c:262-263`); on Windows it disables auditing (`src/windows.c:340`, `:573`).
- **Consumers / platforms:** C-05, C-06, C-04. All.
- **Impact:** refused paths reach whatever captures stderr. A Linux host that passes NULL to silence the audit is wrong about it.
- **Remediation:**
  - NULL means no audit on every platform;
  - audit classes, with optional path redaction (a hash or a prefix);
  - document that the trace ring holds no paths.
- **Regression test:** with a NULL audit, a refusal writes nothing to stderr; a refused open's trace entry has no path bytes.
- **Dependencies:** F-03 `audit_policy`; A-05.
- **Approval:** the Linux NULL change (behaviour), and the redaction API.

### A-21: Broker crash or disconnect needs a fail-closed contract
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `exchange` returns `-EIO` when the broker is gone (`src/lockdown.c:459-460`) or the reply is short (`:487-490`). The reply's version is never checked.
  - The process is never ended: it keeps running, and every brokered call fails.
  - There is no reconnect.
  - Under `SBX_LOCK_PASSTHROUGH`, unclaimed paths still reach the kernel after the broker dies.
  - Windows: `sbx_open` returns `-EIO` and the child keeps running (`src/windows_client.c:60-66`). The job is killed only when the host closes it (`src/windows.c:854`, `:1044-1062`), not when the broker thread ends.
- **Consumers / platforms:** C-05 and C-06 (fail-closed required), C-03 ("no descendant outlives the authority"), C-07. All.
- **Impact:** a worker outlives its authority, half-working. That is the opposite of fail-closed.
- **Remediation:**
  - a host-selectable fail-closed option, on in strict profiles: a broker-gone `-EIO` ends the process (`exit_group`);
  - check the reply's version;
  - Windows: the broker thread closes the job when its pipe breaks, in strict mode;
  - document the behaviour per platform.
- **Regression test:** close the broker's end. In strict mode the child exits on its next brokered call; in the compatibility control it gets `EIO` and continues. A stub broker sending a short reply gives `EIO` and no leaked descriptor. A Windows equivalent too.
- **Dependencies:** F-04; A-09; A-19.
- **Approval:** a behaviour change.

### A-22: Privileged host callbacks can be confused deputies
- **Priority:** P1 · **Verdict:** Confirmed (design gap)
- **Evidence:**
  - `struct sbx_access` carries op, asked, resolved, need, flags, `pid`, `rule_verdict` and `allowed_by` (`include/sbx.h:592-605`). There is no worker identity beyond the pid, no policy version and no request id.
  - The pid comes from `SCM_CREDENTIALS` in `serve_loop` (`src/broker.c:1854-1861`), which the kernel vouches for.
  - The decider is asked on every request (`src/broker.c:713-720`); nothing is cached.
  - A listener serves many workers with one policy and one decider (`:1889-1893`).
- **Consumers / platforms:** C-01, C-04, C-05: hosts whose permission system is the decider. All.
- **Impact:** a host that records consent by path can apply one worker's consent to another worker's request. The library gives the host no principal to key its records on.
- **Remediation:** append a broker-assigned `worker_id` (from the attach token or connection), a `policy_version` and a `request_id` to `struct sbx_access`. Add a policy per worker (`sbx_broker_listen_each`, D).
- **Regression test:** two attached workers, with a decider that allows a path only for the worker that consented. Worker B is refused A's path; A's re-request is allowed. This can't be written today, which is itself the evidence.
- **Dependencies:** A-27; D.
- **Approval:** an ABI addition.

### A-23: Time-of-check/time-of-use and authorization races
- **Priority:** P1 · **Verdict:** Partially confirmed
- **The defences are real:**
  - `open_parent`, `open_decided` (`O_NOFOLLOW`) and `confirm_opened` (`src/broker.c:782-855`);
  - a 5000-open symlink-swap race test with an unconfined outside file (`tests/sbx_test.c:556`, `:2789-2821`).
- **Gap:** policy mutators take no lock. `add_rule` reallocates the rules (`src/broker.c:354-367`) while serve threads read them unlocked (`:436-463`). Only the tree and exe tables are locked.
- **Consumers / platforms:** C-03, C-05, C-07: any host that grants after serving starts. Linux and Android; on Windows one broker thread per worker narrows it.
- **Impact:** `sbx_policy_add` after `sbx_broker_start` (for example, after a picker) races a `realloc` against readers. That is a use-after-free in the more privileged process. The host triggers it, not the worker, but it is still a soundness hole.
- **Remediation:** document that mutating a served policy is forbidden, or take a read-write lock; make revocable tagged rules (`docs/design.md:1193`) the supported dynamic grant.
- **Regression test:** a confined open loop while the host calls `sbx_policy_add` in a loop, under TSan and ASan, with no report expected. CI has no TSan job; add one.
- **Dependencies:** A-22; F-05.
- **Approval:** a locking or contract change.

### A-24: Shared memory and descriptor transfer require explicit authority
- **Priority:** P1, P0 for any consumer relying on `sealed_fds` · **Verdict:** Confirmed, and worse than stated
- **Evidence:**
  - Sealing compares fd *numbers* in BPF (`src/lockdown.c:1699-1706`, applied at `:1995-2004`).
  - `socketpair` is never filtered.
  - Reproduced: under a default lockdown, the sealed descriptor's `ioctl` gets `EPERM`. The same descriptor, received back over `SCM_RIGHTS` under a new number, passes `ioctl`.
  - `memfd_create`, SysV `shmget`/`shmat` and RWX shared mappings are allowed (reproduced). The design says so (`docs/design.md:863-864`).
  - `sbx_lockdown` neither inventories nor closes inherited descriptors (`src/lockdown.c:2129-2307`): reproduced with an outside-the-rules file opened before lockdown, still readable after. Only `sbx_spawn` closes them (`src/spawn.c:42-66`).
  - `sealed_check` (`tests/sbx_test.c:572`) tests only the original number.
- **Consumers / platforms:** C-01, C-05, C-06: anyone sealing binder or GPU. Neither droidtop nor Enginehost uses `sealed_fds` today (checked), so no shipped workload is exposed. Android, Linux.
- **Impact:** an advertised mechanism, "a sealed binder descriptor carries none" (`include/sbx.h:276-283`), is bypassable in one step. Shared memory and inherited descriptors are channels that no policy sees.
- **Remediation:**
  - stop advertising sealing until it seals the open file, not the number. Options: refuse `SCM_RIGHTS` ingress in strict profiles (filter `recvmsg` with control data, or refuse `socketpair` under a strict flag), or close the descriptor instead of sealing it;
  - a shared-memory capability class;
  - an inherited-descriptor inventory at lockdown, refusing undeclared descriptors in strict mode.
- **Regression test:** extend `sealed_check`: `socketpair`, send the sealed descriptor, receive it, `ioctl` the copy. Expected refused; the unconfined control succeeds. A second test: `memfd_create` + a shared writable mapping is refused in strict mode.
- **Dependencies:** A-02; A-08; A-27.
- **Approval:** filter change, new class, doc correction (H).

### A-25: Execution and code-loading paths need policy controls
- **Priority:** P1 · **Verdict:** Partially confirmed
- **Correct:**
  - exec is refused unless `SBX_LOCK_EXEC` (`src/lockdown.c:2046-2055`, reproduced);
  - with it, the broker decides as a read of a regular file with an execute bit (`src/broker.c:1004-1023`);
  - library loading goes through brokered `open`.
- **Gaps:**
  - No W^X control: `mmap`/`mprotect` with `PROT_EXEC` on anonymous or memfd memory is always allowed (reproduced). A strict "no unreviewed code loading" profile can't be enforced.
  - The trampoline allows any `execveat(fd, "", AT_EMPTY_PATH)` (`src/lockdown.c:1802-1809`), not only the helper. Code that calls it can run any descriptor it holds without an exec decision. The image keeps the filter and gains no authority, but `docs/design.md` says only the helper's run gets through (H).
- **Consumers / platforms:** C-05 (must forbid), C-02 (needs JIT allowed), C-04. Linux and Android. Windows: the dynamic-code mitigation isn't used (A-14).
- **Remediation:** an opt-in W^X flag (refuse `PROT_WRITE|PROT_EXEC` together, and `PROT_EXEC` on anonymous memory); Windows dynamic-code policy; correct the design text.
- **Regression test:** with the flag, `mmap(PROT_WRITE|PROT_EXEC)` and `mprotect(PROT_EXEC)` on anonymous memory get `EACCES`; without it (the control), both succeed.
- **Dependencies:** A-14; F-01.
- **Approval:** new flag.

### A-26: Cross-platform semantics are not equivalent
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - `sbx_lockdown` returns only 0 or an errno (`include/sbx.h:330`), with no report of what was installed.
  - Windows's `less_privileged` field is the only effective-state output there is, and it reports a silent downgrade (A-13).
  - There is no "sandbox enabled" boolean to misuse, but nothing positive either.
- **Consumers:** all.
- **Impact:** a consumer can't tell "installed as asked" from "installed with something missing", so a required protection can quietly become advisory.
- **Remediation:** the D contract: `sbx_negotiate`, the `*_checked` calls and `sbx_report`.
- **Regression test:** T-14.
- **Dependencies:** none; this is the root of Phase 1.
- **Approval:** API.

### A-27: Multiple workloads may share authority unintentionally
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - one policy for every client of a listener (`src/broker.c:1889-1893`);
  - `exe_records` is a static table shared by every policy, keyed by pid only, without a start time (`src/broker.c:737-774`). The tree table is per policy and start-time-qualified (`:123-177`);
  - Windows: the SID comes from the container name (`src/windows.c:664-679`), and static ACEs stay (`:693-724`), so two instances under one name share every static grant.
- **Consumers / platforms:** C-01, C-02, C-05 when co-hosted. All.
- **Impact:**
  - Windows: a cross-instance file grant;
  - Linux: an exe-path record served across policies, or to a reused pid.
- **Remediation:** per-policy `exe_records` keyed by pid and start time; an instance nonce in the container name, with cleanup (A-12); a per-worker identity (A-22).
- **Regression test:** T-10: two hostile instances on each platform; neither reaches the other's grants or records.
- **Dependencies:** A-12; A-22.
- **Approval:** behaviour and API.

### A-28: Kernel/runtime vulnerability containment needs a realistic claim
- **Priority:** P1 · **Verdict:** Confirmed
- **Evidence:**
  - The filter is a denylist ending in `ret(ALLOW)` (`src/lockdown.c:2069`).
  - Refused (`EACCES`), at `:2006-2055`: the path mutators, exec without the flag, `ptrace`, `process_vm_*` on others, `process_madvise`, `bpf`, `perf_event_open`, io_uring, raw and netlink sockets, xattrs, `*_handle_at` and `fanotify_mark`.
  - Denied (`EPERM`), at `:2059-2068` and `:1948-1951`: namespaces, mount, `chroot`, `pivot_root`, the keyring, `kcmp`, pidfd, `tkill` and module loading.
  - Allowed (reproduced): `ioctl` (unfiltered except on sealed numbers), `socketpair`, `memfd_create`, SysV shm, `mmap`/`mprotect` `PROT_EXEC`, `userfaultfd`, `personality` and `seccomp(GET_ACTION_AVAIL)`.
- **Consumers:** all, most of all C-02 and C-05 (GPU) and C-01 (binder).
- **Impact:** the allowed kernel APIs remain an exploit path. `userfaultfd`, a well-known exploit primitive, has no flag to drop it.
- **Remediation:**
  - a residual-syscall register per profile, generated from `build_filter`;
  - optional flags to refuse `userfaultfd` and to allowlist `ioctl` request numbers;
  - never claim containment of kernel bugs.
- **Regression test:** a generated `surface_check` asserting each syscall's class against the register, as a drift guard, with confined vs unconfined comparison.
- **Dependencies:** A-15; A-24; F-03.
- **Approval:** new flags; the register is documentation.
