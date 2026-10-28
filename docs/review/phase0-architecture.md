# Fibrewall Phase 0 — Deliverables B, D, G

## B. Current security capability matrix (at `2dfda43`, v0.1.7)

What each backend has today, kept in four separate kinds of column:

- **Mechanism:** the operating-system feature used.
- **Configuration:** how a consumer turns it on.
- **Guarantee:** what an attacker running inside the worker cannot do, *if
  the configuration is as stated*.
- **Limitation:** what it does not stop.

"Linux" means Linux and Android unless a row says otherwise. Neither
backend gives a different operating-system identity. On Linux and Android
the worker keeps the uid and SELinux domain of whoever started it: the
host's own on Linux, the app's on Android. Isolated-UID on Android comes
from the consumer's service, not from this library. On Windows the
identity comes from the AppContainer SID, which is a real security
principal.

### Linux and Android: `sbx_lockdown` (seccomp-bpf, SIGSYS broker)

| Capability | Mechanism | Configuration | Guarantee | Limitation |
| --- | --- | --- | --- | --- |
| **Lockdown on every thread** | `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)` with `no_new_privs` | `sbx_lockdown(fd, &options)` | every thread of the process is under the same filter once the call returns 0; it can't be removed or widened | a filter is only additive: code that ran *before* the call was unconfined (A-04). A thread that blocks SIGSYS makes the lockdown refuse (`EDEADLK`) |
| **File system view** | path calls trap; the broker resolves under its own identity and passes a descriptor (`SCM_RIGHTS`) | `sbx_policy_add` rules (`SBX_READ`/`SBX_WRITE`/`SBX_DENY`), aliases, decider | a path the rules and decider refuse is never opened for the worker. Symlinks, `..` and `/proc/self/*` are judged where they lead (`open_parent`/`confirm_opened`) | descriptors already held, or handed over (`own_opens`, `sbx_local_add`), are used directly by the kernel (A-02). Read and write are the only rights (A-11) |
| **Exec** | trapped; the broker decides the target; `sbx-exec` loads it under the inherited filter | `SBX_LOCK_EXEC` + `exec_helper` + `child_library` | every new image runs under the same filter from its first instruction; `#!` scripts are handled as the kernel does | the loader runs with sbx-exec's minimal handler (6 path calls). A static target keeps only that handler. Without `SBX_LOCK_EXEC`, exec is refused |
| **Process tree** | fork keeps the filter and handler; exec as above; `libsbx_child.so` adopts or attaches | `sbx_broker_listen` + `SBX_BROKER`/`SBX_TOKEN` env, or lockdown before exec | descendants of a locked-down process can't shed the filter | a tree started by attach (`LD_PRELOAD`) is unconfined until the constructor runs. Other constructors and `DT_PREINIT` code may run first (A-04). No tree-wide teardown: `PR_SET_PDEATHSIG` covers only `sbx_spawn`'s direct child |
| **Network, none** | `socket` refused except Unix datagram with `SBX_LOCK_LOG_SOCKET` | default | no inet, netlink or packet sockets can be made | inherited sockets still work (A-02, A-07) |
| **Network, own sockets** | filter allows inet stream/dgram (`SBX_LOCK_INET`); every socket family listed (`SBX_LOCK_SOCKETS`) | flags | | no per-destination control: any address the uid can reach, loopback included |
| **Network, brokered** | broker makes the sockets; each destination goes to the decider | `SBX_LOCK_NET_BROKERED` + `sbx_policy_set_net` | the decider sees and may refuse every connect, bind and accept | grants are per policy, not per worker (A-06, A-22). The receiver sees the broker's identity |
| **Unix IPC** | `connect`/`bind` brokered as paths; abstract names listed | `SBX_LOCK_UNIX`, `sbx_policy_add_unix_name` | only sockets the rules allow | `SBX_LOCK_SOCKETS` lets any reachable socket through (A-08). Binder through a preopened fd is unfiltered (A-16) |
| **Signals** | `kill`/`tgkill` only to own pid; or brokered | default; `SBX_LOCK_SIGNALS`; `SBX_LOCK_SIGNAL_TREE` | default: no signal to another process | `SBX_LOCK_SIGNALS` reaches every process of the uid |
| **Clear escapes** | refused in every mode | always | no ptrace, `process_vm_*` (except own memory, v0.1.6), namespaces, mount, bpf, `perf_event_open`, io_uring, module loading, keyring, new SIGSYS handler | allowed syscalls remain kernel attack surface (A-28) |
| **Devices** | descriptors opened before lockdown; the handler answers later opens from them | `own_opens`, `sbx_local_add` | only listed device paths open | ioctl on them is not filtered: GPU and hwbinder are full surfaces (A-15, A-16) |
| **Resources** | rlimits at `sbx_spawn` | `spec.limits` | the limits the consumer sets | no cgroups, CPU time, process count or broker budgets (A-18, A-19) |
| **Learning** | refusals recorded, then allowed | `SBX_LOCK_LEARN` | none: no protection while on | must never ship on (A-05) |
| **Diagnostics** | trace ring, audit callback, kernel audit | `sbx_trace`, `sbx_policy_set_audit`, `SBX_LOCK_AUDIT` | | may record paths and arguments (A-20) |

### Windows: `sbx_spawn` (AppContainer / LPAC, job object, named-pipe broker)

| Capability | Mechanism | Configuration | Guarantee | Limitation |
| --- | --- | --- | --- | --- |
| **Identity** | AppContainer SID, no capabilities; LPAC where supported | `spec.container`, `spec.less_privileged` | every object ACL that doesn't name the SID refuses it. LPAC refuses `ALL APPLICATION PACKAGES` grants too | LPAC unavailable leads to a plain AppContainer, reported only in `out->less_privileged` (A-13). One container name is shared by every instance using it (A-12, A-27) |
| **Confinement before code** | process created suspended, assigned to the job, then resumed | `sbx_spawn` | confined from its first instruction | |
| **Process tree** | `CHILD_PROCESS_POLICY` restricted + job with 1 active process, no breakaway, kill on close | always | no child processes; the worker dies with the job handle | |
| **Handles** | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` | `spec.handles`, std handles | only listed handles are inherited | a listed handle keeps whatever access it was opened with |
| **Files** | the broker opens under its identity, checks the final path, and duplicates at the exact access | policy rules; `sbx_open` | a refused path is never opened; junctions, `..`, ADS and device paths are refused (tested) | open only: no rename, delete or list (the agent lane does those itself) |
| **Static grants** | an inheritable ACE for the SID on a folder | `SBX_READ \| SBX_STATIC` | read-only, kernel-enforced | the ACE outlives the worker (A-12) |
| **Network** | none (no capabilities) | always | no sockets, loopback included | no brokered network on Windows |
| **UI** | job UI limits | always | no clipboard, global atoms, other desktops, or system parameters | window messages within the same desktop are limited only by UIPI and the limits |
| **Memory** | job per-process memory limit | `spec.memory_limit` | | no CPU, handle or I/O limits (A-18) |
| **Mitigations** | none set | none | | no `PROCESS_CREATION_MITIGATION_POLICY` bits (A-14) |

### Not available on any backend today
- A separate identity on Linux: no uid or namespace setup.
- Landlock and cgroups.
- An effective-enforcement report, beyond Windows's `less_privileged` field.
- A required/preferred/forbidden negotiation.
- A policy digest.
- Per-worker grants in a shared broker.
- Revocation of descriptors already given.
- macOS, iOS and BSD backends.

## D. Proposed API changes

Written as a compilable header, `include/sbx_contract.h`, on branch `ci/fibrewall-phase0` (proposal only, not built, not in the ABI). It defines: `SBX_G_*` guarantee bits and `SBX_R_*` residual-authority bits; size-prefixed `struct sbx_requirements` (required / preferred / forbidden) and `struct sbx_report` (effective / unavailable / residual / blocking / backend / policy_digest / launch_result / reason); `sbx_negotiate` (dry run); `sbx_lockdown_checked`; `sbx_spawn_confined` (A-04); `sbx_spawn_checked` (A-13); and `sbx_broker_listen_each`, a policy per attaching worker (A-06, A-22, A-27). Compatibility: all additive — new symbols and new structs, no change to existing calls, so the C ABI is preserved. It compiles under gcc and mingw with -Wall -Wextra -Werror.

---

## G. Cross-platform feasibility

Each platform is split into four parts:
- **Supported mechanisms:** documented, stable operating-system features.
- **Assumptions:** what the design relies on and must be tested.
- **Restrictions:** what the platform won't let a third-party app do.
- **Guarantees that can't be offered:** things to report as unavailable,
  never to emulate.

### Linux (desktop and server)
- **Supported, in use:** seccomp-bpf with `TSYNC`, `no_new_privs`,
  `SCM_RIGHTS` and `SCM_CREDENTIALS`, `PR_SET_PDEATHSIG`, rlimits.
- **Supported, not used:**
  - Landlock (5.13+; network rules 6.7+), as a kernel-enforced file
    system and TCP-port layer beneath the broker. It would make
    `SBX_G_FS_MEDIATED` hold even against a bug in the handler;
  - unprivileged user namespaces with mount, PID, IPC and net (where the
    distribution allows them; Ubuntu 24.04 restricts them through
    AppArmor);
  - cgroup v2 for memory, pids and CPU (needs a delegated subtree:
    systemd `Delegate=` or a user session);
  - `SECCOMP_RET_USER_NOTIF` (5.0+), which needs no in-process handler;
  - pidfd for tree teardown.
- **Assumptions:** the kernel's seccomp and SIGSYS semantics hold; the
  loader and libc don't make path calls this design misses. Both are
  tested on Ubuntu 24.04 only.
- **Can't be offered without privilege:** a different uid. That needs
  root, a setuid helper or a user namespace, so `SBX_G_IDENTITY_SEPARATE`
  is unavailable unless one of those is present.

### Android
- **Supported, in use:** seccomp (8.0+ always has it), the broker,
  descriptors.
- **Supported, consumer side:** `isolatedProcess` services (a separate
  uid and `isolated_app` domain). This is where `SBX_G_IDENTITY_SEPARATE`
  and `SBX_G_IDENTITY_LEAST` come from on Android.
- **Restrictions:**
  - no user namespaces and no Landlock on the kernels handhelds ship (the
    RP5 runs 4.19);
  - no cgroup control for apps;
  - an isolated process can't use the GPU, so GPU workloads run same-UID
    (A-01, A-15);
  - SELinux varies by vendor; the emulator is not a real device (T-12).
- **Can't be offered:** a separate identity for a GPU workload in the
  same process, and Binder filtering (seccomp sees only `ioctl`, not the
  transaction). Both must be reported as residual (`SBX_R_HOST_UID`,
  `SBX_R_BINDER`, `SBX_R_GPU`). The only structural fix is a split
  process: software or remote rendering in the isolated worker, with the
  GPU in a host-owned process.

### Windows
- **Supported, in use:** AppContainer (Windows 8+), LPAC (10 1703+), job
  objects (nested since 8), handle lists, child-process policy.
- **Supported, not used:**
  - `PROCESS_CREATION_MITIGATION_POLICY` and `_POLICY2`: DEP and ASLR on,
    strict handle checks, extension points off, image load only from
    signed or system locations, prohibited dynamic code (not for
    JIT/Python ctypes callbacks), Win32k lockdown (not for UI or GPU),
    CET;
  - job CPU rate and handle limits;
  - `DeleteAppContainerProfile`, and ACE removal for cleanup.
- **Assumptions:** the runner's Windows Server image behaves like client
  Windows (LPAC present); the agent's Python and its extensions load in
  LPAC with only static grants. Both are to be tested with real Python
  (#606 design item 1).
- **Restrictions:** an AppContainer profile is per user and named; two
  instances under one name share the SID (A-12, A-27). A per-instance
  name (a random suffix), cleaned up on exit, avoids that.
- **Can't be offered:** network endpoint filtering inside the container
  without the broker; it is either no capability or full capability.

### macOS (not built)
- **Supported:** App Sandbox (entitlements, signed);
  `sandbox_init_with_parameters` (deprecated API, still what Chromium and
  WebKit use for their helpers); XPC services as separate helper
  processes; security-scoped bookmarks.
- **Restrictions:**
  - an App Sandbox helper's sandbox comes from its own signed
    entitlements, so a host can't give each plugin a different profile
    without the SPI;
  - `sandbox-exec` is deprecated and must not be the production basis
    (the review says so too);
  - notarization and the hardened runtime limit loading unsigned plugin
    code (`com.apple.security.cs.disable-library-validation` is needed
    for third-party native plugins, and that weakens the host).
- **Feasible:** a signed XPC helper per plugin class, using App Sandbox
  plus the SPI profile for narrowing, with the broker over XPC or a Unix
  socket. Report `SBX_G_IDENTITY_SEPARATE` as unavailable: App Sandbox
  is per app, not per principal.

### iOS and iPadOS (not built)
- **Restrictions:**
  - no `fork` or `exec`, and no downloaded native code;
  - app extensions are separate processes with their own sandbox, but are
    bundled and signed.
- **Feasible:** only bundled, signed extensions as workers, and WASM or
  interpreters inside them.
- **Can't be offered:** arbitrary downloadable native plugins.
  `sbx_negotiate` must say so, not attempt them.

### FreeBSD and OpenBSD (not built)
- **FreeBSD:** Capsicum (`cap_enter`, `cap_rights_limit`) is a strong
  capability model: after `cap_enter`, no global namespaces at all. A
  broker that passes descriptors maps onto it naturally.
- **OpenBSD:** `pledge` and `unveil`; `unveil` is path containment
  enforced by the kernel.
- Both are separate backends with their own guarantee sets, not seccomp
  look-alikes.

### Cross-platform rule (A-26)
There is no "sandbox enabled" boolean in the proposed API. Each launch
gets the `sbx_report` bit set from D, and a consumer's strict profile is
a `required` mask. A platform that can't meet a bit says so in
`unavailable`, with the reason.
