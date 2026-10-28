# Fibrewall Phase 0 — Deliverable C: consumer conformance matrix

# Consumers of the sandbox library (Fibrewall) at 2dfda43 / v0.1.7: usage, conformance input, documentation claims

Read-only research for the Fibrewall review (Droidtop/tracker `coordination/design/sandbox/fibrewall-review-2026-10-28.md`, sections 3, 7, 11 C and H). Nothing was modified, committed or posted.

## Sources and revisions

- **Library**: `/home/user/sandbox` at `2dfda43` (tag v0.1.7). It is a shallow clone, but every tag from v0.1.0 onward is in its history.
- **droidtop**: the local clone `/home/user/droidtop` is **stale**. Its HEAD is `4930a24` from 2026-10-15, its vendor gitlink is `683c3c7`, and it has no `PluginOpenService`. The current state was read from GitHub `Droidtop/droidtop` main at **`28d2bb5`**, through `mcp__github__get_file_contents` and `gh api ... ?ref=28d2bb5`. Copies of those files are in `/tmp/claude-0/-home-user/df5821a9-6d6e-5a3b-b4e3-bd897750d132/scratchpad/dt/`, with an `m_` prefix for code files. All droidtop line numbers below refer to that commit unless a line says otherwise.
- **Enginehost**: `Droidtop/enginehost` was not in this session's scope. It was attached read-only with `add_repo`, because the task asked for it to be read. It was then shallow-cloned to `/home/user/enginehost` at **`40913f9`** (2026-10-28).
- **droidtop-agent / Pythia** and **Mesh Infinity**: access denied (see "Could not access").

### Pinned library versions (important)

| Consumer | Pin | What it is |
|---|---|---|
| droidtop main (`vendor/sandbox` gitlink at 28d2bb5) | **`a40cc14`** (2026-10-16, "design: the isolated UID is a mode a host chooses") | **Untagged, before v0.1.0, 7 tags behind v0.1.7.** It has `SBX_LOCK_INET` (bbedd55), `SBX_LOCK_NET_BROKERED` (abbeeae), `sbx_local_add_mode`, PASSTHROUGH/claims and list/chmod/utimens. It lacks everything from 2026-10-22 on: SIGSYS kept open (03857cd), `SBX_LOCK_LEARN`, `UNIX`/`SOCKETS`/`SIGNALS`/`SIGNAL_TREE`/`CONTAIN`, `EXEC`, `sbx_broker_listen`/`sbx_attach`/`libsbx_child.so`, `WATCH`, `sbx_trace`, the 64-bit-only build, the `process_vm_readv`-self fix (0.1.6) and the per-open spare descriptors for own-opened devices (0.1.7). |
| droidtop local clone (`/home/user/droidtop`, 2026-10-15) | `683c3c7` (2026-10-14) | An older snapshot, for reference only. |
| droidtop SPEC.md:20703-20704 | says "bi0shacker001/sandbox 467c429, vendored" | **Wrong** about the pin, which is a40cc14. |
| Enginehost (`vendor/sandbox` gitlink, `.gitmodules`) | **`2dfda43` = v0.1.7** | Current. |

## Consumer usage today

### 1. droidtop: plugin sandbox (`plugin-host` module)

**JNI binding.** `plugin-host/native/CMakeLists.txt:33-35` builds `vendor/sandbox` as the static `sbx` library, linked into `libdroidtoppy.so`. The two binding files are below.

**`plugin-host/native/src/plugin_filter.c`** (the confined side; Kotlin `PluginSyscallFilter` in `PluginSandboxService.kt:225-258`)
- It makes one call: `sbx_lockdown(broker_fd, &options)`.
- **Flags**:
  - With `net.sockets` in an open process, the flags are `SBX_LOCK_INET`. Otherwise they are `SBX_LOCK_LOG_SOCKET`.
  - A contained (isolated) process adds `SBX_LOCK_PASSTHROUGH`.
  - An isolated process with the network hole adds `SBX_LOCK_NET_BROKERED` (plugin_filter.c:109-111).
- It never uses `sealed_fds`, `SBX_LOCK_EXEC`, `SBX_LOCK_LEARN`, `SBX_LOCK_UNIX`, `SBX_LOCK_SOCKETS` or `SBX_LOCK_CONTAIN`.
- **`claims`** (PASSTHROUGH) are droidtop's private-data roots under every name: `/data/data/<pkg>`, `/data/user/N/<pkg>`, `/data/user_de/N/<pkg>` (`SandboxBroker.claims`).
- **`own_opens`** are `/dev/hwbinder`, `/dev/kgsl-3d0`, `/dev/mali0` and `/dev/dri/renderD128`, used only in an open process with the `gpu.render` hole (`PluginSandboxService.kt:243, 254-258`). That hole is now unreachable, because `PluginTiers.HOLES = [net.sockets]` (`PluginTiers.kt:42`).
- **An open process is made dumpable** before lockdown (`plugin_filter.c:116`).
- **A contained process gets `RLIMIT_FSIZE`** equal to the data quota, with SIGXFSZ ignored (`plugin_filter.c:117-126`). An open process gets no limit.
- **Report string** (`plugin_filter.c:137`): "on: … no programs, no io_uring, no ptrace, no namespaces, no signals to other processes (every thread)".

**`plugin-host/native/src/plugin_broker.c`** (the broker side, in `:app`; Kotlin `SandboxBroker.kt`)
- Calls: `sbx_policy_new`, `sbx_policy_add`, `sbx_policy_alias`, `sbx_policy_set_decider`, `sbx_policy_set_audit` and `sbx_broker_start` on a `socketpair(SOCK_SEQPACKET)`.
- For a network grant it also calls `sbx_policy_set_net(grants)` and `sbx_policy_add_system_socket("/dev/socket/dnsproxyd", SBX_NET_RESOLVE)` and `("/dev/socket/fwmarkd", SBX_NET_CONNECT|SBX_NET_LISTEN)` (plugin_broker.c:166-168).
- **The decider** (plugin_broker.c:90-96) allows `/dev/ashmem<boot id>`. It returns `-ENOSPC` once the data folder's quota is reached (measured at most once a second) and `SBX_KEEP` for everything else. **It never inspects network accesses.** No `SBX_NET_DECIDE` is set, so any address is allowed.
- **Network grants** for `net.sockets` are `NET_CONNECT|NET_LISTEN|NET_RESOLVE` (`SandboxBroker.kt:144`).
- **Rules** (`SandboxBroker.kt:80-104`):
  - Every tier: the plugin's own `app-data` and `app-data-de` folders as `READ|WRITE|DECIDE` (lines 85-86), with droidtop's private roots aliased to them.
  - The OPEN tier adds READ on `/system`, `/system_ext`, `/product`, `/vendor`, `/odm`, `/apex`, `/linkerconfig`, `/data/dalvik-cache`, `/data/fonts`, `/data/resource-cache`, `/proc`, `/sys`, `/dev/__properties__`, `/dev/binderfs/features`, droidtop's APK folder and its native-library folder (line 91).
  - It also adds RW on `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom` and `/dev/ashmem`.
  - It adds `files.shared` folders by path (`sharedRulesFor`, line 99), and GPU nodes only with `gpu.render`.

**Process tiers** (`plugin-host/src/main/AndroidManifest.xml`; `PluginProcesses.kt`; `NativePluginRunner.kt:115-200`)
- **Contained (default)**:
  - Form: `PluginSandboxService`, `android:isolatedProcess="true"` (manifest:64). From API 29 it is one `bindIsolatedService` instance per plugin. Below that it uses slots `:plugin_sandbox0..7`, which are killed on unbind (`PluginSandboxSlotService`).
  - It refuses to load if the process is not actually isolated (`PluginSandboxService.kt:54`).
  - If the lockdown fails, the plugin does not load (`PluginDangers.PROTECTION_FAILED`). The person can still choose **"Run anyway"** for this run of droidtop: red dialog D2 (`PluginDangers.kt:50-60`), `runUnprotected` (`PluginSandboxService.kt:73`). That is an explicit, user-confirmed downgrade to an isolated UID with no seccomp.
- **`net.sockets` on API 30+**: an "open" plugin whose only hole is the network is routed into an **isolated** process with `SBX_LOCK_NET_BROKERED` (`NativePluginRunner.kt:120-125`, `PluginTiers.runsIsolated`, `PluginTiers.kt:95`). droidtop's broker creates, connects, binds, listens and accepts its sockets **under droidtop's UID**.
- **Open process (`PluginOpenService`)**: covered in its own audit below.
- **Full trust**:
  - Form: `PluginRuntimeService` and `FullTrustSlot1..7`, `:pluginhost*`, droidtop's UID, **no lockdown at all**. The manifest says so: "This is crash containment, not security" (manifest:35).
  - Who runs here: contract-1 plugins and plugins granted `host.full_trust`.
  - A debug switch `debug.droidtop.isolate_full=1` (`PluginTiers.kt:58-63`) runs contract-2 full-access plugins isolated with the brokered network (`NativePluginRunner.kt:123, 196`). **It is off by default.**

**PluginOpenService: separate audit of the same-UID path** (`PluginSandboxService.kt:191-212`; manifest:88ff, `:plugin_open0..7`, `isolatedProcess="false"`)
- **Who lands here today**:
  - A plugin granted `net.sockets` on **Android 8-10** (API < 30), because `runsIsolated` requires API 30.
  - A plugin whose `_droidtopHoles` still names `gpu.render`. The code path exists, but the permission is retired.
- **Identity**: droidtop's own UID and SELinux domain (`untrusted_app`). It has droidtop's `INTERNET`, its storage permission (`MANAGE_EXTERNAL_STORAGE` where granted), its Shizuku binder reachability and everything else the UID holds.
- **Library mechanisms it uses**:
  - `sbx_lockdown` with no PASSTHROUGH, so every path is brokered.
  - `SBX_LOCK_INET` (any IPv4/IPv6 TCP/UDP endpoint, `bind`/`listen` included, no Unix sockets) or `SBX_LOCK_LOG_SOCKET` (AF_UNIX datagram `socket`+`connect` to any datagram socket the UID can reach).
  - No `sealed_fds`, so the binder descriptors ART holds stay usable. No resource limits.
- **Residual authority (not mediated)**:
  - Binder calls to every system service as droidtop.
  - Starting or binding droidtop's own non-exported components. plugin-api.md:4265 lists this as **open** below Android 11.
  - The Shizuku binder, if droidtop has one. plugin-api.md:3684 admits this.
  - Inherited zygote/ART descriptors.
  - Loopback/LAN services of droidtop and other apps, through INET.
  - Network traffic that is droidtop's.
- **Process hardening it has**:
  - One plugin per process, killed on unbind (`PluginOpenService.onUnbind`), and the slot is not reused until death is seen (`PluginProcesses.kt` `dying`).
  - Callers checked by `DroidtopCallers`, per plugin-api.md:4257-4260.
- **Plain-language disclosure**:
  - Containment check, OPEN text (`PluginCrashPolicy.kt:129`): "…shares droidtop's user id, so its own code could still ask Android's services for things as droidtop".
  - `net.sockets` caution (`PluginPermissions.kt:69-71`): "connects by itself, also to other apps on this device". **It does not mention the as-droidtop Binder authority.**

**Containment check / probe**
- `PluginCrashPolicy.containmentReport` (`PluginCrashPolicy.kt` ~110-150) loads the plugin and asks its process for `reachability` (network, droidtop's files, shared storage). It then prints the tier sentence, the uid, the process description (`PluginProcesses.describe`), the filter's report string and notes on hooks, assets and Python.
- It is reachable under Advanced on the plugin page (`AppSettingsCatalogs.kt` "Containment check").
- It reports **what the host configured plus a few live reachability probes**. The library returns only `0`/`-errno`, so **no effective-enforcement report comes from the library itself**.
- Text errors:
  - The OPEN-tier sentence is printed even when an open plugin actually runs **isolated** on API 30+ (net.sockets alone). It then wrongly says "shares droidtop's user id".
  - The CONTAINED sentence says "no network". That holds for the CONTAINED tier, but the isolated `net.sockets` and isolated-full-trust processes are also isolated processes with brokered networking, and they are labelled by their configured tier, not by the process.

**Wine (`runtime-windows/.../WineXSession.kt`, 448 lines)**: **not under the sandbox.**
- No `SBX_BROKER`, `LD_PRELOAD` or `WineGrants` code exists. The env setup at WineXSession.kt:118-164 and the launch at ~249 have no sandbox.
- A repository code search for `SBX_BROKER` finds only `plugin_broker.c`.
- SPEC.md:6289, 6824 ("Design only; nothing here is built") and SPEC.md:8959 ("No Wine sandbox exists yet") agree.
- The pinned a40cc14 **cannot** run it anyway. It has no `SBX_LOCK_CONTAIN`, `EXEC`, `listen`/`attach` or `libsbx_child.so`.
- **proot**: not under the sandbox either. SPEC.md:7018-7040 marks it as Phase 3, with "a stronger mechanism for proot" still open.

**docs/SPEC.md security claims (main 28d2bb5)**
- **12a (SPEC.md:20596-20800)**:
  - "every plugin, full access included, runs isolated under a UID of its own" (20632-20633).
  - "full access reaches the OS and Shizuku only through the sandbox's binder relay" (20633-20637). The relay is not built: library design.md:107-125 and 1662-1663 list it as planned.
  - The contained tier has "no network" (20665).
  - "For a contained plugin the permission model is a security boundary" (20670-20671).
  - "Its file broker keeps every file access going through droidtop's permission system" (20682-20684).
  - Full trust is "for compatibility and stability, not security" (20784-20790). This contradicts 20632.
- **5a/5b (Wine)**:
  - "what the broker lets it reach is exactly this list and nothing else" (6363-6365).
  - "Not in the list … refused by the broker … Deleting or rewriting any of it is refused" (6389-6392).
  - "Only what escapes the environment is refused" (6847-6848).
  - "Directory change notifications (`inotify`) are refused" (7009-7010). `SBX_LOCK_CONTAIN` actually includes `SBX_LOCK_INOTIFY`.
  - All of 5a/5b is still "Design only".
- **plugin-api.md**:
  - The 5.1 table (3675-3686).
  - The 5.6 audit table (4255-4269).
  - "No plugin runs under droidtop's UID, at any tier" (4311). This is a decision, not the current state.

### 2. Enginehost (`/home/user/enginehost` at 40913f9; pin v0.1.7)

**Two separate seccomp layers**:
- **Layer 1 (not the library)**: `enginehost_deny_internet()` in `app/src/main/cpp/runtime_sandbox.c:73-108`. It is a hand-written filter:
  - EACCES on `socket(AF_INET/AF_INET6)`, `io_uring_setup` and foreign-architecture calls; everything else is allowed.
  - Installed in both `:runtime` and `:runtime_isolated` (`EnginehostApplication.kt:37`, `RuntimeSandbox.apply`, `RuntimeSandbox.kt:54-65`).
  - **Best effort by decision**: if it fails, the game still runs (RuntimeSandbox.kt:45-48; engine-sandbox.md:55-63).
- **Layer "lockdown" (the library)**:
  - Confined side: `Java_dev_enginehost_RuntimeSandbox_lockdown0` (runtime_sandbox.c:143-186), calling `sbx_lockdown`.
  - **Flags**: `SBX_LOCK_WATCH`, always (runtime_sandbox.c:171). `SBX_LOCK_LEARN` when `debug.enginehost.learn` names the core or is `all` (line 173; RuntimeSandbox.kt:85). `SBX_LOCK_AUDIT` when `debug.enginehost.audit=1` (line 175), retried without it on `-EINVAL` (lines 178-183).
  - **No sockets of any kind** (no LOG_SOCKET/INET/NET_BROKERED), **no `sealed_fds`**, no EXEC.
  - **`own_opens`**: `/dev/hwbinder`, `/dev/kgsl-3d0`, `/dev/mali0`, `/dev/dri/renderD128` (RuntimeSandbox.kt:413).
  - **Tracing**: `sbx_trace`, `sbx_trace_fault`, `sbx_syscall_name` (runtime_sandbox.c:199-330).
  - Broker side: `serve0` (runtime_sandbox.c:409-451): `sbx_policy_new`, `sbx_policy_add` (**its return value is ignored**, line 439), `sbx_policy_set_decider`/`set_audit` and `sbx_broker_start`. The broker runs in the main process behind `SandboxBrokerProvider` (a ContentProvider call).

**Same-UID "allocate-then-clamp" (GPU and WebView cores, `:runtime`)**
- `EnginehostComponentFactory.kt:54-59` calls `RuntimeSandbox.lockdown(...)` when `locksDown(plugin)`, meaning the core declares `"lockdown": true`, `debug.enginehost.lockdown=1` is set, or a learning run is on (`RuntimeSandbox.kt:74`). The call is wrapped in `check(...)`, so it **fails closed** for those cores.
- **Policy** (`RuntimeSandbox.policy`, RuntimeSandbox.kt:284-353):
  - READ: the system trees, `/proc`, `/sys`, `/mnt/expand`, the APK and native-library folders, the bundles and the WebView provider code.
  - **RW: `/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`** and the GPU/ion/goldfish/bstpgaipc nodes (lines 308-316).
  - RW: `cacheDir`, `codeCacheDir`, the device-protected code cache, `app_webview*`, the controller-bindings folder, **two host `shared_prefs` files plus their `.bak` files** (lines 324-328), the CrashWatch note and HostEvents runtime files (334-335), and EngineSaveFolders.
  - The game folder is RO or RW, with `gameWrites` sub-folders RW, and the save folder is RW.
  - The **process keeps Enginehost's UID**: `MANAGE_EXTERNAL_STORAGE` through Binder-mediated APIs, `INTERNET` through Binder (DownloadManager, intents) and Binder in general. engine-sandbox.md:65-75 and 2291 say so.
- **Cores with neither `isolatable` nor `lockdown`** still run in `:runtime` with only the layer-1 network filter, after a per-launch red consent sheet (engine-sandbox.md:112-152; strings.xml:653-661).

**Isolated software-rendering cores (`:runtime_isolated`, `IsolatedRuntimeService`, manifest:217-219)**
- They use the isolated UID, plus the clamp when `locksDown`: `brokerForIsolated` serves `isolatedPolicy` (RuntimeSandbox.kt:362-374, READ system, `/proc`, `/sys` and the app's code; RW only null/zero/random/ashmem).
- The service calls `check(RuntimeSandbox.confineIsolated(...))` (`IsolatedRuntimeService.kt:247`), so it fails closed.
- Game and save files reach the process as descriptors over binder (`HostFileBroker`).

**Learning mode use**
- The `debug.enginehost.learn` system property is settable by adb/root only.
- The library's `SBX_LOCK_LEARN` is paired with a recording decider that returns 0 for every refused path (`learn_decide`, runtime_sandbox.c:388-391) and an audit that records `syscall` ops.
- Warning surfaces: a toast, a logcat line and a host event, "LEARNING MODE: … this run has NO sandbox" (RuntimeSandbox.kt:157-163).
- The profile is written to `Android/data/dev.enginehost/files/sandbox-learned/<id>-<digest>.json`, containing paths generalised as `$APP`/`$EXTERNAL`, etc. (engine-sandbox.md:2391-2404).
- `tools/sandbox-learn/propose.py` proposes a diff that a person reviews; nothing is auto-applied (2413-2419).
- The LaunchActivity plan event records " LEARNING, nothing refused" (LaunchActivity.kt:234).

**User-facing claims**
- `ProblemReport.kt:119`: "sandboxed (isolated)" / "sandboxed (locked down)" / "not sandboxed".
- `TrustBadges.kt:7-11, 22-27`: a lockdown core shows **no** Full-access badge ("'Sandboxed' is the absence of Full access"). A same-UID clamped core is therefore presented the same as an isolated one.
- `engine-sandbox.md:2261-2264`: "It counts as sandboxed".
- `engine-sandbox.md:2318-2320`: "A GPU core under the clamp is therefore **fully sandboxed, not a lesser case**."
- `engine-sandbox.md:3-4`: "engine code gets no internet access and no arbitrary file access".

### 3. droidtop-agent / Pythia (computer-side Python plugins)
- **Inaccessible** (no repository access).
- The only evidence is the library's own record of the agreement, `docs/design.md:1360-1363` and `1491-1513`:
  - The agent's Rust broker owns the permission checks. The library provides `sbx_spawn` (AppContainer/LPAC plus a job object), the broker and the decider.
  - Python's runtime is `SBX_READ|SBX_STATIC`.
  - Plugin files are opened with `sbx_open` after the agent decides; "open only"; no network in the container; the channel is a pipe in the handle list.
  - Tested: `tests/sbx_test_win.c` grant-once decider (lines 313-321).
- **No Linux agent confinement is recorded.** On Linux, `sbx_spawn` only starts a process (sbx.h:476-485). The agent would have to call `sbx_lockdown` itself (A-04).

### 4. Mesh Infinity
- **Inaccessible.** The review's section 3 C-05/C-06 is the only input.
- **No evidence it consumes the library today.** The README:25 consumer list names only droidtop and Enginehost.

## Conformance input

Legend: "lib" = the Fibrewall mechanism; "test" = a test in `/home/user/sandbox/tests` (function name in `tests/sbx_test.c` unless noted). The sbx_test attempts are in the `attempts[]` table, lines 296-332.

### C-01 droidtop isolated third-party plugins

| Requirement | Consumer today | Library mechanism | Test | Gap |
|---|---|---|---|---|
| Android isolated UID/SELinux domain | `isolatedProcess="true"`, `bindIsolatedService` per plugin from API 29, single-use slots below 29; refuses a non-isolated process (PluginSandboxService.kt:54) | **none** (host side). The library only offers `SBX_LOCK_PASSTHROUGH`/`UNBROKERED`, "for a process another wall already guards" (sbx.h:85-104) | none in library; droidtop `ContainedFilesRigTest` (rig) | No way to require or verify an isolated identity through the library (F-02/F-03). The BlueStacks rig runs with SELinux disabled (SPEC.md:20674), so the emulator does not validate SELinux (T-12). |
| Native plugin loading and Flutter | dex in memory; `.so` and Flutter engine at virtual paths through droidtop's guarded `dlopen` hooks (`sandbox_hooks.c`) plus library local files; Flutter assets from a memfd on API 30+ | `sbx_local_add`, `sbx_local_add_mode`, PASSTHROUGH claims | `passthrough_check` (local_add at sbx_test.c:2319-2359) | The `dlopen` hooks live outside the library. On API < 30, Flutter assets depend on the hooks reaching AssetManager (plugin-api.md 5.3). |
| Files and resources through controlled handles | descriptors from `:app`; droidtop private roots aliased to the plugin's own folder; quota through the decider; `RLIMIT_FSIZE` set by droidtop | `sbx_policy_add`, `sbx_policy_alias`, decider/`SBX_DECIDE`, `sbx_local_add` | main run (aliases, decider `granted.txt`/`revoked.txt`), `race`, `list_check`, `passthrough_check` | A delivered descriptor cannot be revoked (A-02). The quota is a lazy walk, not enforcement on held descriptors. |
| Binder/system services narrowly mediated | Contained: only the isolated UID's limits; Binder otherwise unmediated. Open: full droidtop Binder authority | `sealed_fds` exists but is **unused**; the binder relay `sbx_relay` is **planned, not built** (design.md:107-125, 1662) | `sealed_check`; `tests/android/gpu_probe.c` (sealing in a non-ART process) | **No library mechanism for ART processes** (A-01/A-08/A-16). Open process: P0. |
| Selective networking | `net.sockets`: API 30+ isolated with `SBX_LOCK_NET_BROKERED`, grants CONNECT\|LISTEN\|RESOLVE, no `SBX_NET_DECIDE`, decider ignores net (any endpoint, listen as droidtop). API < 30: open process with `SBX_LOCK_INET` (any endpoint, loopback included) | `SBX_LOCK_NET_BROKERED`, `sbx_policy_set_net`, `sbx_policy_add_system_socket`, `SBX_LOCK_INET` | `net_check(all grants)`, `net_check(0)`, `inet_check`; `socket(AF_INET*)` attempts | No endpoint, direction or loopback policy (A-07). The broker acts as droidtop's UID (A-06). `sendto` destinations are uncovered (sbx.h:629-630). No byte relay below API 30 (design.md:1659). |
| Explicit, revocable permissions | `PluginGrants`; a changed hole or `files.shared` grant retires or ends the process (PluginProcesses.retire/detach) | decider for future accesses only | main run (decider `revoked.txt` → EACCES) | No revocation of handed descriptors or sockets (A-02, F-05). Revocation means killing the worker; the library does not state this. |
| Per-plugin process and storage isolation | one process per plugin; single-use slots; per-plugin data folder; one broker per plugin | one `sbx_broker_start` policy per socket | **none** (no two-hostile-worker test, T-10) | Open-process plugins share droidtop's UID with each other and with full trust (A-27). |
| Native execution, scripting, services/jobs, RPC | Python from descriptors; jobs and RPC over `IPluginRuntime` binder; exec refused | default lockdown (exec refused); `SBX_LOCK_EXEC` unused | attempt "execve" | No controlled subprocess for plugins. |
| Optional elevated capability without general escape | holes (`net.sockets`). Full trust = droidtop UID, **unconfined** (manifest:35). `isolate_full` debug switch off by default | binder relay planned | none | Full access is a general escape today. SPEC 12a claims otherwise (see claims table). |
| Accurate isolated vs same-UID distinction | `PluginTier` plus Containment check text (PluginCrashPolicy.kt:120-131) | **none**: `sbx_lockdown` returns 0/errno only | none | Labels follow the configured tier, not the process (isolated net.sockets is shown as "shares droidtop's user id"). No effective-guarantee report (F-03). |
| *PluginOpenService* (audit separately) | droidtop UID, not isolated; every path brokered; `SBX_LOCK_INET` or `LOG_SOCKET`; dumpable; no sealed fds; no rlimit | `sbx_lockdown` (no PASSTHROUGH) + broker | `confined_attempts`, `inet_check` (same-UID single process) | Ambient Binder/UID authority (A-01) and droidtop's non-exported components below Android 11 (plugin-api.md:4265). INET reaches loopback services. LOG_SOCKET datagram connects to any reachable datagram socket. |
| **Acceptance**: one grant cannot reach unrelated host data, services, plugins or OS authority | Holds for the contained tier only as strongly as the isolated UID plus seccomp. Fails for the open tier (Binder) and for full trust | — | no end-to-end test | P0 for the open and full-trust tiers. |

### C-02 Enginehost engines and untrusted games

| Requirement | Consumer today | Library mechanism | Test | Gap |
|---|---|---|---|---|
| Native engines, scripting VMs, game content | bundles RO, game RO/RW, saves RW through the broker | `sbx_policy_add`, broker | main run, `race`, `confined_attempts` | Rule-add errors are ignored (runtime_sandbox.c:439). |
| EGL/GLES/Vulkan, driver compatibility | `own_opens` hwbinder/kgsl/mali/renderD128; GPU nodes RW in rules | `own_opens` (spare descriptors, 0.1.7) | `gpu_probe.c` (Android, non-ART); main run own_opens `/dev/zero` | No ioctl surface limit (A-15). GPU confinement is not a separate assurance class. |
| ART, Binder, audio, rendering | `/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder` granted RW; no sealing | none for ART Binder | none | Binder authority is unmediated (A-01/A-16). |
| Isolated software-rendering engines | `:runtime_isolated` plus clamp with `isolatedPolicy`; fails closed | `sbx_lockdown` in an isolated process | none in library | The library cannot verify the isolated UID. |
| Same-UID GPU engines, allocate-then-clamp | `:runtime` lockdown for `lockdown:true` cores; fails closed; flags `WATCH` | `sbx_lockdown`, `own_opens`, `SBX_LOCK_WATCH` | `watch_check`, `gpu_probe.c` | Residual Binder, UID, GPU and inherited-descriptor authority is not reported. Docs call it "fully sandboxed". |
| Per-game RO/RW directories | `game` RO with `gameWrites` RW, `save` RW, longest match | longest-rule matching | main run (read-only `game`, writable `save`) | Read/write is coarse: no create/delete/rename split (A-11). |
| Saves, caches, archives, runtime libraries | cache and code-cache RW; **two host `shared_prefs` files and host note files RW** | rules | — | The engine can rewrite host settings and host diagnostics (integrity of host data). |
| Multiple threads, native callbacks | TSYNC; SIGSYS kept open | `sbx_lockdown` (TSYNC, `-EDEADLK`) | `sigsys_check`, main `working()` threads | — |
| Controlled spawning | exec refused | `SBX_LOCK_EXEC` unused | attempt "execve" | — |
| Engine profiles through learning mode | `SBX_LOCK_LEARN` from a debug system property; profile JSON; human review | `SBX_LOCK_LEARN`, decider/audit `allowed_by` | `learn_check` | Learning profiles are written under `Android/data` with paths (A-20). The library itself does not gate LEARN to developer launch authority (A-05). |
| Network blocked | layer 1 (own filter, best effort) plus lockdown (no sockets) | default lockdown | `socket(...)` attempts | Layer 1 silently degrades on failure (RuntimeSandbox.kt:45-48). DNS and Binder channels remain (engine-sandbox.md:65-75). |
| Accurate user disclosure | badges, ProblemReport, consent sheet | none | none | "sandboxed (locked down)" equals "isolated" in UI (no badge). |
| **Acceptance**: effective permissions bounded and unsupported guarantees reported | path view bounded for lockdown cores; nothing reported | — | — | No report of residual authority (F-03). |

### C-03 Wine, PRoot, process trees

| Requirement | Consumer today | Library mechanism | Test | Gap |
|---|---|---|---|---|
| Supervise all descendants | **not used** (Wine and proot run unconfined; droidtop pin lacks the API) | `sbx_broker_listen`, `sbx_attach`, `libsbx_child.so`, `SBX_LOCK_EXEC`, `sbx-exec` | `listen_check`, `exec_helper_check`, `exec_check`, `program_tree_check` | The first image runs pre-constructor code, and static binaries ignore `LD_PRELOAD` (A-04). |
| Filesystem view and drive translation | not built (layers are design only, design.md:371) | rules, aliases, `SBX_CASE_INSENSITIVE`, `SBX_LOCK_PATHOPS` | `pathops_check`, main run (case-insensitive) | No COW layer (F-06). |
| Unix sockets, restricted local IPC | — | `SBX_LOCK_UNIX` + `sbx_policy_add_unix_name`; `SBX_LOCK_SOCKETS` (unrestricted, in CONTAIN) | `unix_check`, `contain_check` | CONTAIN allows every same-UID socket (A-03, A-08). |
| Executable loading, interpreter handoff | — | `SBX_LOCK_EXEC` (`#!` decided by the broker) | `exec_check`, `program_tree_check` | — |
| Signals in approved groups | — | `SBX_LOCK_SIGNAL_TREE` (broker-judged), `SBX_LOCK_SIGNALS` (any same-UID process, in CONTAIN) | `signal_tree_check`, `contain_check` | Process groups refused. CONTAIN can signal host processes. |
| Shared memory, descriptor inheritance | — | unrestricted | none | A-24. |
| Lifecycle, cleanup, accounting | — | `sbx_listener_close` only | none | No tree teardown or resource accounting (F-08, A-18). |
| **Acceptance**: every child confined from its first instruction | — | — | — | Not met (A-04). |

### C-04 droidtop-agent / Python (computer side)

| Requirement | Consumer today | Library mechanism | Test | Gap |
|---|---|---|---|---|
| Python and native extensions, `ctypes` constrained by the OS | (repo inaccessible) Windows: AppContainer/LPAC per design.md:1491-1513 | `sbx_spawn` (Windows), `SBX_STATIC` | `sbx_test_win.c` attempts 226-237 | Linux: no spawn-time confinement (A-04). |
| Controlled subprocess | refused on Windows (child-process policy plus job) | job, `CHILD_PROCESS_POLICY` | `sbx_test_win.c` "create a process", "breakaway" | No allowed-subprocess mode. |
| Explicit filesystem/network/host-service permissions | files: agent decides, then `sbx_open`; network: plugin API only | `sbx_open`, decider | `sbx_test_win.c` broker checks 271-360 | `SBX_STATIC` ACEs persist and are shared per container name (A-12). |
| Windows and Linux | Windows only, recorded | — | Windows CI | Linux agent path undefined. |
| Long-running, async | — | job object, memory limit | "commit more memory" | No CPU, handle or IO limits (A-18). |
| Cross-session separation | — | container name chosen by the host | none | The test reuses one `CONTAINER` for both runs (sbx_test_win.c:666-667). No cross-instance test (A-27). |
| LPAC required vs preferred | — | `less_privileged` → silent fallback to AppContainer (src/windows.c:939, 1022) | `confined_run(1, …)` only **prints** `less_privileged` (sbx_test_win.c:494), with no assertion | A-13. |

### C-05 / C-06 Mesh Infinity

| Requirement | Consumer today | Library mechanism | Test | Gap |
|---|---|---|---|---|
| Separate low-authority OS worker | unknown (inaccessible) | Android: host-side only; Windows: `sbx_spawn`; Linux: none (no UID/namespace separation) | Windows suite | Linux and Android identity separation must come from the host. |
| No ambient access to keys and vaults | unknown | path rules (Linux); AppContainer token (Windows) | `confined_attempts`; Windows attempts | Same-UID Linux leaves IPC, Binder and D-Bus open. |
| Resource limits and termination | unknown | Linux `sbx_spawn` rlimits; Windows job memory limit | `spawn_check` (RLIMIT_NOFILE), "commit more memory" | A-18. |
| Fail-closed startup, no silent downgrade | unknown | `sbx_lockdown` never half-installed; Windows LPAC silent fallback | — | A-13; no required/preferred API (F-02). |
| High-assurance effective-profile verification | unknown | none | none | F-03 / policy digest absent. |
| Media workers without WASM | unknown | same | — | — |

### C-07 General-purpose

Same as above. No consumer is known beyond the four. The README consumer list (README.md:25) names only droidtop and Enginehost.

