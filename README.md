<h1 align="center">sandbox</h1>

<p align="center">
  <b>A process sandbox for Linux and Android, in C.</b><br>
  No root, no user namespaces, no Landlock. It runs on the 4.19 kernels handhelds ship with.
</p>

<p align="center">
  <a href="https://github.com/bi0shacker001/sandbox/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/bi0shacker001/sandbox/ci.yml?branch=main&label=ci&style=flat-square"></a>
  <img alt="Linux and Android" src="https://img.shields.io/badge/Linux%20%C2%B7%20Android-26%2B-3ddc84?style=flat-square">
  <img alt="Language: C" src="https://img.shields.io/badge/language-C-555555?style=flat-square">
  <a href="LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/github/license/bi0shacker001/sandbox?style=flat-square"></a>
  <img alt="Status: early" src="https://img.shields.io/badge/status-early-d69e2e?style=flat-square">
</p>

<p align="center">
  <a href="#how-it-works">How it works</a> ·
  <a href="#what-it-blocks">What it blocks</a> ·
  <a href="#status">Status</a> ·
  <a href="#build">Build</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="#licence">Licence</a>
</p>

sandbox confines a process that runs untrusted code, such as a game engine plugin, so that it can only touch the files you allow. A trusted process answers each file request from a policy you write. It is used by [droidtop](https://github.com/Droidtop/droidtop) and [Enginehost](https://github.com/Droidtop/enginehost), each of which vendors it.

## How it works

```
  confined process                          trusted process
  ----------------                          ---------------
  sbx_lockdown(fd)                          sbx_broker_start(policy, fd)
  seccomp-bpf on every thread               policy: path rules, aliases,
        |                                           your decider, audit
        |  open("/game/data.bin")                   |
        |  traps, goes over a Unix socket  ---->    checks the rules, opens the
        |                                           file itself
        |  <---- file descriptor (SCM_RIGHTS)
```

After lockdown, no system call can name a file by itself. Each one traps and is forwarded to the broker. Calls on descriptors the process already holds are untouched, so a GPU driver keeps its device.

| Piece | What it does |
|---|---|
| **Lockdown** `sbx_lockdown` | Called first in the confined process. Installs the filter on every thread. |
| **Broker** `sbx_broker_*` | Runs in a trusted process and answers each request from a policy. |
| **Path rules** | Read, or read and write, with optional case-insensitive lookup. |
| **Aliases** | A folder handed over under a fixed name. |
| **Decider and audit** | Your callbacks: grant or refuse each access, and log it. |

The broker resolves paths itself and makes each call relative to a parent directory it has opened and checked, so a symlink swapped in mid-call cannot lead outside the rules. The design follows Chromium's Linux syscall broker and Android's minijail policies. The reasoning is in [docs/design.md](docs/design.md).

## What it blocks

Refused outright: sockets (a process that needs the network can be given inet sockets, and only those, with `SBX_LOCK_INET`, or have the broker make, connect, bind, listen and accept them under its own identity with `SBX_LOCK_NET_BROKERED`, for an Android isolated process that may create none), `execve`, `ptrace`, namespaces, mounts, `io_uring`, `bpf`, signals to other processes and foreign system-call ABIs.

An end-to-end test runs escape attempts first without the sandbox, as a control, and then confined, and checks that each one fails. It also races a symlink against the broker and checks that a file outside the rules is never touched.

## Status

Early. Built today:

- the lockdown and the broker;
- the end-to-end and escape-attempt test, run in CI on Linux and on the Android emulator (API 28 and 34);
- on Windows, `sbx_spawn` into an AppContainer and job object with an explicit broker (`sbx_open`), and its escape suite in CI ([design](docs/design.md#windows-design-2026-10-23-droidtoptracker606)). macOS is later;
- for a tree of processes such as Wine: `sbx_broker_listen` and `libsbx_child.so`, exec through the broker (`SBX_LOCK_EXEC` and the static `sbx-exec` loader), and the `SBX_LOCK_CONTAIN` preset, which restricts the file system view only.

Not built yet:

- minijail policy files, for per-process allowlists;
- the `native` launcher, a binder-less process that keeps the GPU;
- the Android AAR with its Kotlin API.

### Releases

- **v0.1.7** (2026-10-24): each open of an own-opened device after lockdown takes one of three spare descriptors opened with it, an open file of its own; binder maps each open file once, and duplicates collided with EBUSY ([Droidtop/tracker#550](https://github.com/Droidtop/tracker/issues/550)).

- **v0.1.6** (2026-10-24): `process_vm_readv` of the process's own memory is allowed. ART's SafeCopy reads so before it accepts a SIGSEGV as an implicit null check; refused, every null receiver in Java killed a locked-down process ([Droidtop/tracker#550](https://github.com/Droidtop/tracker/issues/550)). Any other process's memory stays refused.

- **v0.1.5** (2026-10-24): `sbx_trace_fault` reaches the faulting thread's callers where the unwinder stops at the signal chain, by walking its frame records (arm64 x29, x86_64 rbp) and the leaf's link ([Droidtop/tracker#550](https://github.com/Droidtop/tracker/issues/550)).

- **v0.1.4** (2026-10-24): 64-bit only, the owner's rule ([Droidtop/tracker#646](https://github.com/Droidtop/tracker/issues/646)):
  - the library builds for x86_64 and arm64 (Linux and Android arm64-v8a, x86_64). On any other architecture `lockdown.c` stops at an `#error`; the ENOSYS stubs that let 32-bit hosts link are gone, and CI no longer builds armeabi-v7a or x86.

- **v0.1.3** (2026-10-24), for cores that die of a segmentation fault under Enginehost's lockdown ([Droidtop/tracker#550](https://github.com/Droidtop/tracker/issues/550)):
  - `sbx_trace_fault`: a fatal signal noted in the trace ring with its address, the faulting place and an unwind of its callers, each named by library and symbol; the ring's version is 2 ([docs/design.md](docs/design.md), "When a trap kills").

- **v0.1.2** (2026-10-23), for Ren'Py under Enginehost's lockdown ([Droidtop/tracker#550](https://github.com/Droidtop/tracker/issues/550)):
  - `SBX_LOCK_WATCH`: inotify marks decided and added by the broker, scoped to readable paths and narrowed to a folder's own events where it holds a name the process may not read ([docs/design.md](docs/design.md), "SBX_LOCK_WATCH").

- **v0.1.1** (2026-10-23), a program tree such as Wine, end to end ([Droidtop/tracker#470](https://github.com/Droidtop/tracker/issues/470)):
  - `#!` scripts run under `SBX_LOCK_EXEC`, as the kernel runs them, with the interpreter decided by the broker;
  - the first process of a tree attaches with `SBX_LOCK_CONTAIN` from the environment: `SBX_EXEC_HELPER` and `SBX_CHILD_LIBRARY` name `sbx-exec` and `libsbx_child.so`;
  - a test of the system shell running `cat`, `ls`, a nested shell, a pipe and a `#!` script, each image confined, also in learning mode and attached from the environment, on Linux, arm64 and the emulators;
  - on Windows, a test that a decider can grant one open and refuse the next with `-EACCES`, and the C runtime left to the consumer (`SBX_MSVC_STATIC_RUNTIME`);
  - a host guide for running a program tree, in [docs/design.md](docs/design.md).

- **v0.1.0** (2026-10-23), the library half of [Droidtop/tracker#584](https://github.com/Droidtop/tracker/issues/584) piece 0:
  - `SBX_LOCK_LEARN`, with learning records that name the flag that would allow each call (`allowed_by`);
  - `SBX_LOCK_INET`, `SBX_LOCK_UNIX`, `SBX_LOCK_PATHOPS`, `SBX_LOCK_INOTIFY`, `SBX_LOCK_SOCKETS`, `SBX_LOCK_SIGNALS`, `SBX_LOCK_SIGNAL_TREE`, `SBX_LOCK_EXEC` and `SBX_LOCK_AUDIT`, and the `SBX_LOCK_CONTAIN` preset;
  - `sbx_broker_listen`, `sbx_attach` and `libsbx_child.so`, and `sbx-exec` for arm64-v8a and x86_64;
  - `sbx_trace`;
  - the Windows backend.

  A host using `SBX_LOCK_EXEC`, or `SBX_LOCK_CONTAIN`, which includes it, ships `sbx-exec` and `libsbx_child.so` where they can be executed (on Android, the app's native-library folder). It passes their absolute paths in `sbx_lockdown_options`.

## Build

```sh
cmake -S . -B build && cmake --build build
TMPDIR=/tmp ./build/sbx_test
```

On Windows: `cmake -S . -B build && cmake --build build --config Release && build\Release\sbx_test_win.exe`.

For Android, add the NDK toolchain file: `-DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26`.

Consumers vendor this repository at a pinned commit and add it with `add_subdirectory`. The API is in [include/sbx.h](include/sbx.h).

## FAQ

**Why not Landlock or user namespaces?**
Landlock needs kernel 5.13 or newer, is off in GKI kernels and is not in Android's app seccomp allowlist. Unprivileged user namespaces are usually compiled out, and SELinux forbids an app any capability in one. seccomp-bpf is available, so that is what this uses.

**Is it a full security boundary?**
It is a file and system-call wall. The reasoning, and what it does not cover, is in the "What it does not stop" section of [docs/design.md](docs/design.md).

**Does it need root?**
No.

## Licence

GPL-3.0-or-later, see [LICENSE](LICENSE). Vendored third-party code, when added, keeps its own licence in its own directory.
