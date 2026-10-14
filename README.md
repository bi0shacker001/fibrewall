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

The broker resolves paths itself and makes each call relative to a parent directory it has opened and checked, so a symlink swapped in mid-call cannot lead outside the rules. The design follows Chromium's Linux syscall broker and Android's minijail policies. The reasoning is in the "What it does not stop" section of [docs/design.md](docs/design.md).

## What it blocks

Refused outright: sockets, `execve`, `ptrace`, namespaces, mounts, `io_uring`, `bpf`, signals to other processes and foreign system-call ABIs.

An end-to-end test runs escape attempts first without the sandbox, as a control, and then confined, and checks that each one fails. It also races a symlink against the broker and checks that a file outside the rules is never touched.

## Status

Early. Built today:

- the lockdown and the broker;
- the end-to-end and escape-attempt test, run in CI on Linux and on the Android emulator (API 28 and 34).

Not built yet:

- minijail policy files, for per-process allowlists;
- the `native` launcher, a binder-less process that keeps the GPU;
- the Android AAR with its Kotlin API.

## Build

```sh
cmake -S . -B build && cmake --build build
TMPDIR=/tmp ./build/sbx_test
```

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
