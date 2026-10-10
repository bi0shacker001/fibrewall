# sandbox

A process sandbox library for Linux and Android, in C. It needs no root,
no user namespaces and no Landlock, so it works on the kernels Android
handhelds ship with (4.19 and up).

Two pieces:

- **The lockdown** (`sbx_lockdown`). The process that will run untrusted
  code calls this first. It installs a seccomp-bpf filter on every thread.
  After that, no system call can name a file by itself. Each such call
  traps, and is forwarded over a Unix socket to the broker. Sockets,
  `execve`, `ptrace`, namespaces, mounts, `io_uring`, `bpf`, signals to
  other processes and foreign system-call ABIs are refused outright. Calls
  on descriptors the process already holds are untouched, so a GPU driver
  keeps its device.
- **The broker** (`sbx_broker_*`). It runs in a trusted process and
  answers each request from a policy:
  - path rules (read, or read-write), with optional case-insensitive
    lookup;
  - aliases (a folder handed over under a fixed name);
  - the host's own **decider**, which can grant or refuse each access, and
    an **audit** callback.

  The broker resolves paths itself and makes every call relative to a
  parent directory it has opened and checked, so a symlink swapped in
  mid-call cannot lead outside the rules. Files go back as descriptors
  (SCM_RIGHTS).

The design follows Chromium's Linux syscall broker and Android's minijail
policies. The reasoning is in [docs/design.md](docs/design.md).

## Status

Early. Built today:

- the lockdown and broker;
- an end-to-end and escape-attempt test, run in CI on Linux and on the
  Android emulator (API 28 and 34).

Not built yet:

- minijail policy files, for per-process allowlists;
- the `native` launcher (a binder-less process that keeps the GPU);
- the Android AAR with its Kotlin API.

## Building

```sh
cmake -S . -B build && cmake --build build
TMPDIR=/tmp ./build/sbx_test
```

For Android, use the NDK toolchain file
(`-DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26`).
Consumers vendor this repository at a pinned commit and add it with
`add_subdirectory`.

## Licence

GPL-3.0-or-later (see LICENSE). Vendored third-party code, when added,
keeps its own licence in its own directory.
