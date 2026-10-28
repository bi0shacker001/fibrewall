## E. Adversarial test plan (T-01..T-14)

Each row maps a review test area to its current coverage and what is still
needed. Detailed reproduction steps live beside each finding in the A
register (deliverable A); they are not repeated here. Every test has an
unconfined control, so a refusal proves enforcement rather than breakage.

| T | Area | Covered today | To add |
| --- | --- | --- | --- |
| T-01 | Filesystem escape | symlink, `..`, `/proc` forms, dirfd, the symlink-swap race, case folding (`tests/sbx_test.c` attack table, `race`) | Windows nested sub-rule bypass (A-10); case-insensitive filesystems; pre-existing hard links; ancestor renames; reparse kinds beyond junctions |
| T-02 | Credential / identity | token and UID gate at the listener; signal-tree membership | same-UID authority (A-01) once an identity report exists; cross-worker confused deputy (A-22) |
| T-03 | IPC | Unix sockets, signals, one Windows named event | sealed-descriptor re-import (A-24); SysV and `mq`; `TIOCSTI`; shared memory; a named pipe across two same-container instances (A-27) |
| T-04 | Network | inet family and type gating; brokered connect/listen/resolve; netlink refusal | the marker bypass (A-06); per-endpoint and per-protocol policy (A-07); datagram `sendto` destinations |
| T-05 | Execution | exec chain, `#!` scripts, interpreters, fail-closed adoption | writable-executable memory / W^X (A-25); static-binary exec (A-17) |
| T-06 | Resource denial | Windows memory limit; `spawn` sets rlimits | enforcement that the limits bite; CPU, wall-clock, fd and broker-request budgets (A-18) |
| T-07 | Broker protocol | length and framing checks on both backends | a fuzz harness on `serve_one` and the Windows parser (A-09); the answer-socket and FIFO cases |
| T-08 | Concurrent policy change | the filesystem race only | policy mutation while serving, under TSan (A-23) |
| T-09 | Kernel / device | `gpu_probe` on the emulator (non-gating, swiftshader) | an `ioctl`-surface assertion per own-opened device (A-15); a residual-syscall drift guard (A-28) |
| T-10 | Cross-consumer isolation | none | two mutually hostile instances on each backend (A-27) |
| T-11 | Failure injection | the SIGSYS and EDEADLK paths | broker death and disconnect: fail-closed in strict mode (A-21) |
| T-12 | Platform reality | Windows LPAC and plain AppContainer both run | a real device with enforcing SELinux; a kernel other than the emulator's; Windows ARM64 |
| T-13 | Compatibility regression | the program-tree test uses the test binary | a real Wine or Box64 tree; real Enginehost cores; the agent's Python |
| T-14 | Assurance-report correctness | none (no report exists) | request an unavailable guarantee and confirm the report names it and strict mode refuses to launch (depends on D) |

The proposed test files, written as expected-result cases with their
controls, go on `ci/fibrewall-phase0`. The ones that fail today
(A-06, A-10, A-24) are committed with their expected post-fix result and
are what the Phase 2 fixes will turn green, so each fix has its regression
test waiting.

**CI gaps to close, independent of any one finding:** a thread-sanitizer
job; a fuzz job; a real-device or at least enforcing-SELinux Android run;
execution of the arm64 Android build (only x86_64 runs today); and release
gating on a strict profile, not on the emulator suite alone.

## F. Implementation plan (dependency-ordered)

No source lands on `main` without the owner's approval. The order follows
the review's phases; `#651` (bounded zones) is F-01's consumer-facing
layer, and the `#606` Windows items and macOS sit in Phase 3 and Phase 5.

**Phase 1 — the contract (the highest-value change, enables everything
else).** Files: `include/sbx_contract.h` (proposed, on the branch),
`src/lockdown.c`, `src/windows.c`, a new `src/report.c`.
- the guarantee, residual, requirement and report types (D);
- `sbx_negotiate` (a dry run), and the `*_checked` launch calls;
- the effective-enforcement report and the policy digest;
- strict launch fails before any untrusted code when a required guarantee
  is missing.
- Release gate: a consumer can require a guarantee and read back what was
  installed (closes A-26, and makes A-01/A-03/A-05/A-13 reportable).

**Phase 2 — harden the current backends.** Dependency order within it:
1. the marker-to-trampoline binding (A-06) and the answer-socket and
   reply-version checks (A-09, A-21) — small, high value;
2. the descriptor inventory and `ioctl`/`TIOCSTI` handling (A-02, A-24),
   and sealing that survives re-import, or its removal from the docs;
3. `sbx_spawn_confined` (A-04);
4. the Windows container lifecycle: per-instance names, `sbx_container_remove`,
   rollback (A-12), LPAC-required (A-13), and the mitigation set (A-14);
5. broker budgets and timeouts (A-18, A-19), and policy-mutation locking
   (A-23);
6. the fail-closed broker-death contract (A-21).
- Each ships with the regression test that currently fails.
- Release gate: the adversarial suite (E) passes, the fuzz and TSan jobs
  are green, and no finding above P2 is open against a claimed guarantee.

**Phase 3 — finish the consumers' needs.** The Binder relay (A-16, F-07);
granular filesystem rights (A-11); structured network policy (A-07,
#651's `net.local`/`net.internet`); the W^X flag (A-25); the `#606`
Windows items (real Python in CI, the remaining path operations); the
bounded-zones layer (#651) on top of the policy model.

**Phase 4 — the portable framework.** The policy schema (F-01), dynamic
grants and revocation (F-05), the overlay filesystem (F-06), the service
broker (F-07), developer tooling (F-11) and language bindings (F-10).

**Phase 5 — more platforms.** macOS first (G), then iOS and BSD by
consumer demand. No platform is "supported" until its own escape and
compatibility suites pass.

## I. Release readiness (at v0.1.7)

**Safe to run now, as built:**
- **Enginehost locked-down cores** (same-UID, file and syscall confinement),
  *as long as* the UI stops calling them "sandboxed" without naming the
  class: they keep the app's Binder and GPU authority (A-01, A-15, A-16).
  That is a documentation fix (H), not a code change.
- **droidtop isolated plugins** whose isolation comes from the Android
  isolated process, with the library adding file and syscall confinement
  on top. The strength is the isolated UID, not the library (A-01).
- **Windows file brokerage** for a computer-side agent, in LPAC, *if* the
  agent checks `less_privileged` (A-13) and uses a distinct container name
  per workload (A-12). Both are caller obligations to document now.

**Needs safeguards before it is relied on:**
- **Brokered networking** with per-destination intent: the marker bypass
  (A-06) must be fixed first, or the host must grant all-or-nothing (as
  droidtop does today) and not believe the decider is a boundary.
- **`sealed_fds`:** do not advertise or rely on it until A-24 is fixed. No
  shipped consumer uses it today, so this is a doc change now and a code
  fix before first use.
- **Process trees from an attached first process** (Wine): the first image
  is not confined before its loader runs, and a static first program is
  not confined at all (A-04). Start such a tree only from a trusted
  launcher, and treat `sbx_spawn_confined` as the prerequisite.
- **Learning mode:** never in a shipped profile (A-05).

**Must not launch under a claimed strict profile until built:**
- anything requiring a **separate OS identity on Linux or same-UID
  Android** (Mesh Infinity's strict worker): the library provides none
  (A-01).
- anything requiring **per-destination network, IPC or resource limits**
  as enforced guarantees: these are incomplete (A-07, A-08, A-18).
- anything requiring a **verified effective profile**: no report exists
  yet (A-26). This is the gate the owner's review calls the highest-value
  deliverable, and it is the reason a strict consumer cannot be released on
  v0.1.7 at all — not because a specific wall is weak, but because the
  library cannot yet prove which walls are up.

**Pins:** Enginehost is on v0.1.7. droidtop is on `a40cc14`, before v0.1.0
and seven tags behind, and its SPEC names the wrong pin (H). A pin update
is a droidtop-lane task, noted here because the review asks for consumer
accuracy.
