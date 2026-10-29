# Fibrewall as a universal sandbox library

Status: design, the end goal (owner, 2026-10-29). We implement toward it
incrementally; nothing here is built until its own change lands with the
owner's approval. The working name stays `sbx` until the owner says to
rename. This sits above `docs/design.md` (what is built), `docs/contract.md`
(the guarantees contract), and `docs/zones.md` (#651, bounded zones).

## 0. What the owner asked for

One library usable for **container isolation, a firejail-style confiner,
genuine (and adaptive) network filtering, and interactive malware
monitoring and testing** — across as many operating systems, security
levels and profiles as possible. "Anything a sandbox could need, for
anything a sandbox could be useful for."

Four decisions set the shape (owner, 2026-10-29):

1. **The whole vision is the destination; we implement out as we go.** This
   document is the north star, not a single deliverable.
2. **Network filtering is genuine, including adaptive filtering** — not
   just "which hosts may be reached", but L7 inspection and rules that
   change with what they observe.
3. **Monitoring is interactive, driven programmatically — rules-based, not
   an AI.** The host supplies deterministic rules that decide in real time
   and may adapt on accumulated state.
4. **This is a library.** We build the mechanism and a programmatic API so
   other tools can be a container runtime, a firejail, or an analysis
   harness *using only us*. We do not build those tools, their CLIs,
   daemons, or any UI.

## 1. The spine that makes "universal" tractable

Three invariants already in the library carry the whole vision:

- **The broker is the trust boundary, not the in-process filter.** Policy
  is declarative data; each OS backend enforces as much of it as that OS
  allows. A weak backend is still safe — it just enforces less.
- **The guarantees contract (`docs/contract.md`, A-26).** A consumer states
  the guarantees it *requires*, *prefers* and *forbids*; `sbx_negotiate`
  reports what a given policy and backend would actually enforce, what they
  rule out, and what authority would remain. This is how one library spans
  many "security levels" honestly: it runs on what the platform offers and
  **tells the truth about the residual** instead of pretending.
- **The host decides and audits.** Today through `sbx_policy_set_decider`
  and `sbx_policy_set_audit`. Generalising that one seam into an adaptive
  rules engine (§4) is the single most important new idea here, because
  decisions 2 and 3 are both *that engine* pointed at different event
  streams.

So "universal" is not one enormous sandbox. It is:

> **one declarative policy × a rules engine the host drives × many backends,
> each reporting honestly what it enforces.**

Everything below fills in that sentence.

## 2. The model: three orthogonal axes

**A. Capability classes** — the vocabulary of what a sandbox controls. The
library speaks these; a consumer never names a mechanism.

| Class | Built today | Universal needs |
| --- | --- | --- |
| Filesystem | path broker, aliases, case-fold, passthrough | mount namespace, overlay (copy-up + ephemeral), Landlock, `unveil`, bind-mount views |
| Process / exec | exec brokering, `sbx_spawn_confined` (A-04), `#!`/interpreter chains | W^X / code-loading policy (A-25), static-binary handling (A-17) |
| Network | all-or-nothing brokered connect/bind/listen/resolve | per-destination/port/protocol, DNS policy, L3/L4 firewall, **L7 filtering proxy**, **adaptive rules** (§5) |
| IPC | Unix sockets, signals (+ signal tree) | SysV, POSIX mq, shared memory class (A-24 ingress), abstract sockets, a D-Bus-style proxy, full isolation via a net/ipc namespace |
| Devices / ioctl | own-opens, `TIOCSTI`/`TIOCLINUX` refusal | per-device `ioctl` allowlists, a device-node policy |
| Resources | rlimits, Windows job object | cgroups v2 (cpu, memory, io, pids, freeze), broker-request budgets (A-18/A-19) |
| Identity / isolation | Android isolated UID | user namespace (desktop Linux), uid/gid maps, a separate-identity guarantee (A-01) |
| Kernel-surface reduction | seccomp allow/deny profiles | per-profile tables (§6), architecture pinning (built) |
| Observation / audit | `LEARN`, audit sink, trace ring | an **interactive, rules-based observe mode** (§5), structured behavioural reports |
| Ephemerality / teardown | — | disposable overlay + snapshot + diff + discard; kill-the-tree; the "what did it do" artifact |

**B. Backends** — each OS realises each class with its real mechanism
(§3). The class is portable; the mechanism is not.

**C. Profiles / levels** — a profile is a table over the classes
(allow / prompt / deny) plus the guarantees it *requires*, at a chosen
strictness. This is `docs/zones.md` (#651) generalised from Enginehost to
every consumer. Profiles ship with the library, are reviewed, and never
come from the sandboxed program.

The library's job at runtime: take one policy + profile, compose the
strongest mechanisms each backend offers, install them, and hand back a
report (the contract) of what is actually enforced and what leaks.

## 3. Backend matrix (OS × class)

Mechanisms per OS. "enforced" = a guarantee the contract may promise;
"best-effort" = installed but not promised; "—" = not available, the
contract says so. Kernel- and OS-version facts are marked *verify on
target*, as `docs/design.md` already does for the device kernels.

| Class | Linux desktop | Android | Windows | macOS | FreeBSD | OpenBSD |
| --- | --- | --- | --- | --- | --- | --- |
| Filesystem | mount ns + overlay + Landlock + broker | broker + SELinux `isolated_app` | broker + AppContainer ACLs | App Sandbox / Seatbelt + broker | Capsicum + broker | `unveil` + broker |
| Process/exec | seccomp + `no_new_privs` + exec broker | seccomp + exec broker | job object + AppContainer | Seatbelt + `posix_spawn` attrs | Capsicum + seccomp-bpf-like via Capsicum | `pledge` |
| Network | net ns + nftables/eBPF + L7 proxy | broker only (no ns) | WFP + broker | network extension / proxy + broker | pf + broker | pf + broker |
| IPC | ipc/net/user ns | broker + isolated UID | AppContainer + broker | Seatbelt + broker | Capsicum | `pledge` classes |
| Devices/ioctl | seccomp `ioctl` + device cgroup | seccomp `ioctl` | handle policy | Seatbelt | Capsicum | — |
| Resources | cgroups v2 | rlimits (+ app limits) | job object | `taskpolicy` / rlimits | rctl / rlimits | `login.conf` / rlimits |
| Identity | user ns (uid/gid map) | isolated UID (kernel) | restricted token / AppContainer SID | per-app container | jail (needs privilege) | — |
| Kernel surface | seccomp-bpf | seccomp-bpf | — (syscall filtering is weak) | — | Capsicum caps | `pledge` |
| Observation | seccomp-unotify / ptrace / eBPF | seccomp trap (our broker) | ETW + minifilter | Endpoint Security framework | DTrace / ptrace | — |
| Teardown | overlay discard + kill cgroup | kill process | kill job | kill + discard | kill jail | kill |

Reading of it: **desktop Linux is where container isolation and the
firejail persona live** (namespaces + cgroups + overlay + Landlock), exactly
the set the review found *absent on Android*. Android stays the
isolated-UID + seccomp + broker backend it is. Windows gains WFP (network)
and ETW/minifilter (observation) on top of today's AppContainer + job +
broker. macOS and the BSDs are later backends with their own idioms.

## 4. The adaptive rules engine (the heart of decisions 2 and 3)

Today one callback, `sbx_decide_fn`, sees path and socket accesses and
returns an errno or `SBX_KEEP`. Generalise it into a **deterministic,
stateful, event-driven rules engine** the host owns. This is not AI and not
a scripting language the sandboxed code can reach: it is host C (or a host
binding) the library calls back.

- **Events are typed and cover every class:** `open`/`stat`/path ops, exec,
  `connect`/`bind`/`listen`/`accept`, DNS resolve, an L7 network chunk
  (§5), `ioctl`, IPC, signal, a resource threshold, a child spawn, a
  syscall seen in observe mode.
- **A verdict is richer than allow/deny:** `allow`, `deny(errno)`,
  `prompt` (defer to the profile's prompt policy, `docs/zones.md`),
  `modify` (rewrite an argument — a redirected path, a clamped resource, a
  substituted address), `substitute` (answer without the kernel — a canned
  reply, for analysis), and `log` (record and fall through). Every verdict
  is audited.
- **Rules carry host state, so they adapt.** The engine threads a
  per-sandbox context through every callback; a rule may count, timestamp,
  remember prior events and change its answer — "allow the first N
  connections then throttle", "deny once this process has both read the
  address book and opened a socket", "tighten after the setup phase ends".
  That is the "adaptive" in adaptive filtering and the "rules-based
  adaptability" in monitoring, in one mechanism.
- **Determinism and safety:** callbacks run in the broker (the trusted
  side), never in the sandboxed process; they must be prompt (a slow rule
  stalls one request, never the broker — budgets, A-19); a throwing or
  absent rule fails closed. The engine is the same on every backend; only
  which event types a backend can raise differs, and the contract says
  which.

Everything in §5 and §6 is this engine applied.

## 5. Network filtering (genuine, adaptive)

Layered, weakest-assumption first. A consumer composes the layers a profile
asks for; the contract reports which are actually in force.

1. **L3/L4 confinement (the floor).** The broker grants or refuses
   `connect`/`bind`/`listen` per destination, port and protocol, and
   resolves names itself (DNS policy lives here). On a backend where the
   sandboxed code could route around the broker (it holds a socket), a
   **network namespace + nftables/eBPF egress filter** (Linux), **WFP**
   (Windows) or **pf** (BSD) makes the restriction real at the kernel, not
   advisory. This closes A-06/A-07.
2. **L7 inspection (the teeth).** The sandbox's allowed flows are routed
   through a **filtering proxy the library provides as a mechanism** (a
   transparent/SOCKS endpoint the net-namespace points at). It exposes each
   connection and, for inspectable protocols, each message to the rules
   engine: TLS SNI / ALPN, HTTP request line and headers, DNS questions.
   Rules return allow/deny/modify per §4 — block by SNI, rewrite a header,
   redirect, rate-limit.
3. **Adaptive control.** Because the proxy and the L3/L4 grants both run
   through the one stateful rules engine, a rule can change the policy as
   it observes: escalate from log to block after a pattern, open a
   destination only after a prior handshake, throttle on volume, quarantine
   a flow. The adaptivity is the host's rules plus the engine's threaded
   state, nothing hidden.

Honest limits: the proxy can inspect only what it can see; end-to-end
encryption without a trusted-proxy CA is opaque above L4 (SNI and cert
still visible). We do not MITM silently; a consumer that wants content
inspection installs its own trust anchor in the sandbox and owns that
choice. The contract says "L4 only" vs "L7 available" per flow.

## 6. Monitoring and analysis (interactive, programmatic, rules-based)

An **observe mode** distinct from enforce: the point is to watch and decide
by rule, not to minimise the syscall surface.

- **Full syscall visibility without killing:** seccomp user-notification
  (`unotify`, Linux 5.0+; *verify on target*) or `ptrace`, surfacing each
  intercepted call to the rules engine, which may allow, deny, modify the
  arguments, or substitute a result — deterministically, by host rule.
  (The RP5's 4.19 kernel has no `unotify`; there the existing SIGSYS→broker
  path is the observer, so observe mode degrades, and the contract says
  so.) Windows uses ETW + a minifilter; macOS the Endpoint Security
  framework.
- **Filesystem effect:** run on an **ephemeral overlay**; snapshot before,
  diff after — the exact set of files created, changed and deleted.
- **Network effect:** every connection, DNS question and (where L7 is on)
  message recorded; optional pcap.
- **Process effect:** the full exec/fork tree with arguments and
  environment, timed.
- **The artifact:** a structured, machine-readable behavioural report the
  consumer reads — *the library produces the data; the consumer decides
  what the verdict means.* No scoring or classification lives here.
- **Teardown:** discard the overlay, kill the tree, release the cgroup —
  one call, so a harness can run a sample and reset.

Anti-evasion is explicitly **best-effort**, never a guarantee the contract
promises: a sample can detect timing, the proxy, or the absence of a real
environment. We state this rather than imply a tamperproof analysis box.

## 7. The library boundary (decision 4)

Fibrewall is **mechanism + a programmatic API**. It ships:

- the capability-class policy model and the guarantees contract;
- the backends (§3), selected and probed at runtime (`sbx_probe`);
- the adaptive rules engine (§4): event types, verdicts, the threaded
  host-state context, the audit sink;
- the network layers (§5) as callable mechanisms (grant table, namespace +
  firewall programmer, the proxy endpoint);
- the observe-mode mechanisms (§6): the interception source, the overlay
  snapshot/diff, the capture, the report structure, teardown;
- a stable C ABI (GPL-3.0-or-later) and, later, bindings (Rust first).

Fibrewall does **not** ship: a CLI, a daemon, a config-file format, a UI, or
any persona. A container runtime, a firejail-style launcher, a network
filter appliance and a malware-analysis harness are all things a consumer
builds *on this library* — the same way Enginehost and droidtop are
consumers today. The test of every API addition: can an outside tool drive
it with no UI assumptions and no code of ours beyond the library?

## 8. Roadmap (extends the review's F; each phase lands incrementally)

- **Phase U0 — the model.** Generalise the policy into capability-class
  *intents* and extend the contract's guarantee/residual bits to every
  class. Generalise `sbx_decide_fn` into the rules engine's event/verdict
  API (§4), with today's path/net deciders as its first event types. No new
  enforcement; this is the spine everything else needs, and it keeps the
  C ABI additive.
- **Phase U1 — Linux container/firejail backend.** user + mount + pid +
  ipc + uts + cgroup namespaces, `pivot_root` + overlayfs, cgroups v2,
  Landlock, capability drop — behind the same policy. Unlocks container
  isolation and the firejail persona at once. (Desktop Linux; Android
  unchanged.)
- **Phase U2 — network filtering.** Per-destination/port/protocol grants
  and DNS policy; the net-namespace + nftables/eBPF floor; the L7 proxy
  endpoint; adaptive rules over both.
- **Phase U3 — observe/analysis mode.** `unotify`/ptrace interception into
  the rules engine; ephemeral overlay snapshot/diff; network capture; the
  behavioural report; teardown.
- **Phase U4 — macOS and BSD backends.** Seatbelt + Endpoint Security;
  Capsicum + `pf`; `pledge`/`unveil`.
- **Phase U5 — bindings.** Rust and others over the stable ABI.

Ordering is a default, not a commitment; the owner steers it per the "we
implement out as we go" decision.

## 9. Non-goals and honest limits

- **Not a VM or hypervisor.** gVisor and Firecracker reimplement a kernel;
  we do not. For a workload that needs that isolation strength, the library
  offers a *delegation hook* — a profile may require "run inside a VM the
  consumer provides" — rather than a home-grown kernel.
- **Anti-evasion is best-effort** (§6).
- **iOS can only be a consumer** of its own App Sandbox; it cannot host
  custom profiles, so it is not a backend.
- **Android keeps its ceiling:** isolated UID + seccomp + broker, no
  namespaces (`CONFIG_USER_NS` off; review §3). The contract reports the
  difference rather than hiding it.
- **The sandbox never trusts the sandboxed program's cooperation** for any
  guarantee: a layer that the program could route around (an in-process
  filter, an advisory proxy) is a best-effort layer, and the enforced
  guarantee is the one the kernel or a more-trusted process holds.

## 10. Decisions (coordinator, 2026-10-29)

- **Rules-engine host language.** C callbacks are the floor and what the ABI
  promises. A small, safe, *declarative* rule format the library evaluates
  itself (a consumer ships rules as data, not code) is wanted too, but
  later: Phase U0 defines only the C event/verdict API, and the declarative
  layer is built on top of it afterwards.
- **Proxy scope.** Ship a built-in L7 filtering proxy mechanism, kept
  optional. Genuine network filtering means the library must be able to see
  the traffic (HTTP, TLS SNI), so an intercept-hooks-only design that leaves
  the proxy to the consumer is not enough; the consumer may still bring its
  own where it prefers.
- **cgroups / privilege.** Unprivileged-first: the desktop-Linux container
  and firejail backends work through user namespaces with no privilege.
  cgroup-v2 delegation and a one-time privileged helper are an *optional*
  enhancement, never required, and the guarantees contract reports which of
  the two a given launch got.
- **Report format.** Both: a stable, versioned C struct is the ABI truth,
  with a serialisation helper alongside it. The serialisation is **JSON**
  (not CBOR) unless a consumer needs CBOR later.
