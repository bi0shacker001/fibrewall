# Bounded zones: allow, prompt and deny profiles (design, 2026-10-28, Droidtop/tracker#651)

Design only, for the owner's review. Nothing here is built. The owner said
"Yep!" (2026-10-25) to a written design of the catalogue entries and the
five profile tables, put to him before anything is built. This is that
design.

## Why

The owner, 2026-10-25: "Maybe lockdown profiles are wise? ... This avoid the
'every game gets the level of permission the sloppiest game relies on'
issue." Learned or contributed per-game profiles were turned down: "Learning
what a specific application does only helps if that application ISN'T
malicious. And per-game profiles requires a developer or contributor to
provide a profile, which means profiles for malicious things are possible."
And: "Permissions you CAN grant an application, but that don't have to
automatically be provided. The profiles we design can be 'allow these, deny
these, and prompt the user for these', and as the user chooses
higher-risk-tolerance profiles, what falls into what will change."

So there are three layers. Only the middle one ever moves:

| Layer | Who sets it | Example |
| --- | --- | --- |
| **Never**: refused in every profile, not in the catalogue | the library | ptrace, namespaces, mounts, bpf, module loading; running a program outside the game's folder; files outside what the person granted |
| **Zones**: the catalogue, each entry allow, prompt or deny | the chosen profile, then the person's answers | change files in its own folder; use the internet; run its own helper program |
| **Always**: a core's baseline, the same for every game | the core | its GPU, audio and binder (allocate-then-clamp); its private data folder; reading the game's own folder |

The library owns the catalogue, the five profiles, the profile format, the
prompt policy and the check of a request against a profile (owner,
2026-10-25: "This code can benefit any application that uses the sandbox,
so should probably go in that library, then enginehost calls into it"). An
app that uses it supplies the prompt UI and the storage for the person's
answers. Enginehost uses it first; droidtop's plugin sandbox can use it
later.

## The catalogue (first entries)

Each entry is one bounded thing a game may need beyond its core's baseline.
Every entry has a stable id, a plain-language line the person sees, the
mechanism that enforces it, and when it is asked.

"First use" means the request waits at the broker while the person answers
(see "Prompts"). "Before launch" means the entry can't be judged one call
at a time, so it is asked on the launch sheet instead.

| Id | What the person sees | Mechanism | Asked |
| --- | --- | --- | --- |
| `files.own.write` | Change files in its own folder | the game folder's rule becomes read-write; each write-open goes through the broker | first use |
| `files.nearby.read` | Read other folders in the same game library | read rule on the library folder the person already chose for Enginehost (never above it) | first use, naming the folder |
| `files.picked.read` | Read a folder you pick | Android's folder picker; the app passes the picked folder to the library as a rule | first use: the picker *is* the question |
| `files.picked.write` | Change files in a folder you pick | the same, read-write | first use (picker) |
| `files.watch` | Notice when its files change | `SBX_LOCK_INOTIFY` (the kernel's inotify) | before launch |
| `net.local` | Talk to devices on your local network | `SBX_LOCK_NET_BROKERED`: the broker makes each socket, and the zone check sees each destination. Private, link-local and loopback addresses count as local | first use, naming the address |
| `net.internet` | Use the internet | the same, for every other address | first use, naming the host |
| `net.host` | Let other devices connect to it | brokered `bind` and `listen` (`SBX_NET_LISTEN`) | first use |
| `programs.own` | Run its own helper programs | `SBX_LOCK_EXEC`: an executable inside the game's folder runs under the same sandbox and the same grants, never wider. Each one is listed by name in Game setup | first use, naming the program |
| `ipc.local` | Let its own programs talk to each other | `SBX_LOCK_UNIX`: Unix sockets bound inside the game's folder, or abstract names under the game's own prefix | first use |
| `links.open` | Offer to open web links | the app's existing "offer to open" route. The library only says whether the offer may appear | each link (the offer is the question) |

The catalogue is fixed and versioned, and written by us. These are not
entries, so no profile can grant them:
- **a program outside the game's folder** (deny in every profile, owner,
  2026-10-25);
- **the clear escapes**: ptrace, other processes' memory, namespaces,
  mounts, bpf, `perf_event_open`, io_uring and module loading;
- **an extra system call a core's clamp refuses.** Each needed one would
  become its own named entry after review, and none is needed yet. What
  Enginehost's learning runs recorded is covered by the entries above:
  inotify, Unix sockets, inet sockets and exec.

**Rules for the catalogue (owner, 2026-10-25):**
- A new entry starts in prompt in every profile, including the person's
  own. It is never allow.
- The default profile's allow list changes only by an owner decision
  written into the spec.
- Learning mode stays a developer tool. Its output (including
  `allowed_by`) never becomes a grant or a profile entry by itself.

## The five profiles

Plain names, from least to most risk tolerance. **Careful** is the
default. A is allow, P is prompt, D is deny.

| Entry | Locked | **Careful** (default) | Balanced | Relaxed | Open |
| --- | --- | --- | --- | --- | --- |
| Change files in its own folder | P | A | A | A | A |
| Read other folders in the game library | D | P | P | A | A |
| Read a folder you pick | D | P | P | P | P |
| Change files in a folder you pick | D | D | P | P | P |
| Notice when its files change | D | P | A | A | A |
| Talk to devices on your local network | D | D | P | P | A |
| Use the internet | D | D | P | P | P |
| Let other devices connect to it | D | D | D | P | P |
| Run its own helper programs | D | P | P | A | A |
| Let its own programs talk to each other | D | P | A | A | A |
| Offer to open web links | D | P | P | P | P |

The reasons for each row:
- **Internet is never allow in a shipped profile.** It is deny in Locked
  and Careful, and prompt above them. That is the owner's "grantable, ...
  never silently allowed". A person's own profile may set it to allow,
  because that is their own explicit choice.
- **A folder you pick never goes above prompt**, because the picker itself
  is the question. A game can never name its own target folder (#651
  point 5).
- **Letting other devices connect** opens the device to the network, so it
  is the last network entry to loosen.
- **Its own helper programs** run inside the same sandbox with the same
  grants, so they can't widen anything. Relaxed allows them without a
  question.
- **Locked** is for a game the person doesn't trust at all. It may read its
  own folder and use its core's baseline, and nothing else is offered.
  Even writing its own folder is a question.

## The person's own profiles

A profile editor (the app's UI) builds a table from the same catalogue,
starting from any shipped profile. The library parses and checks it. The
format is plain text, so an app can store it wherever it likes:

```
sbx-zones 1
name: My profile
based-on: careful
files.own.write = allow
net.internet = prompt
```

The library checks it like this:
- an id the catalogue doesn't have is an error, because a person's profile
  can't add entries, only sort them;
- a missing id takes `based-on`'s zone for it;
- an id newer than the profile's catalogue version starts in prompt;
- a line for something in the "never" layer is an error;
- the version line is required. A file from a newer library is refused,
  never half-read.

## Prompts

**The answer.** The person's answer is stored per game by the app, listed
in Game setup, and can be revoked there. The library defines the record:

```
game id, entry id, answer (allow | deny), detail (the folder, host or program it named), catalogue version
```

An answer covers its detail only. "Use the internet: allowed for
example.com" does not cover other hosts, and allowing one program does not
cover another. A revoked answer takes effect on the next launch.

**A request that waits.** When the zone is prompt and no answer is stored,
the broker parks that request on a thread of its own, as it already does
for a blocking `connect`. Then it calls the app's `ask` callback. Only the
asking thread of the game waits; its other threads' file and socket calls
go on.
- The answer comes back allow or deny. "Remember" stores it; "this time"
  answers only this request.
- A game that exits while it waits is answered `EINTR` and then torn down.

**Prompt background action (owner, 2026-10-25).** This is one setting:
wait (the default), allow or deny. It decides what happens when the app
says the person can't be asked right now, for example when the game is in
the background, or between frames with no prompt shown.
- **Wait:** the request stays parked until the person can answer.
- **Allow or deny:** that answer is given for this request only, and is
  never remembered.
- It never defaults to allow.

**Before launch.** Entries the broker can't judge one call at a time
(`files.watch`), and anything the person wants settled up front, are asked
on one sheet before the game starts. The answers go into the lockdown's
flags.

**How a prompt appears mid-game** (this was the issue's open question) is
the app's choice. The library tells the app which game is waiting, on
which entry and detail, and that the call is parked. An Android app can
show an overlay above the game's surface, or a notification while the game
is in the background. Neither one needs the game's cooperation.

## Library API (proposed)

```c
enum sbx_zone { SBX_ZONE_DENY, SBX_ZONE_PROMPT, SBX_ZONE_ALLOW };

/* The catalogue, compiled in. */
unsigned sbx_zone_catalogue_version(void);
const struct sbx_zone_entry *sbx_zone_entry(unsigned index); /* id, text, asked_before_launch */

/* Profiles: the five shipped ones, or the person's own parsed from text. */
const struct sbx_zone_profile *sbx_zone_shipped(const char *name); /* "locked" ... "open" */
int sbx_zone_profile_parse(const char *text, struct sbx_zone_profile **out, char *error, size_t error_size);
enum sbx_zone sbx_zone_of(const struct sbx_zone_profile *profile, const char *entry_id);

/* What the app supplies. */
struct sbx_zone_host {
    /* A stored answer for (game, entry, detail): SBX_ZONE_ALLOW, SBX_ZONE_DENY, or SBX_ZONE_PROMPT when none. */
    enum sbx_zone (*recall)(void *context, const char *game, const char *entry, const char *detail);
    /* Ask the person; returns allow or deny, and whether to remember. Called on a parked request's own thread. */
    enum sbx_zone (*ask)(void *context, const struct sbx_zone_question *question, int *remember);
    int (*can_ask_now)(void *context, const char *game);
    void (*remember)(void *context, const char *game, const char *entry, const char *detail, enum sbx_zone answer);
    unsigned background_action; /* SBX_ZONE_PROMPT (wait, the default), SBX_ZONE_ALLOW or SBX_ZONE_DENY */
    void *context;
};

/* Sets the policy's rules and decider, and the lockdown's flags, for one game under one profile. */
int sbx_zone_apply(struct sbx_policy *policy, struct sbx_lockdown_options *options,
                   const struct sbx_zone_profile *profile, const struct sbx_zone_game *game,
                   const struct sbx_zone_host *host);
```

`struct sbx_zone_game` names the game's id and folder, the library folder,
the folders the person picked, and the answers from the launch sheet.

`sbx_zone_apply` turns the profile into the policy:
- rules for the game's folder;
- the flags the entries need, and no others. Deny everywhere means the
  flag stays off;
- a decider that maps each request to its entry:

  | Request | Entry |
  | --- | --- |
  | a write-open under the game's folder | `files.own.write` |
  | a connect to a private address | `net.local` |
  | an exec inside the folder | `programs.own` |
  | an exec outside the folder | refused, every time |

  It then answers from the zone, then the stored answer, then the prompt.

An app that wants nothing of this keeps using rules and deciders as today.

## What changes outside the library

- **Enginehost's spec:** the runtime's "no network" rule becomes "network
  only through `net.local` and `net.internet`" (#651 point 3).
- **Enginehost:** keep answers in the game's library entry, list them in
  Game setup, and provide the prompt overlay and the picker.
- **droidtop's plugin sandbox:** can adopt the same catalogue later.
  Plugins' own permissions stay theirs until then.

## Questions for the owner

1. **The five names:** Locked, Careful, Balanced, Relaxed, Open, with
   Careful as the default. Are those right?
2. **`files.nearby.read`:** the owner's example was "read a folder next to
   it". Folder grants come only from the picker (point 5), so this entry
   reads only inside the library folder the person already picked for
   Enginehost. Is that the intended meaning, or should "a folder next to
   it" always go through the picker (`files.picked.read`)?
3. **Internet:** is prompt the most any shipped profile should give, Open
   included?
4. **Remembered answers:** should they be per detail (this host, this
   folder, this program), as above, or per entry ("internet: allowed for
   this game")?
