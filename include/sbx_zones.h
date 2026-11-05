/*
 * Bounded zones: allow, prompt and deny profiles (docs/zones.md,
 * Droidtop/tracker#651). A fixed catalogue of bounded things a sandboxed
 * program may need beyond its host's baseline; five shipped profiles that
 * sort each entry into allow, prompt or deny; a person's own profiles,
 * parsed from text; and sbx_zone_apply, which turns one profile, for one
 * program, into the broker's rules, the lockdown's flags and a decider that
 * asks the host's prompt for each "prompt" entry on a thread of the
 * request's own.
 *
 * The library owns the catalogue, the profiles, the format and the check.
 * The host supplies the question's UI and the storage of the person's
 * answers. Linux and Android.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_ZONES_H
#define SBX_ZONES_H

#include <stddef.h>

#include "sbx.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32

enum sbx_zone { SBX_ZONE_DENY = 0, SBX_ZONE_PROMPT = 1, SBX_ZONE_ALLOW = 2 };

/* The catalogue's version: an entry added later starts in prompt in a profile written for an earlier one. */
#define SBX_ZONE_CATALOGUE_VERSION 1u
unsigned sbx_zone_catalogue_version(void);

struct sbx_zone_entry {
    const char *id;             /* "files.own.write", ... */
    const char *text;           /* what the person sees: "Change files in its own folder" */
    int asked_before_launch;    /* 1: settled on the launch sheet, not one call at a time */
    unsigned since;             /* the catalogue version that added it */
};
/* The catalogue, in order; NULL past its end. */
const struct sbx_zone_entry *sbx_zone_entry(unsigned index);

struct sbx_zone_profile;
/* A shipped profile: "locked", "careful" (the default), "balanced", "relaxed" or "open"; NULL for another name. */
const struct sbx_zone_profile *sbx_zone_shipped(const char *name);
/*
 * A person's own profile from its text (docs/zones.md, "The person's own
 * profiles"). Returns 0 and *out (free it with sbx_zone_profile_free), or
 * -EINVAL with the first problem, in words, in error.
 */
int sbx_zone_profile_parse(const char *text, struct sbx_zone_profile **out, char *error, size_t error_size);
void sbx_zone_profile_free(struct sbx_zone_profile *profile);
/* The profile's zone for an entry; SBX_ZONE_DENY for an id the catalogue does not have. */
enum sbx_zone sbx_zone_of(const struct sbx_zone_profile *profile, const char *entry_id);
const char *sbx_zone_profile_name(const struct sbx_zone_profile *profile);

/* A question for the person. */
struct sbx_zone_question {
    const char *game;    /* the program's id, as the host gave it */
    const char *entry;   /* the catalogue entry's id */
    const char *text;    /* the entry's line */
    const char *detail;  /* what it names: the folder, the host or address, the program, the port */
};

/* What the host supplies. Every callback runs on a broker thread; ask may block. */
struct sbx_zone_host {
    /* A stored answer for (game, entry, detail): SBX_ZONE_ALLOW, SBX_ZONE_DENY, or SBX_ZONE_PROMPT when none. */
    enum sbx_zone (*recall)(void *context, const char *game, const char *entry, const char *detail);
    /* Asks the person: SBX_ZONE_ALLOW or SBX_ZONE_DENY; *remember 1 to keep the answer. */
    enum sbx_zone (*ask)(void *context, const struct sbx_zone_question *question, int *remember);
    /* Whether the person can be asked now (NULL: always). */
    int (*can_ask_now)(void *context, const char *game);
    /* Stores an answer the person asked to keep (NULL: none kept). */
    void (*remember)(void *context, const char *game, const char *entry, const char *detail, enum sbx_zone answer);
    /* When the person cannot be asked: SBX_ZONE_PROMPT waits (the default), ALLOW or DENY answers this request only. */
    enum sbx_zone background_action;
    void *context;
};

/* The program the profile is applied to. Every path is absolute. */
struct sbx_zone_game {
    const char *id;
    const char *folder;                 /* the program's own folder */
    const char *library;                /* the library folder the person chose (files.nearby.read), or NULL */
    const char *const *picked_read;     /* folders the person picked to be read (files.picked.read) */
    unsigned picked_read_count;
    const char *const *picked_write;    /* folders the person picked to be changed (files.picked.write) */
    unsigned picked_write_count;
    const char *const *launch_allowed;  /* entry ids the person allowed on the launch sheet */
    unsigned launch_allowed_count;
};

/*
 * Sets policy's rules, network rules and decider, and adds to options->flags
 * the lockdown flags the entries need and no others, for game under profile
 * (docs/zones.md, "Library API"). The host's own baseline (its devices, its
 * private folders) is the host's to add before or after. The policy keeps
 * what it needs of game, host and profile (copies); host->context must
 * outlive it. options->flags gains SBX_LOCK_EXEC only when exec_helper and
 * child_library are set. Returns 0 or a negative errno.
 */
int sbx_zone_apply(struct sbx_policy *policy, struct sbx_lockdown_options *options, const struct sbx_zone_profile *profile,
                   const struct sbx_zone_game *game, const struct sbx_zone_host *host);

#endif

#ifdef __cplusplus
}
#endif

#endif
