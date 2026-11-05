/*
 * Bounded zones (include/sbx_zones.h, docs/zones.md, Droidtop/tracker#651):
 * the catalogue, the five profiles, the profile format, and the decider
 * that sorts each request into its entry and answers from the zone, the
 * person's stored answer, then the prompt.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx_zones.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

enum {
    Z_OWN_WRITE, Z_NEARBY_READ, Z_PICKED_READ, Z_PICKED_WRITE, Z_WATCH, Z_NET_LOCAL, Z_NET_INTERNET, Z_NET_HOST,
    Z_PROGRAMS_OWN, Z_IPC_LOCAL, Z_LINKS_OPEN, Z_COUNT
};

static const struct sbx_zone_entry catalogue[Z_COUNT] = {
    {"files.own.write", "Change files in its own folder", 0, 1},
    {"files.nearby.read", "Read other folders in the same game library", 0, 1},
    {"files.picked.read", "Read a folder you pick", 0, 1},
    {"files.picked.write", "Change files in a folder you pick", 0, 1},
    {"files.watch", "Notice when its files change", 1, 1},
    {"net.local", "Talk to devices on your local network", 0, 1},
    {"net.internet", "Use the internet", 0, 1},
    {"net.host", "Let other devices connect to it", 0, 1},
    {"programs.own", "Run its own helper programs", 0, 1},
    {"ipc.local", "Let its own programs talk to each other", 0, 1},
    {"links.open", "Offer to open web links", 0, 1},
};

/* The "never" layer: refused in every profile and never an entry, so a line naming one is an error. */
static const char *const never[] = {
    "programs.outside", "ptrace", "memory.others", "namespaces", "mounts", "bpf", "perf", "io_uring", "modules",
};

#define D SBX_ZONE_DENY
#define P SBX_ZONE_PROMPT
#define A SBX_ZONE_ALLOW

struct sbx_zone_profile {
    char name[64];
    unsigned char zones[Z_COUNT];
};

/* docs/zones.md, "The five profiles": columns Locked, Careful (the default), Balanced, Relaxed, Open. */
static const struct sbx_zone_profile shipped[5] = {
    {"locked", {P, D, D, D, D, D, D, D, D, D, D}},
    {"careful", {A, P, P, D, P, D, D, D, P, P, P}},
    {"balanced", {A, P, P, P, A, P, P, D, P, A, P}},
    {"relaxed", {A, A, P, P, A, P, P, P, A, A, P}},
    {"open", {A, A, P, P, A, A, P, P, A, A, P}},
};

#undef D
#undef P
#undef A

unsigned sbx_zone_catalogue_version(void) { return SBX_ZONE_CATALOGUE_VERSION; }

const struct sbx_zone_entry *sbx_zone_entry(unsigned index) { return index < Z_COUNT ? &catalogue[index] : NULL; }

const struct sbx_zone_profile *sbx_zone_shipped(const char *name) {
    for (unsigned i = 0; name && i < 5; i++) {
        if (strcmp(shipped[i].name, name) == 0) return &shipped[i];
    }
    return NULL;
}

static int entry_index(const char *id) {
    for (int i = 0; id && i < Z_COUNT; i++) {
        if (strcmp(catalogue[i].id, id) == 0) return i;
    }
    return -1;
}

enum sbx_zone sbx_zone_of(const struct sbx_zone_profile *profile, const char *entry_id) {
    int i = entry_index(entry_id);
    return profile && i >= 0 ? (enum sbx_zone) profile->zones[i] : SBX_ZONE_DENY;
}

const char *sbx_zone_profile_name(const struct sbx_zone_profile *profile) { return profile ? profile->name : NULL; }

void sbx_zone_profile_free(struct sbx_zone_profile *profile) {
    for (unsigned i = 0; i < 5; i++) {
        if (profile == &shipped[i]) return;  /* shipped ones are not the caller's */
    }
    free(profile);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = '\0';
    return s;
}

static int fail(char *error, size_t size, int line, const char *what, const char *word) {
    if (error && size) snprintf(error, size, "line %d: %s%s%s", line, what, word ? ": " : "", word ? word : "");
    return -EINVAL;
}

int sbx_zone_profile_parse(const char *text, struct sbx_zone_profile **out, char *error, size_t error_size) {
    if (!text || !out) return -EINVAL;
    *out = NULL;
    if (error && error_size) error[0] = '\0';
    char *copy = strdup(text);
    if (!copy) return -ENOMEM;
    int set[Z_COUNT];
    unsigned char zones[Z_COUNT];
    memset(set, 0, sizeof(set));
    char name[64] = "";
    const struct sbx_zone_profile *base = &shipped[1];
    unsigned catalogue_version = 1;
    int seen_version = 0, line_number = 0, result = 0;
    char *save = NULL;
    for (char *raw = strtok_r(copy, "\n", &save); raw && result == 0; raw = strtok_r(NULL, "\n", &save)) {
        line_number++;
        char *line = trim(raw);
        if (line[0] == '\0' || line[0] == '#') continue;
        if (!seen_version) {
            unsigned version;
            char tail;
            if (sscanf(line, "sbx-zones %u%c", &version, &tail) != 1) {
                result = fail(error, error_size, line_number, "the first line must be \"sbx-zones 1\"", NULL);
            } else if (version != 1) {
                result = fail(error, error_size, line_number, "a profile from a newer library; it is not read", NULL);
            }
            seen_version = 1;
            continue;
        }
        char *colon = strchr(line, ':'), *equals = strchr(line, '=');
        if (colon && (!equals || colon < equals)) {
            *colon = '\0';
            char *key = trim(line), *value = trim(colon + 1);
            if (strcmp(key, "name") == 0) {
                snprintf(name, sizeof(name), "%s", value);
            } else if (strcmp(key, "based-on") == 0) {
                base = sbx_zone_shipped(value);
                if (!base) result = fail(error, error_size, line_number, "no shipped profile is called", value);
            } else if (strcmp(key, "catalogue") == 0) {
                char *end;
                unsigned long v = strtoul(value, &end, 10);
                if (*end || v == 0) result = fail(error, error_size, line_number, "not a catalogue version", value);
                else if (v > SBX_ZONE_CATALOGUE_VERSION) result = fail(error, error_size, line_number, "a catalogue from a newer library", value);
                else catalogue_version = (unsigned) v;
            } else {
                result = fail(error, error_size, line_number, "unknown setting", key);
            }
            continue;
        }
        if (!equals) {
            result = fail(error, error_size, line_number, "expected \"<entry> = allow|prompt|deny\"", line);
            continue;
        }
        *equals = '\0';
        char *id = trim(line), *zone = trim(equals + 1);
        int index = entry_index(id);
        if (index < 0) {
            int is_never = 0;
            for (size_t k = 0; k < sizeof(never) / sizeof(never[0]); k++) is_never |= strcmp(never[k], id) == 0;
            result = fail(error, error_size, line_number,
                          is_never ? "refused in every profile; no profile can grant it" : "the catalogue has no entry", id);
            continue;
        }
        if (strcmp(zone, "allow") == 0) zones[index] = SBX_ZONE_ALLOW;
        else if (strcmp(zone, "prompt") == 0) zones[index] = SBX_ZONE_PROMPT;
        else if (strcmp(zone, "deny") == 0) zones[index] = SBX_ZONE_DENY;
        else {
            result = fail(error, error_size, line_number, "a zone is allow, prompt or deny, not", zone);
            continue;
        }
        set[index] = 1;
    }
    free(copy);
    if (result == 0 && !seen_version) result = fail(error, error_size, 0, "the version line \"sbx-zones 1\" is missing", NULL);
    if (result != 0) return result;
    struct sbx_zone_profile *profile = calloc(1, sizeof(*profile));
    if (!profile) return -ENOMEM;
    snprintf(profile->name, sizeof(profile->name), "%s", name[0] ? name : "own");
    for (int i = 0; i < Z_COUNT; i++) {
        /* Missing: based-on's zone, or prompt for an entry newer than the catalogue the profile was written for. */
        if (set[i]) profile->zones[i] = zones[i];
        else if (catalogue[i].since > catalogue_version) profile->zones[i] = SBX_ZONE_PROMPT;
        else profile->zones[i] = base->zones[i];
    }
    *out = profile;
    return 0;
}

/* ---- Applying a profile ---- */

struct session {
    char *id, *folder, *library;
    unsigned char zones[Z_COUNT];
    struct sbx_zone_host host;
};

static void session_free(void *argument) {
    struct session *s = argument;
    if (!s) return;
    free(s->id);
    free(s->folder);
    free(s->library);
    free(s);
}

static int under(const char *path, const char *folder) {
    if (!path || !folder) return 0;
    size_t n = strlen(folder);
    while (n > 1 && folder[n - 1] == '/') n--;
    return strncmp(path, folder, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

/* The stored answer, then the person; called only for an entry whose zone is prompt. */
static int answer(struct session *s, int entry, const char *detail, const struct sbx_access *access) {
    const struct sbx_zone_host *h = &s->host;
    enum sbx_zone stored = h->recall ? h->recall(h->context, s->id, catalogue[entry].id, detail) : SBX_ZONE_PROMPT;
    if (stored == SBX_ZONE_ALLOW) return 0;
    if (stored == SBX_ZONE_DENY) return -EACCES;
    if (!h->ask) return -EACCES;
    /* Asking waits: the broker serves this request again on a thread of its own, where it may. */
    if (!access->parked) return SBX_PARK;
    while (h->can_ask_now && !h->can_ask_now(h->context, s->id)) {
        if (h->background_action == SBX_ZONE_ALLOW) return 0;
        if (h->background_action == SBX_ZONE_DENY) return -EACCES;
        if (access->pid > 0 && kill(access->pid, 0) != 0 && errno == ESRCH) return -EINTR;
        usleep(250 * 1000);
    }
    struct sbx_zone_question question = {s->id, catalogue[entry].id, catalogue[entry].text, detail};
    int remember = 0;
    enum sbx_zone said = h->ask(h->context, &question, &remember);
    if (said != SBX_ZONE_ALLOW) said = SBX_ZONE_DENY;
    if (remember && h->remember) h->remember(h->context, s->id, catalogue[entry].id, detail, said);
    return said == SBX_ZONE_ALLOW ? 0 : -EACCES;
}

static int starts(const char *s, const char *prefix) { return s && strncmp(s, prefix, strlen(prefix)) == 0; }

static int zone_decide(void *context, const struct sbx_access *access) {
    struct session *s = context;
    const char *path = access->resolved && access->resolved[0] ? access->resolved : access->asked;
    if (access->net_rule) {
        /* Our own ask rules name their entry. */
        const char *rule = access->net_rule;
        int entry = starts(rule, "ask out local") ? Z_NET_LOCAL
                  : starts(rule, "ask out internet") || starts(rule, "ask dns any") ? Z_NET_INTERNET
                  : starts(rule, "ask in any") ? Z_NET_HOST : -1;
        if (entry < 0 || s->zones[entry] != SBX_ZONE_PROMPT) return SBX_KEEP;
        const char *detail = entry == Z_NET_INTERNET && access->net_name ? access->net_name : access->asked;
        return answer(s, entry, detail, access);
    }
    if (strcmp(access->op, "exec") == 0) {
        /* A program outside its folder never runs, whatever the profile (owner, 2026-10-25). */
        if (!under(path, s->folder)) return -EACCES;
        if (s->zones[Z_PROGRAMS_OWN] == SBX_ZONE_PROMPT) return answer(s, Z_PROGRAMS_OWN, path, access);
        return SBX_KEEP;
    }
    if ((strcmp(access->op, "bind") == 0 || strcmp(access->op, "connect") == 0) && under(path, s->folder)) {
        if (s->zones[Z_IPC_LOCAL] == SBX_ZONE_PROMPT) return answer(s, Z_IPC_LOCAL, s->folder, access);
        return s->zones[Z_IPC_LOCAL] == SBX_ZONE_DENY ? -EACCES : SBX_KEEP;
    }
    if (access->need == SBX_WRITE && under(path, s->folder) && s->zones[Z_OWN_WRITE] == SBX_ZONE_PROMPT) {
        return answer(s, Z_OWN_WRITE, s->folder, access);
    }
    if (access->rule_verdict != 0 && access->need != SBX_WRITE && s->library && under(path, s->library) &&
        !under(path, s->folder) && s->zones[Z_NEARBY_READ] == SBX_ZONE_PROMPT) {
        return answer(s, Z_NEARBY_READ, s->library, access);
    }
    return SBX_KEEP;
}

static int launch_allowed(const struct sbx_zone_game *game, int entry) {
    for (unsigned i = 0; i < game->launch_allowed_count; i++) {
        if (game->launch_allowed[i] && strcmp(game->launch_allowed[i], catalogue[entry].id) == 0) return 1;
    }
    return 0;
}

int sbx_zone_apply(struct sbx_policy *policy, struct sbx_lockdown_options *options, const struct sbx_zone_profile *profile,
                   const struct sbx_zone_game *game, const struct sbx_zone_host *host) {
    if (!policy || !options || !profile || !game || !game->id || !game->folder || game->folder[0] != '/' || !host) return -EINVAL;
    if (game->library && game->library[0] != '/') return -EINVAL;
    struct session *s = calloc(1, sizeof(*s));
    if (!s) return -ENOMEM;
    s->id = strdup(game->id);
    s->folder = strdup(game->folder);
    s->library = game->library ? strdup(game->library) : NULL;
    if (!s->id || !s->folder || (game->library && !s->library)) {
        session_free(s);
        return -ENOMEM;
    }
    memcpy(s->zones, profile->zones, sizeof(s->zones));
    s->host = *host;
    const unsigned char *z = s->zones;
    int error = 0;

    /* Files. The game's folder is decided on every access, so writes, exec and sockets in it reach the entries. */
    error |= sbx_policy_add(policy, game->folder, (z[Z_OWN_WRITE] == SBX_ZONE_ALLOW ? SBX_READ | SBX_WRITE : SBX_READ) | SBX_DECIDE);
    if (game->library && z[Z_NEARBY_READ] == SBX_ZONE_ALLOW) error |= sbx_policy_add(policy, game->library, SBX_READ);
    /* A folder the person picked: the picker was the question, so it holds unless the zone is deny. */
    for (unsigned i = 0; z[Z_PICKED_READ] != SBX_ZONE_DENY && i < game->picked_read_count; i++) {
        error |= sbx_policy_add(policy, game->picked_read[i], SBX_READ);
    }
    for (unsigned i = 0; z[Z_PICKED_WRITE] != SBX_ZONE_DENY && i < game->picked_write_count; i++) {
        error |= sbx_policy_add(policy, game->picked_write[i], SBX_READ | SBX_WRITE);
    }
    if (z[Z_WATCH] == SBX_ZONE_ALLOW || (z[Z_WATCH] == SBX_ZONE_PROMPT && launch_allowed(game, Z_WATCH))) {
        options->flags |= SBX_LOCK_WATCH;
    }

    /* The network: filtered, through the broker, only as far as the zones reach. */
    int network = z[Z_NET_LOCAL] != SBX_ZONE_DENY || z[Z_NET_INTERNET] != SBX_ZONE_DENY || z[Z_NET_HOST] != SBX_ZONE_DENY;
    if (network) {
        options->flags |= SBX_LOCK_NET_BROKERED | SBX_LOCK_NET_FILTER;
        if (z[Z_NET_LOCAL] != SBX_ZONE_DENY) {
            error |= sbx_policy_net_rule(policy, z[Z_NET_LOCAL] == SBX_ZONE_ALLOW ? "allow out local" : "ask out local");
        }
        if (z[Z_NET_INTERNET] != SBX_ZONE_DENY) {
            int allow = z[Z_NET_INTERNET] == SBX_ZONE_ALLOW;
            error |= sbx_policy_net_rule(policy, allow ? "allow out internet" : "ask out internet");
            error |= sbx_policy_net_rule(policy, allow ? "allow dns any" : "ask dns any");
        }
        if (z[Z_NET_HOST] != SBX_ZONE_DENY) {
            error |= sbx_policy_net_rule(policy, z[Z_NET_HOST] == SBX_ZONE_ALLOW ? "allow in any" : "ask in any");
        }
    }
    if (z[Z_PROGRAMS_OWN] != SBX_ZONE_DENY && options->exec_helper && options->child_library) options->flags |= SBX_LOCK_EXEC;
    /* Unix sockets of its own; with the network on, its filter decides Unix connects by the same rules, and binds stay refused. */
    if (z[Z_IPC_LOCAL] != SBX_ZONE_DENY && !network) options->flags |= SBX_LOCK_UNIX;

    if (error) {
        session_free(s);
        return -EINVAL;
    }
    sbx_policy_set_decider(policy, zone_decide, s);
    sbx_policy_attach(policy, s, session_free);
    return 0;
}
