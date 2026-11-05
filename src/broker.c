/*
 * The broker half of sbx (see include/sbx.h): answers a confined process's
 * path calls from a policy of path rules and the host's decider.
 *
 * Each request is made absolute (against the directory descriptor that
 * came with it), normalised lexically and mapped through the aliases, then
 * resolved as the kernel would: every symlink on the way is followed (the
 * last one only for calls that follow it), found with readlink() alone.
 * The rules decide on the resolved path; a path that does not resolve is
 * decided on its lexical form, so a refusal never says whether something
 * exists. The host's decider then sees both and the rules' verdict.
 *
 * The broker never stats or opens anything on the confined code's behalf
 * beyond the call it was asked for (and O_PATH handles, which check no
 * permission). It runs in the same SELinux domain as an app's code would,
 * and a getattr can be refused there where the asked-for call is allowed:
 * on the emulator a stat of /system/bin/hwservicemanager was, which sent
 * libhidl down its passthrough path and aborted the allocator
 * (Droidtop/tracker#26, ehsandbox lockdown run 4).
 *
 * The call itself is made relative to the resolved parent directory,
 * opened first and checked again through the name the kernel gives the
 * open descriptor (/proc/self/fd), with O_NOFOLLOW on the final name: a
 * symlink swapped in between the check and the call cannot lead it
 * outside the rules, so nothing outside is ever created, truncated,
 * renamed or removed. An open is checked once more on what the new
 * descriptor names.
 *
 * /proc/self and /proc/thread-self are rewritten to the sender's pid, which
 * comes from SCM_CREDENTIALS (the kernel's word, not the request's).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "sbx.h"
#include "protocol.h"
#include "internal.h"
#include "net.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef __NR_renameat2
#if defined(__x86_64__)
#define __NR_renameat2 316
#elif defined(__aarch64__)
#define __NR_renameat2 276
#endif
#endif

#define LOOKUP 0x100u       /* internal need: stat, access F_OK, traversal */
#define MODE_BITS (SBX_READ | SBX_WRITE)
#define FLAG_BITS (SBX_CASE_INSENSITIVE | SBX_DECIDE)

struct rule {
    char *path;
    size_t length;
    unsigned mode;
    unsigned flags;
};

struct alias {
    char *virtual_path;
    size_t virtual_length;
    char *real_path;
    size_t real_length;
};

struct sbx_policy {
    struct rule *rules;
    size_t count;
    struct alias *aliases;
    size_t alias_count;
    sbx_decide_fn decide;
    void *decide_context;
    sbx_audit_fn audit;
    void *audit_context;
    unsigned net;  /* SBX_NET_* grants */
    char *system_paths[SBX_SYSTEM_SOCKETS_MAX];
    unsigned system_grants[SBX_SYSTEM_SOCKETS_MAX];
    unsigned system_count;
    struct tree *tree;  /* SBX_LOCK_SIGNAL_TREE: the processes that have asked this policy's brokers anything */
    /* SBX_LOCK_UNIX's abstract names: the name's bytes (no leading NUL) and the mode. */
    char *unix_names[SBX_UNIX_NAMES_MAX];
    size_t unix_name_lengths[SBX_UNIX_NAMES_MAX];
    unsigned unix_name_modes[SBX_UNIX_NAMES_MAX];
    unsigned unix_name_count;
    struct netp *netp;  /* the network rules (sbx_policy_net_rule) and the addresses the broker resolved */
    int refs;           /* the host's, plus one per broker thread that outlives a request (accept, relays) */
};

static void default_audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result >= 0) return;
    fprintf(stderr, "sbx: refused %s %s (%s): %s\n", access->op, access->asked,
            access->resolved[0] ? access->resolved : "unresolved", strerror(-result));
}

/*
 * ---- The tree a policy's brokers serve (SBX_LOCK_SIGNAL_TREE) ----
 *
 * Every process that has sent a request, by pid and start time (so a pid
 * the kernel hands to someone else later is not taken for it). A signal's
 * target is in the tree when it, or a process it descends from, is here.
 */
#define TREE_MAX 1024
struct tree {
    pthread_mutex_t lock;
    unsigned count;
    struct {
        pid_t pid;
        unsigned long long start;
    } members[TREE_MAX];
};

/* A process's start time and parent from /proc/<pid>/stat; 0 when it is gone. */
static unsigned long long process_start(pid_t pid, pid_t *parent) {
    char path[64], text[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    /* After the command's closing parenthesis: state, ppid, then 17 fields to starttime (field 22). */
    char *after = strrchr(text, ')');
    if (!after) return 0;
    char state;
    int ppid;
    unsigned long long start = 0;
    if (sscanf(after + 1, " %c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &state,
               &ppid, &start) != 3) {
        return 0;
    }
    if (parent) *parent = (pid_t) ppid;
    return start;
}

/*
 * Records pid, once: every request passes here, so a pid already present
 * costs a scan and no /proc read. A pid the kernel later reuses keeps its
 * first start time, so the new process counts only as itself (a sender).
 */
static int tree_note(struct tree *tree, pid_t pid) {
    if (!tree || pid <= 0) return 0;
    pthread_mutex_lock(&tree->lock);
    for (unsigned i = 0; i < tree->count; i++) {
        if (tree->members[i].pid == pid) {
            pthread_mutex_unlock(&tree->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&tree->lock);
    unsigned long long start = process_start(pid, NULL);
    if (start == 0) return 0;
    pthread_mutex_lock(&tree->lock);
    unsigned slot = tree->count < TREE_MAX ? tree->count++ : TREE_MAX;
    /* Full: the first member that has exited makes room. */
    for (unsigned i = 0; slot == TREE_MAX && i < TREE_MAX; i++) {
        if (process_start(tree->members[i].pid, NULL) != tree->members[i].start) slot = i;
    }
    if (slot < TREE_MAX) {
        tree->members[slot].pid = pid;
        tree->members[slot].start = start;
    }
    pthread_mutex_unlock(&tree->lock);
    /*
     * Full of live members: the pid is untracked, so the tree can no longer
     * tell it apart from a stranger. Refuse the request rather than drop it
     * silently and judge a tree member as an outsider (review A-19).
     */
    return slot < TREE_MAX ? 0 : -EAGAIN;
}

static int tree_has(struct tree *tree, pid_t pid, unsigned long long start) {
    int found = 0;
    pthread_mutex_lock(&tree->lock);
    for (unsigned i = 0; i < tree->count && !found; i++) {
        found = tree->members[i].pid == pid && tree->members[i].start == start;
    }
    pthread_mutex_unlock(&tree->lock);
    return found;
}

/* Whether target (a process, by its thread group) is sender, or in the tree: a member or a member's descendant. */
static int in_tree(struct tree *tree, pid_t sender, pid_t target) {
    if (target <= 0) return 0;
    if (target == sender) return 1;
    pid_t at = target;
    for (int depth = 0; depth < 64 && at > 1; depth++) {
        pid_t parent = 0;
        unsigned long long start = process_start(at, &parent);
        if (start == 0) return 0;
        if (tree_has(tree, at, start)) return 1;
        at = parent;
    }
    return 0;
}

/* The thread group a thread belongs to, from /proc/<tid>/status; 0 when it is gone. */
static pid_t thread_group(pid_t tid) {
    char path[64], text[2048];
    snprintf(path, sizeof(path), "/proc/%d/status", (int) tid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0) return 0;
    text[n] = 0;
    char *line = strstr(text, "\nTgid:");
    return line ? (pid_t) atoi(line + 6) : 0;
}

struct sbx_policy *sbx_policy_new(void) {
    struct sbx_policy *policy = calloc(1, sizeof(struct sbx_policy));
    if (!policy) return NULL;
    policy->tree = calloc(1, sizeof(struct tree));
    if (!policy->tree) {
        free(policy);
        return NULL;
    }
    policy->netp = netp_new();
    if (!policy->netp) {
        free(policy->tree);
        free(policy);
        return NULL;
    }
    pthread_mutex_init(&policy->tree->lock, NULL);
    policy->audit = default_audit;
    policy->refs = 1;
    return policy;
}

/* A broker thread that outlives its request (an accept, a name relay) keeps the policy until it ends. */
static const struct sbx_policy *policy_hold(const struct sbx_policy *policy) {
    __atomic_add_fetch(&((struct sbx_policy *) policy)->refs, 1, __ATOMIC_ACQ_REL);
    return policy;
}
static void policy_release(const struct sbx_policy *policy) { sbx_policy_free((struct sbx_policy *) policy); }

void sbx_policy_free(struct sbx_policy *policy) {
    if (!policy) return;
    if (__atomic_sub_fetch(&policy->refs, 1, __ATOMIC_ACQ_REL) > 0) return;
    netp_free(policy->netp);
    for (size_t i = 0; i < policy->count; i++) free(policy->rules[i].path);
    for (size_t i = 0; i < policy->alias_count; i++) {
        free(policy->aliases[i].virtual_path);
        free(policy->aliases[i].real_path);
    }
    for (unsigned i = 0; i < policy->system_count; i++) free(policy->system_paths[i]);
    for (unsigned i = 0; i < policy->unix_name_count; i++) free(policy->unix_names[i]);
    free(policy->rules);
    free(policy->aliases);
    if (policy->tree) pthread_mutex_destroy(&policy->tree->lock);
    free(policy->tree);
    free(policy);
}

void sbx_policy_set_decider(struct sbx_policy *policy, sbx_decide_fn decide, void *context) {
    if (!policy) return;
    policy->decide = decide;
    policy->decide_context = context;
}

void sbx_policy_set_audit(struct sbx_policy *policy, sbx_audit_fn audit, void *context) {
    if (!policy) return;
    policy->audit = audit ? audit : default_audit;
    policy->audit_context = audit ? context : NULL;
}

/* out = a + b, both NUL-terminated; fails when the result would not fit in SBX_PATH_MAX. */
static int join(char *out, const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la + lb >= SBX_PATH_MAX) return -ENAMETOOLONG;
    memmove(out + la, b, lb + 1);
    if (out != a) memmove(out, a, la);
    return 0;
}

/* Lexically absolute and normalised: no "", ".", ".." components, no trailing slash. Fails on overflow. */
static int normalise(const char *base, const char *path, size_t path_len, char *out) {
    char joined[SBX_PATH_MAX * 2 + 2];
    size_t used = 0;
    if (path_len == 0 || path[0] != '/') {
        size_t base_len = strlen(base);
        if (base_len + 1 >= sizeof(joined)) return -ENAMETOOLONG;
        memcpy(joined, base, base_len);
        used = base_len;
        joined[used++] = '/';
    }
    if (used + path_len >= sizeof(joined)) return -ENAMETOOLONG;
    memcpy(joined + used, path, path_len);
    used += path_len;
    joined[used] = '\0';

    size_t length = 0;
    out[0] = '\0';
    char *cursor = joined;
    while (*cursor) {
        while (*cursor == '/') cursor++;
        if (!*cursor) break;
        char *end = cursor;
        while (*end && *end != '/') end++;
        size_t part = (size_t) (end - cursor);
        if (part == 1 && cursor[0] == '.') {
            /* nothing */
        } else if (part == 2 && cursor[0] == '.' && cursor[1] == '.') {
            while (length > 0 && out[length - 1] != '/') length--;
            if (length > 0) length--;
            out[length] = '\0';
        } else {
            if (length + 1 + part >= SBX_PATH_MAX) return -ENAMETOOLONG;
            out[length++] = '/';
            memcpy(out + length, cursor, part);
            length += part;
            out[length] = '\0';
        }
        cursor = end;
    }
    if (length == 0) strcpy(out, "/");
    return 0;
}

static int resolve(const char *path, int follow_last, int may_create, char *out);

/* The canonical form of an absolute path a host names: resolved when it resolves, else normalised. */
static char *canonical_copy(const char *path) {
    char normal[SBX_PATH_MAX];
    char resolved[SBX_PATH_MAX];
    if (normalise("/", path, strlen(path), normal) != 0) return NULL;
    if (resolve(normal, 1, 0, resolved) == 0) return strdup(resolved);
    return strdup(normal);
}

static int add_rule(struct sbx_policy *policy, char *copy, unsigned mode);

int sbx_policy_add(struct sbx_policy *policy, const char *path, unsigned mode) {
    if (!policy || !path || path[0] != '/') return -EINVAL;
    char *copy = canonical_copy(path);
    if (!copy) return -ENOMEM;
    /* The name as given, when it differs from what it resolves to: both checks must pass, and they see both. */
    char normal[SBX_PATH_MAX];
    if (normalise("/", path, strlen(path), normal) == 0 && strcmp(normal, copy) != 0) {
        char *given = strdup(normal);
        if (!given) {
            free(copy);
            return -ENOMEM;
        }
        int added = add_rule(policy, given, mode);
        if (added != 0) {
            free(copy);
            return added;
        }
    }
    return add_rule(policy, copy, mode);
}

/* Takes copy. */
static int add_rule(struct sbx_policy *policy, char *copy, unsigned mode) {
    struct rule *grown = realloc(policy->rules, (policy->count + 1) * sizeof(struct rule));
    if (!grown) {
        free(copy);
        return -ENOMEM;
    }
    policy->rules = grown;
    policy->rules[policy->count].path = copy;
    policy->rules[policy->count].length = strlen(copy);
    policy->rules[policy->count].mode = mode & MODE_BITS;
    policy->rules[policy->count].flags = mode & FLAG_BITS;
    policy->count++;
    return 0;
}

int sbx_policy_alias(struct sbx_policy *policy, const char *virtual_path, const char *real_path) {
    if (!policy || !virtual_path || !real_path || virtual_path[0] != '/' || real_path[0] != '/') return -EINVAL;
    char normal[SBX_PATH_MAX];
    if (normalise("/", virtual_path, strlen(virtual_path), normal) != 0) return -ENAMETOOLONG;
    if (strcmp(normal, "/") == 0) return -EINVAL;
    char *virtual_copy = strdup(normal);
    char *real_copy = canonical_copy(real_path);
    struct alias *grown = virtual_copy && real_copy
        ? realloc(policy->aliases, (policy->alias_count + 1) * sizeof(struct alias)) : NULL;
    if (!grown) {
        free(virtual_copy);
        free(real_copy);
        return -ENOMEM;
    }
    policy->aliases = grown;
    struct alias *a = &policy->aliases[policy->alias_count++];
    a->virtual_path = virtual_copy;
    a->virtual_length = strlen(virtual_copy);
    a->real_path = real_copy;
    a->real_length = strlen(real_copy);
    return 0;
}

/* path is under (or is) prefix, on a component boundary. */
static int within(const char *path, const char *prefix, size_t prefix_len) {
    if (prefix_len == 1 && prefix[0] == '/') return 1;
    return strncmp(path, prefix, prefix_len) == 0 && (path[prefix_len] == '\0' || path[prefix_len] == '/');
}

/* Replaces the prefix (length old_len) of path with replacement. */
static int replace_prefix(char *path, size_t old_len, const char *replacement, size_t new_len) {
    size_t tail = strlen(path + old_len);
    if (new_len + tail >= SBX_PATH_MAX) return -ENAMETOOLONG;
    memmove(path + new_len, path + old_len, tail + 1);
    memcpy(path, replacement, new_len);
    if (path[0] == '\0') strcpy(path, "/");
    return 0;
}

static int apply_alias(const struct sbx_policy *policy, char *path) {
    for (size_t i = 0; i < policy->alias_count; i++) {
        const struct alias *a = &policy->aliases[i];
        if (within(path, a->virtual_path, a->virtual_length)) {
            return replace_prefix(path, a->virtual_length, a->real_path, a->real_length);
        }
    }
    return 0;
}

/* The way back, for getcwd: a real path under an alias reads as its virtual name. */
static int unapply_alias(const struct sbx_policy *policy, char *path) {
    for (size_t i = 0; i < policy->alias_count; i++) {
        const struct alias *a = &policy->aliases[i];
        if (within(path, a->real_path, a->real_length)) {
            return replace_prefix(path, a->real_length, a->virtual_path, a->virtual_length);
        }
    }
    return 0;
}

static int all_digits(const char *s, size_t n) {
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

/* The rule that decides path (the longest), or NULL. */
static const struct rule *matching_rule(const struct sbx_policy *policy, const char *path) {
    const struct rule *best = NULL;
    for (size_t i = 0; i < policy->count; i++) {
        const struct rule *r = &policy->rules[i];
        if (within(path, r->path, r->length) && (!best || r->length >= best->length)) best = r;
    }
    return best;
}

/* What the rules allow on a normalised absolute path for the process pid: a mode, LOOKUP, or SBX_DENY. */
static unsigned allowed(const struct sbx_policy *policy, const char *path, pid_t pid) {
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *entry = path + 6;
        size_t n = strcspn(entry, "/");
        if (all_digits(entry, n)) {
            char own[24];
            int own_len = snprintf(own, sizeof(own), "%d", (int) pid);
            return (n == (size_t) own_len && strncmp(entry, own, n) == 0) ? MODE_BITS : SBX_DENY;
        }
    }
    const struct rule *rule = matching_rule(policy, path);
    if (rule) return rule->mode;
    size_t path_len = strlen(path);
    for (size_t i = 0; i < policy->count; i++) {
        if (within(policy->rules[i].path, path, path_len)) return LOOKUP;
    }
    return SBX_DENY;
}

static int permits(unsigned mode, unsigned need) {
    if (need == LOOKUP) return mode != SBX_DENY;
    return mode != LOOKUP && (mode & need) == need;
}

static int exists(const char *path);

/* Rewrites /proc/self and /proc/thread-self for the sender. */
static int rewrite_proc(char *path, pid_t pid, pid_t tid) {
    char rest[SBX_PATH_MAX];
    char head[64];
    const char *tail;
    if (strncmp(path, "/proc/self", 10) == 0 && (path[10] == '\0' || path[10] == '/')) {
        tail = path + 10;
        snprintf(head, sizeof(head), "/proc/%d", (int) pid);
    } else if (strncmp(path, "/proc/thread-self", 17) == 0 && (path[17] == '\0' || path[17] == '/')) {
        tail = path + 17;
        snprintf(head, sizeof(head), "/proc/%d/task/%d", (int) pid, (int) tid);
        /*
         * The thread the request names must be the sender's own. Checked
         * here, where it is used, not for every request: a broker under
         * another UID may not see the sender's /proc at all (an Android app
         * serving its isolated process), and needs it for nothing else.
         */
        if (tid <= 0 || !exists(head)) return -EINVAL;
    } else {
        return 0;
    }
    if (join(rest, head, tail) != 0) return -ENAMETOOLONG;
    strcpy(path, rest);
    return 0;
}

/* Whether path names something, by lookup alone (access F_OK checks no permission on the file itself). */
static int exists(const char *path) {
    return syscall(__NR_faccessat, AT_FDCWD, path, F_OK, 0) == 0 || errno != ENOENT;
}

/*
 * Under a case-insensitive rule, rewrites each component of path that does
 * not exist to an entry of its directory that differs only in case.
 * Components above the rule are left as they are.
 */
static void fold_case(const struct sbx_policy *policy, char *path) {
    const struct rule *rule = matching_rule(policy, path);
    if (!rule || !(rule->flags & SBX_CASE_INSENSITIVE)) return;
    size_t start = rule->length == 1 ? 0 : rule->length;
    char *cursor = path + start;
    while (*cursor == '/') {
        char *name = cursor + 1;
        char *end = name;
        while (*end && *end != '/') end++;
        char saved = *end;
        *end = '\0';
        if (!exists(path)) {
            /* The directory holding name. */
            name[-1] = '\0';
            DIR *directory = opendir(path[0] ? path : "/");
            name[-1] = '/';
            if (directory) {
                struct dirent *entry;
                while ((entry = readdir(directory))) {
                    if (strcasecmp(entry->d_name, name) == 0 && strlen(entry->d_name) == strlen(name)) {
                        memcpy(name, entry->d_name, strlen(name));
                        break;
                    }
                }
                closedir(directory);
            }
        }
        *end = saved;
        cursor = end;
        if (!saved) break;
    }
}

/* Splits an absolute resolved path into its parent and final name ("/" has neither). */
static int split(const char *path, char *parent, const char **name) {
    const char *slash = strrchr(path, '/');
    if (!slash || slash[1] == '\0') return -EINVAL;
    size_t parent_len = (size_t) (slash - path);
    if (parent_len == 0) {
        strcpy(parent, "/");
    } else {
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    }
    *name = slash + 1;
    return 0;
}

/*
 * The path as the kernel would resolve it, path being absolute and
 * normalised. Every symlink on the way is followed, found by readlink()
 * alone (EINVAL: not a link); the last component only when follow_last
 * (open, stat, access, statfs, chdir), not for calls that act on a name
 * itself (lstat, readlink, unlink, rename, mkdir). A final name that does
 * not exist is kept when may_create, else ENOENT.
 */
static int resolve(const char *path, int follow_last, int may_create, char *out) {
    char work[SBX_PATH_MAX];
    if (strlen(path) >= sizeof(work)) return -ENAMETOOLONG;
    strcpy(work, path);
    for (int hops = 0;; hops++) {
        if (hops > 40) return -ELOOP;
        size_t used = 0;
        out[0] = '\0';
        const char *cursor = work;
        int restarted = 0;
        while (*cursor) {
            while (*cursor == '/') cursor++;
            if (!*cursor) break;
            const char *end = cursor;
            while (*end && *end != '/') end++;
            size_t part = (size_t) (end - cursor);
            const char *rest = end;
            while (*rest == '/') rest++;
            int last = *rest == '\0';
            if (used + 1 + part >= SBX_PATH_MAX) return -ENAMETOOLONG;
            out[used] = '/';
            memcpy(out + used + 1, cursor, part);
            size_t candidate = used + 1 + part;
            out[candidate] = '\0';
            if (last && !follow_last) return 0;
            char target[SBX_PATH_MAX];
            ssize_t n = readlink(out, target, sizeof(target) - 1);
            if (n >= 0) {
                target[n] = '\0';
                /* The link's text, against its own directory, then the rest of the path. */
                char joined[SBX_PATH_MAX * 2 + 2];
                size_t length;
                if (target[0] == '/') {
                    length = (size_t) snprintf(joined, sizeof(joined), "%s/%s", target, rest);
                } else {
                    out[used] = '\0';
                    length = (size_t) snprintf(joined, sizeof(joined), "%s/%s/%s", out, target, rest);
                }
                if (length >= sizeof(joined)) return -ENAMETOOLONG;
                int error = normalise("/", joined, length, work);
                if (error != 0) return error;
                restarted = 1;
                break;
            }
            if (errno == ENOENT) {
                if (last && may_create) return 0;
                return -ENOENT;
            }
            if (errno != EINVAL) return -errno;
            used = candidate;
            cursor = end;
        }
        if (!restarted) {
            if (used == 0) strcpy(out, "/");
            return 0;
        }
    }
}

static int fd_path(int fd, char *out) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, out, SBX_PATH_MAX - 1);
    if (n < 0) return -errno;
    out[n] = '\0';
    return 0;
}

static const char *op_name(uint32_t op) {
    switch (op) {
    case SBX_OPEN: return "open";
    case SBX_STAT: return "stat";
    case SBX_ACCESS: return "access";
    case SBX_READLINK: return "readlink";
    case SBX_MKDIR: return "mkdir";
    case SBX_UNLINK: return "unlink";
    case SBX_RENAME: return "rename";
    case SBX_STATFS: return "statfs";
    case SBX_CHDIR: return "chdir";
    case SBX_GETCWD: return "getcwd";
    case SBX_LIST: return "list";
    case SBX_CHMOD: return "chmod";
    case SBX_UTIMENS: return "utimens";
    case SBX_SOCKET: return "socket";
    case SBX_CONNECT: return "connect";
    case SBX_BIND: return "bind";
    case SBX_LISTEN: return "listen";
    case SBX_ACCEPT: return "accept";
    case SBX_LINK: return "link";
    case SBX_SYMLINK: return "symlink";
    case SBX_TRUNCATE: return "truncate";
    case SBX_UNIX_BIND: return "bind";
    case SBX_UNIX_CONNECT: return "connect";
    case SBX_EXEC: return "exec";
    case SBX_SIGNAL: return "signal";
    case SBX_WATCH: return "watch";
    case SBX_SEND: return "send";
    case SBX_RESOLVE: return "resolve";
    default: return "unknown";
    }
}

static int open_wants_write(int flags) {
    return (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

/* What a request is, while it is being decided. */
struct check {
    const struct sbx_policy *policy;
    uint32_t op;
    pid_t pid;
    pid_t tid;
    int flags;
    char asked[SBX_PATH_MAX];
    char real[SBX_PATH_MAX];
};

static void audit(const struct check *c, unsigned need, int result) {
    struct sbx_access access = {
        .op = op_name(c->op), .asked = c->asked, .resolved = c->real,
        .need = need == LOOKUP ? 0 : need, .flags = c->flags, .pid = c->pid, .rule_verdict = result,
    };
    c->policy->audit(c->policy->audit_context, &access, result);
}

/*
 * Decides one path of a request; fills c->real. need: SBX_READ, SBX_WRITE
 * or LOOKUP. Returns 0 when the call may go ahead.
 *
 * The rules decide on the resolved path: a caller may name a place through
 * an alias of the system's own (/sdcard, /data/user/0) or through one of
 * the policy's, but what is acted on is always what the path resolves to.
 * A path that does not resolve is decided on its lexical form.
 */
static int decide(struct check *c, const char *base, const char *raw, size_t len, unsigned need,
                  int follow_last, int may_create) {
    snprintf(c->asked, sizeof(c->asked), "%.*s", (int) len, raw);
    c->real[0] = '\0';
    char normal[SBX_PATH_MAX];
    int error = normalise(base, raw, len, normal);
    if (error == 0) error = apply_alias(c->policy, normal);
    if (error == 0) error = rewrite_proc(normal, c->pid, c->tid);
    if (error != 0) return error;
    fold_case(c->policy, normal);

    int resolved = resolve(normal, follow_last, may_create, c->real);
    if (resolved != 0) c->real[0] = '\0';
    const char *decided = resolved == 0 ? c->real : normal;
    int verdict = permits(allowed(c->policy, decided, c->pid), need) ? 0 : -EACCES;

    const struct rule *rule = matching_rule(c->policy, decided);
    int ask = c->policy->decide && (verdict != 0 || (rule && (rule->flags & SBX_DECIDE)));
    int result = verdict;
    if (ask) {
        struct sbx_access access = {
            .op = op_name(c->op), .asked = c->asked, .resolved = c->real,
            .need = need == LOOKUP ? 0 : need, .flags = c->flags, .pid = c->pid, .rule_verdict = verdict,
        };
        int answer = c->policy->decide(c->policy->decide_context, &access);
        if (answer != SBX_KEEP) result = answer > 0 ? -EACCES : answer;
    }
    /* A refusal never says whether the path exists; an allowed path that does not resolve says why. */
    if (result == 0 && resolved != 0) result = resolved;
    audit(c, need, result);
    return result;
}

/*
 * ---- What each pid runs, after SBX_EXEC ----
 *
 * An image started through sbx-exec is, to the kernel, sbx-exec: its
 * /proc/<pid>/exe names the helper. The broker records the target each pid
 * was allowed to run and answers readlink and open of that pid's own
 * /proc/<pid>/exe with it (Wine and others find their files from it).
 */
#define EXE_RECORDS 256
static struct {
    pid_t pid;
    char path[SBX_PATH_MAX];
} exe_records[EXE_RECORDS];
static unsigned exe_next;
static pthread_mutex_t exe_lock = PTHREAD_MUTEX_INITIALIZER;

static void exe_record(pid_t pid, const char *path) {
    pthread_mutex_lock(&exe_lock);
    unsigned slot = exe_next % EXE_RECORDS;
    for (unsigned i = 0; i < EXE_RECORDS; i++) {
        if (exe_records[i].pid == pid) {
            slot = i;
            break;
        }
    }
    if (slot == exe_next % EXE_RECORDS) exe_next++;
    exe_records[slot].pid = pid;
    snprintf(exe_records[slot].path, sizeof(exe_records[slot].path), "%s", path);
    pthread_mutex_unlock(&exe_lock);
}

/* Whether real is pid's own /proc/<pid>/exe with a recorded target; copies it to out. */
static int exe_lookup(const char *real, pid_t pid, char *out) {
    char own[64];
    snprintf(own, sizeof(own), "/proc/%d/exe", (int) pid);
    if (strcmp(real, own) != 0) return 0;
    int found = 0;
    pthread_mutex_lock(&exe_lock);
    for (unsigned i = 0; i < EXE_RECORDS && !found; i++) {
        if (exe_records[i].pid == pid && exe_records[i].path[0]) {
            snprintf(out, SBX_PATH_MAX, "%s", exe_records[i].path);
            found = 1;
        }
    }
    pthread_mutex_unlock(&exe_lock);
    return found;
}

/*
 * Opens the parent directory of c->real, checks the descriptor still names
 * an allowed place (or one the decider allowed), and returns it with the
 * final name. Returns a negative errno on failure.
 */
static int open_parent(struct check *c, unsigned need, const char **name) {
    char parent[SBX_PATH_MAX];
    if (split(c->real, parent, name) != 0) return -EINVAL;
    int fd = open(parent, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;
    char named[SBX_PATH_MAX];
    if (fd_path(fd, named) != 0 || strcmp(named, parent) != 0) {
        /* The parent changed after the check: refuse rather than act somewhere else. */
        close(fd);
        audit(c, need, -EACCES);
        return -EACCES;
    }
    return fd;
}

/* Checks what an open descriptor actually names against what was decided. */
static int confirm_opened(struct check *c, int fd, unsigned need) {
    char opened[SBX_PATH_MAX];
    if (fd_path(fd, opened) != 0 || opened[0] != '/') return 0;  /* not a filesystem path: nothing to compare */
    if (strcmp(opened, c->real) == 0) return 0;
    if (permits(allowed(c->policy, opened, c->pid), need)) return 0;
    audit(c, need, -EACCES);
    return -EACCES;
}

static void reply(int to, int64_t result, const void *data, uint32_t data_len, int fd) {
    struct sbx_reply header = {.result = result, .data_len = data_len};
    struct iovec parts[2] = {{&header, sizeof(header)}, {(void *) data, data_len}};
    union {
        char buffer[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = parts;
    message.msg_iovlen = data_len ? 2 : 1;
    if (fd >= 0) {
        message.msg_control = control.buffer;
        message.msg_controllen = sizeof(control.buffer);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&message);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    }
    /*
     * Non-blocking: the client makes a fresh reply socketpair per request and
     * is already waiting on it, so a well-formed reply always fits. A client
     * that instead hands a socket whose buffer is full (its own, or the
     * broker's) would otherwise block this serve thread, and with it the whole
     * tree. The reply is dropped instead; that client only starves itself.
     */
    sendmsg(to, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
}

/* Opens c->real (decided) the safe way: from its checked parent, never following a final link. */
static int open_decided(struct check *c, int flags, mode_t mode, unsigned need) {
    int fd;
    if (strcmp(c->real, "/") == 0) {
        fd = open("/", flags | O_NOCTTY | O_CLOEXEC, mode);
        if (fd < 0) return -errno;
    } else {
        const char *name;
        int parent = open_parent(c, need, &name);
        if (parent < 0) return parent;
        fd = openat(parent, name, flags | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC, mode);
        int error = errno;
        close(parent);
        if (fd < 0) {
            /* A final link (one asked for by O_NOFOLLOW and O_PATH stays possible): reported as the kernel would. */
            return -error;
        }
    }
    int confirmed = confirm_opened(c, fd, need);
    if (confirmed != 0) {
        close(fd);
        return confirmed;
    }
    return fd;
}

/*
 * An O_PATH descriptor of a regular file the rules let the process read,
 * exchanged for a read-only one of the same file. A received descriptor
 * with neither read nor write is checked by SELinux as ioctl, which an
 * Android app may not do on system files: the kernel drops it from the
 * reply, the call fails with EIO, and bionic's realpath(), which opens with
 * O_PATH, fails with it (the linker then dropped a WebView in /product from
 * its namespace, Droidtop/tracker#550). Read-only is what an ordinary open
 * of the same path would have been given. Anything else (a directory, a
 * device, a file the rules only let it look up) keeps its O_PATH handle.
 */
static int readable_path_handle(const struct check *c, int fd) {
    if (!permits(allowed(c->policy, c->real, c->pid), SBX_READ)) return fd;
    struct stat handle, opened;
    if (fstat(fd, &handle) != 0 || !S_ISREG(handle.st_mode)) return fd;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    int readable = open(link, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
    if (readable < 0) return fd;
    if (fstat(readable, &opened) != 0 || opened.st_dev != handle.st_dev || opened.st_ino != handle.st_ino) {
        close(readable);
        return fd;
    }
    close(fd);
    return readable;
}

static void handle(const struct sbx_policy *policy, const struct sbx_request *request, const char *path,
                   const char *path2, const char *base, const char *base2, pid_t pid, int answer) {
    struct check c;
    c.policy = policy;
    c.op = request->op;
    c.pid = pid;
    c.tid = request->tid;
    c.flags = request->op == SBX_OPEN ? request->flags : 0;
    int error;
    switch (request->op) {
    case SBX_OPEN: {
        int flags = request->flags;
        int writing = open_wants_write(flags);
        int creating = (flags & O_CREAT) != 0;
        /* O_PATH reads nothing: it is a handle to look things up from, like a traversal. */
        unsigned need = writing ? SBX_WRITE : (flags & O_PATH) ? LOOKUP : SBX_READ;
        error = decide(&c, base, path, request->path_len, need, !(flags & O_NOFOLLOW), creating);
        if (error != 0) break;
        /* The process's own /proc/<pid>/exe after sbx-exec: the target it was allowed to run, not the helper. */
        char exe[SBX_PATH_MAX];
        if (!writing && exe_lookup(c.real, pid, exe)) snprintf(c.real, sizeof(c.real), "%s", exe);
        /*
         * Non-blocking, so opening a FIFO (or a device whose open waits) in a
         * rule cannot hold the broker thread. The caller asked for its own
         * blocking mode, so restore that on the descriptor before handing it
         * back; on a regular file O_NONBLOCK meant nothing either way.
         */
        int fd = open_decided(&c, flags | O_NONBLOCK, (mode_t) request->mode, need);
        if (fd < 0) { error = fd; break; }
        if (flags & O_PATH) fd = readable_path_handle(&c, fd);
        if (!(flags & O_NONBLOCK)) {
            int current = fcntl(fd, F_GETFL);
            if (current >= 0) fcntl(fd, F_SETFL, current & ~O_NONBLOCK);
        }
        reply(answer, 0, NULL, 0, fd);
        close(fd);
        return;
    }
    case SBX_CHDIR: {
        error = decide(&c, base, path, request->path_len, LOOKUP, 1, 0);
        if (error != 0) break;
        int fd = open_decided(&c, O_PATH | O_DIRECTORY, 0, LOOKUP);
        if (fd < 0) { error = fd; break; }
        reply(answer, 0, NULL, 0, fd);
        close(fd);
        return;
    }
    case SBX_STAT: {
        int follow = !(request->flags & AT_SYMLINK_NOFOLLOW);
        error = decide(&c, base, path, request->path_len, LOOKUP, follow, 0);
        if (error != 0) break;
        struct stat st;
        if (strcmp(c.real, "/") == 0) {
            if (stat("/", &st) != 0) { error = -errno; break; }
        } else {
            const char *name;
            int parent = open_parent(&c, LOOKUP, &name);
            if (parent < 0) { error = parent; break; }
            int done = fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW);
            error = done == 0 ? 0 : -errno;
            close(parent);
            if (error != 0) break;
        }
        reply(answer, 0, &st, sizeof(st), -1);
        return;
    }
    case SBX_ACCESS: {
        unsigned need = (request->mode & W_OK) ? SBX_WRITE : (request->mode & R_OK) ? SBX_READ : LOOKUP;
        error = decide(&c, base, path, request->path_len, need, 1, 0);
        if (error != 0) break;
        if (strcmp(c.real, "/") == 0) {
            error = access("/", (int) request->mode) == 0 ? 0 : -errno;
            break;
        }
        const char *name;
        int parent = open_parent(&c, need, &name);
        if (parent < 0) { error = parent; break; }
        error = faccessat(parent, name, (int) request->mode, 0) == 0 ? 0 : -errno;
        close(parent);
        break;
    }
    case SBX_READLINK: {
        error = decide(&c, base, path, request->path_len, LOOKUP, 0, 0);
        if (error != 0) break;
        char exe[SBX_PATH_MAX];
        if (exe_lookup(c.real, pid, exe)) {
            size_t n = strlen(exe);
            if (n > request->mode) n = request->mode;
            reply(answer, (int64_t) n, exe, (uint32_t) n, -1);
            return;
        }
        const char *name;
        int parent = open_parent(&c, LOOKUP, &name);
        if (parent < 0) { error = parent; break; }
        char target[SBX_PATH_MAX];
        ssize_t n = readlinkat(parent, name, target, sizeof(target));
        error = n < 0 ? -errno : 0;
        close(parent);
        if (error != 0) break;
        if ((size_t) n > request->mode) n = (ssize_t) request->mode;
        reply(answer, n, target, (uint32_t) n, -1);
        return;
    }
    case SBX_MKDIR:
    case SBX_UNLINK: {
        error = decide(&c, base, path, request->path_len, SBX_WRITE, 0, request->op == SBX_MKDIR);
        if (error != 0) break;
        const char *name;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        int done = request->op == SBX_MKDIR ? mkdirat(parent, name, (mode_t) request->mode)
                                            : unlinkat(parent, name, request->flags & AT_REMOVEDIR);
        error = done == 0 ? 0 : -errno;
        close(parent);
        break;
    }
    case SBX_RENAME: {
        error = decide(&c, base, path, request->path_len, SBX_WRITE, 0, 0);
        if (error != 0) break;
        struct check c2 = c;
        error = decide(&c2, base2, path2, request->path2_len, SBX_WRITE, 0, 1);
        if (error != 0) break;
        const char *name, *name2;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        int parent2 = open_parent(&c2, SBX_WRITE, &name2);
        if (parent2 < 0) { close(parent); error = parent2; break; }
        long done = request->flags != 0
            ? syscall(__NR_renameat2, parent, name, parent2, name2, (unsigned) request->flags)
            : renameat(parent, name, parent2, name2);
        error = done == 0 ? 0 : -errno;
        close(parent);
        close(parent2);
        break;
    }
    case SBX_CHMOD: {
        error = decide(&c, base, path, request->path_len, SBX_WRITE, 1, 0);
        if (error != 0) break;
        const char *name;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        /* The name is the resolved file's own (no link is left to follow); the mode keeps permission bits only. */
        error = fchmodat(parent, name, (mode_t) (request->mode & 0777), 0) == 0 ? 0 : -errno;
        close(parent);
        break;
    }
    case SBX_UTIMENS: {
        error = decide(&c, base, path, request->path_len, SBX_WRITE, !(request->flags & AT_SYMLINK_NOFOLLOW), 0);
        if (error != 0) break;
        struct timespec times[2];
        if (request->path2_len) memcpy(times, path2, sizeof(times));
        const char *name;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        error = utimensat(parent, name, request->path2_len ? times : NULL, AT_SYMLINK_NOFOLLOW) == 0 ? 0 : -errno;
        close(parent);
        break;
    }
    case SBX_EXEC: {
        /* A program is run as it is read: the rules' read decides, on what the path resolves to. */
        error = decide(&c, base, path, request->path_len, SBX_READ, 1, 0);
        if (error != 0) break;
        /* Non-blocking, so a FIFO in a rule cannot hold the broker; the regular-file check below then refuses it. */
        int fd = open_decided(&c, O_RDONLY | O_NONBLOCK, 0, SBX_READ);
        if (fd < 0) { error = fd; break; }
        struct stat st;
        /*
         * As the kernel answers an exec of anything but a regular file, or of
         * one with no execute bit: sbx-exec maps the file itself, so the
         * kernel's own check never runs.
         */
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
            close(fd);
            error = -EACCES;
            break;
        }
        exe_record(pid, c.real);
        reply(answer, 0, NULL, 0, fd);
        close(fd);
        return;
    }
    case SBX_LINK: {
        /* Both names writable: a link to a file the process may only read would let it write that file. */
        error = decide(&c, base, path, request->path_len, SBX_WRITE, (request->flags & AT_SYMLINK_FOLLOW) != 0, 0);
        if (error != 0) break;
        struct check c2 = c;
        error = decide(&c2, base2, path2, request->path2_len, SBX_WRITE, 0, 1);
        if (error != 0) break;
        const char *name, *name2;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        int parent2 = open_parent(&c2, SBX_WRITE, &name2);
        if (parent2 < 0) { close(parent); error = parent2; break; }
        /* The existing name is already resolved, so nothing is left to follow. */
        error = linkat(parent, name, parent2, name2, 0) == 0 ? 0 : -errno;
        close(parent);
        close(parent2);
        break;
    }
    case SBX_SYMLINK: {
        /* The target is stored as given: whatever later follows it is decided then. */
        char target[SBX_PATH_MAX];
        memcpy(target, path2, request->path2_len);
        target[request->path2_len] = '\0';
        error = decide(&c, base, path, request->path_len, SBX_WRITE, 0, 1);
        if (error != 0) break;
        const char *name;
        int parent = open_parent(&c, SBX_WRITE, &name);
        if (parent < 0) { error = parent; break; }
        error = symlinkat(target, parent, name) == 0 ? 0 : -errno;
        close(parent);
        break;
    }
    case SBX_TRUNCATE: {
        int64_t length;
        memcpy(&length, path2, sizeof(length));
        if (length < 0) { error = -EINVAL; break; }
        error = decide(&c, base, path, request->path_len, SBX_WRITE, 1, 0);
        if (error != 0) break;
        /* Non-blocking, so a FIFO cannot hold the broker; the kernel then refuses to truncate it. */
        int fd = open_decided(&c, O_WRONLY | O_NONBLOCK, 0, SBX_WRITE);
        if (fd < 0) { error = fd; break; }
        error = ftruncate(fd, (off_t) length) == 0 ? 0 : -errno;
        close(fd);
        break;
    }
    case SBX_STATFS: {
        error = decide(&c, base, path, request->path_len, LOOKUP, 1, 0);
        if (error != 0) break;
        int fd = open_decided(&c, O_PATH, 0, LOOKUP);
        if (fd < 0) { error = fd; break; }
        struct statfs st;
        error = fstatfs(fd, &st) == 0 ? 0 : -errno;
        close(fd);
        if (error != 0) break;
        reply(answer, 0, &st, sizeof(st), -1);
        return;
    }
    default:
        error = -ENOSYS;
    }
    reply(answer, error, NULL, 0, -1);
}

/*
 * SBX_LIST: the confined process could not list a folder it holds (an
 * Android isolated process may not read a folder its app opened for it).
 * The descriptor itself came with the request; it is listed here only when
 * the folder it names may be read, and from that same open file
 * description, so the position the process sees moves with it.
 */
static void list_one(const struct sbx_policy *policy, const struct sbx_request *request, int *fds, pid_t pid,
                     int answer) {
    char base[SBX_PATH_MAX];
    if (!request->dirfd_sent || request->path_len != 1 || fd_path(fds[1], base) != 0 || base[0] != '/') {
        reply(answer, -EBADF, NULL, 0, -1);
        return;
    }
    struct check c;
    c.policy = policy;
    c.op = request->op;
    c.pid = pid;
    c.tid = request->tid;
    c.flags = 0;
    int error = decide(&c, base, ".", 1, SBX_READ, 1, 0);
    if (error != 0) { reply(answer, error, NULL, 0, -1); return; }
    if (strcmp(c.real, base) != 0) {
        /* The folder moved under its name after it was opened: decide on what the descriptor holds. */
        if (!permits(allowed(policy, base, pid), SBX_READ)) { reply(answer, -EACCES, NULL, 0, -1); return; }
    }
    static __thread char records[SBX_LIST_MAX];
    size_t asked = request->mode < SBX_LIST_MAX ? request->mode : SBX_LIST_MAX;
    long n = syscall(__NR_getdents64, fds[1], records, asked);
    if (n < 0) { reply(answer, -errno, NULL, 0, -1); return; }
    reply(answer, n, records, (uint32_t) n, -1);
}

/* ---- Sockets (SBX_LOCK_NET_BROKERED; docs/design.md, "A UID of its own for every confined process") ---- */

void sbx_policy_set_net(struct sbx_policy *policy, unsigned grants) {
    if (policy) policy->net = grants;
}

int sbx_policy_net_rule(struct sbx_policy *policy, const char *rule) {
    if (!policy) return -EINVAL;
    return netp_add(policy->netp, rule);
}

/* The grants in force: the host's, or in rule mode what the rules can allow (with the host's SBX_NET_DECIDE). */
static unsigned net_grants(const struct sbx_policy *policy) {
    if (!netp_active(policy->netp)) return policy->net;
    return netp_grants(policy->netp) | (policy->net & SBX_NET_DECIDE);
}

int sbx_policy_add_system_socket(struct sbx_policy *policy, const char *path, unsigned grant) {
    if (!policy || !path || path[0] != '/') return -EINVAL;
    if (strlen(path) >= sizeof(((struct sockaddr_un *) 0)->sun_path)) return -ENAMETOOLONG;
    if (policy->system_count >= SBX_SYSTEM_SOCKETS_MAX) return -ENOSPC;
    char *copy = strdup(path);
    if (!copy) return -ENOMEM;
    policy->system_paths[policy->system_count] = copy;
    policy->system_grants[policy->system_count] = grant;
    policy->system_count++;
    return 0;
}

/* An address in words for the decider and the audit: "203.0.113.5:443", "[2001:db8::1]:80", "*:8384", a path. */
static void address_words(const struct sockaddr *address, socklen_t length, char *out, size_t size) {
    char host[INET6_ADDRSTRLEN] = "?";
    if (address->sa_family == AF_INET && length >= (socklen_t) sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *) address;
        if (in->sin_addr.s_addr == htonl(INADDR_ANY)) strcpy(host, "*");
        else inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        snprintf(out, size, "%s:%u", host, (unsigned) ntohs(in->sin_port));
    } else if (address->sa_family == AF_INET6 && length >= (socklen_t) sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) address;
        if (IN6_IS_ADDR_UNSPECIFIED(&in6->sin6_addr)) snprintf(out, size, "*:%u", (unsigned) ntohs(in6->sin6_port));
        else {
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            snprintf(out, size, "[%s]:%u", host, (unsigned) ntohs(in6->sin6_port));
        }
    } else if (address->sa_family == AF_UNIX) {
        const struct sockaddr_un *un = (const struct sockaddr_un *) address;
        size_t n = length > (socklen_t) offsetof(struct sockaddr_un, sun_path) ? length - offsetof(struct sockaddr_un, sun_path) : 0;
        snprintf(out, size, "%.*s", (int) strnlen(un->sun_path, n), un->sun_path);
    } else {
        snprintf(out, size, "family %u", (unsigned) address->sa_family);
    }
}

static unsigned short port_of(const struct sockaddr *address) {
    if (address->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *) address)->sin_port);
    if (address->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *) address)->sin6_port);
    return 0;
}

/* The grants' verdict, then the decider's (on a refusal, or on every call with SBX_NET_DECIDE), then the audit. */
static int net_decide_rule(const struct sbx_policy *policy, uint16_t op, const char *words, pid_t pid, int verdict,
                           const char *rule) {
    struct sbx_access access = {.op = op_name(op), .asked = words, .resolved = words, .pid = pid, .rule_verdict = verdict,
                                .net_rule = rule};
    int result = verdict;
    if (policy->decide && (verdict != 0 || (policy->net & SBX_NET_DECIDE))) {
        int said = policy->decide(policy->decide_context, &access);
        if (said != SBX_KEEP) result = said > 0 ? 0 : said;
    }
    policy->audit(policy->audit_context, &access, result);
    return result;
}

static int net_decide(const struct sbx_policy *policy, uint16_t op, const char *words, pid_t pid, int verdict) {
    return net_decide_rule(policy, op, words, pid, verdict, NULL);
}

/* A rule's verdict through the decider and the audit: allow is 0; deny, ask and no rule are refusals the decider may turn. */
static int rule_decide(const struct sbx_policy *policy, uint16_t op, const char *words, pid_t pid, struct netp_verdict v) {
    return net_decide_rule(policy, op, words, pid, v.action == NETP_ALLOW ? 0 : -EACCES, v.rule);
}

/* A socket's protocol for the rules: NETP_TCP for a stream, NETP_UDP for a datagram, 0 for anything else. */
static unsigned socket_protocol(int fd) {
    int type = 0;
    socklen_t length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0) return 0;
    return type == SOCK_STREAM ? NETP_TCP : type == SOCK_DGRAM ? NETP_UDP : 0;
}

/*
 * A name the process asked for, decided and then resolved (docs/design.md,
 * "Names: DNS through the broker"): in rule mode by the rules, else by the
 * SBX_NET_RESOLVE grant; the decider and the audit see it as "resolve".
 */
struct lookup_context {
    const struct sbx_policy *policy;
    pid_t pid;
};

static int broker_lookup(void *argument, const char *name, int family, struct sockaddr_storage *out, int max) {
    const struct lookup_context *l = argument;
    const struct sbx_policy *policy = l->policy;
    int verdict;
    if (netp_active(policy->netp)) verdict = rule_decide(policy, SBX_RESOLVE, name, l->pid, netp_name(policy->netp, name));
    else verdict = net_decide(policy, SBX_RESOLVE, name, l->pid, (policy->net & SBX_NET_RESOLVE) ? 0 : -EACCES);
    if (verdict != 0) return -EACCES;
    return netp_resolve(policy->netp, name, family, out, max);
}

/* A blocking connect or accept, on a thread of its own: it holds up no other call, and touches no policy. */
/*
 * A blocking connect or accept runs on a detached thread of its own
 * (net_wait_thread). Without a cap one worker could pipeline thousands,
 * exhausting the broker's threads and descriptors and starving every other
 * worker it serves (review A-19). Two caps bound them: a per-connection
 * budget (conn_budget, one per serve_loop) so a single worker cannot
 * monopolise the broker, and a global ceiling so the broker as a whole stays
 * bounded whatever the number of connections. Past either, the blocking call
 * is answered EAGAIN, as a non-blocking socket past its resources would be.
 */
#define NET_WAIT_MAX_PER_CONN 32
#define NET_WAIT_MAX_TOTAL 256
static pthread_mutex_t net_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int net_wait_total;

struct conn_budget {
    int live;  /* net_wait threads this connection has running */
    int refs;  /* the connection, plus one per live net_wait thread */
};

static struct conn_budget *conn_budget_new(void) {
    struct conn_budget *b = calloc(1, sizeof(*b));
    if (b) b->refs = 1;
    return b;
}

/* Drops one reference and frees at the last. Safe on NULL. */
static void conn_budget_release(struct conn_budget *b) {
    if (!b) return;
    pthread_mutex_lock(&net_wait_lock);
    int remaining = --b->refs;
    pthread_mutex_unlock(&net_wait_lock);
    if (remaining == 0) free(b);
}

/* Reserves a net_wait slot against both caps, taking a reference for the thread; 0, or -EAGAIN when full. */
static int net_wait_reserve(struct conn_budget *b) {
    pthread_mutex_lock(&net_wait_lock);
    int ok = net_wait_total < NET_WAIT_MAX_TOTAL && (!b || b->live < NET_WAIT_MAX_PER_CONN);
    if (ok) {
        net_wait_total++;
        if (b) { b->live++; b->refs++; }
    }
    pthread_mutex_unlock(&net_wait_lock);
    return ok ? 0 : -EAGAIN;
}

/* Returns a reserved slot (the thread finished, or never started) and drops its reference. */
static void net_wait_unreserve(struct conn_budget *b) {
    pthread_mutex_lock(&net_wait_lock);
    net_wait_total--;
    int remaining = -1;
    if (b) { b->live--; remaining = --b->refs; }
    pthread_mutex_unlock(&net_wait_lock);
    if (b && remaining == 0) free(b);
}

/* What a broker thread of its own does (net_wait_thread). */
enum { WAIT_CONNECT, WAIT_ACCEPT, WAIT_SEND, WAIT_RESOLVE, WAIT_DNSPROXY, WAIT_DNS_TCP };

struct net_wait {
    int kind;
    struct conn_budget *budget;
    const struct sbx_policy *policy;  /* held: an accept's rules, a relay's or a lookup's */
    pid_t pid;
    int socket;   /* the process's socket (a duplicate), or a relay's end */
    int answer;   /* the request's answer socket (a duplicate), or -1 */
    struct sockaddr_storage address;
    socklen_t length;
    int flags;
    struct msghdr message;  /* WAIT_SEND: a copy, with its buffers */
    struct iovec part;
    int rights[SBX_SEND_RIGHTS_MAX];
    int right_count;
    char name[256];         /* WAIT_RESOLVE */
};

/* An accepted peer, under the in rules: 0, or a refusal (the connection is then closed). */
static int accept_allowed(const struct net_wait *w, int listening, const struct sockaddr_storage *peer, socklen_t length) {
    if (!w->policy || !netp_active(w->policy->netp)) return 0;
    int domain = peer->ss_family;
    if (domain != AF_INET && domain != AF_INET6) return 0;
    struct netp_addr from;
    if (netp_addr_of((const struct sockaddr *) peer, length, 0, &from) != 0) return -EACCES;
    struct sockaddr_storage local;
    socklen_t local_length = sizeof(local);
    unsigned port = 0;
    struct netp_addr here;
    if (getsockname(listening, (struct sockaddr *) &local, &local_length) == 0 &&
        netp_addr_of((struct sockaddr *) &local, local_length, 0, &here) == 0) {
        port = here.port;
    }
    char words[200], address[160];
    address_words((const struct sockaddr *) peer, length, address, sizeof(address));
    snprintf(words, sizeof(words), "%s to port %u", address, port);
    return rule_decide(w->policy, SBX_ACCEPT, words, w->pid, netp_in(w->policy->netp, NETP_TCP, port, &from));
}

static void *net_wait_thread(void *argument) {
    struct net_wait *w = argument;
    if (w->kind == WAIT_CONNECT) {
        int r = connect(w->socket, (const struct sockaddr *) &w->address, w->length);
        reply(w->answer, r == 0 ? 0 : -errno, NULL, 0, -1);
    } else if (w->kind == WAIT_ACCEPT) {
        for (;;) {
            struct sockaddr_storage peer;
            socklen_t length = sizeof(peer);
            memset(&peer, 0, sizeof(peer));
            int connection = accept4(w->socket, (struct sockaddr *) &peer, &length, (w->flags & SOCK_NONBLOCK) | SOCK_CLOEXEC);
            if (connection < 0) {
                reply(w->answer, -errno, NULL, 0, -1);
                break;
            }
            if (length > (socklen_t) sizeof(peer)) length = sizeof(peer);
            if (accept_allowed(w, w->socket, &peer, length) != 0) {
                /* A peer the rules refuse never reaches the process; the next one is waited for. */
                close(connection);
                continue;
            }
            reply(w->answer, (int64_t) length, &peer, (uint32_t) length, connection);
            close(connection);
            break;
        }
    } else if (w->kind == WAIT_SEND) {
        ssize_t sent;
        do sent = sendmsg(w->socket, &w->message, w->flags);
        while (sent < 0 && errno == EINTR);
        reply(w->answer, sent < 0 ? -errno : sent, NULL, 0, -1);
        free(w->part.iov_base);
        free(w->message.msg_name);
        free(w->message.msg_control);
        for (int i = 0; i < w->right_count; i++) close(w->rights[i]);
        w->part.iov_base = w->message.msg_name = w->message.msg_control = NULL;
        w->right_count = 0;
    } else if (w->kind == WAIT_RESOLVE) {
        struct sockaddr_storage found[SBX_RESOLVE_MAX];
        struct lookup_context l = {w->policy, w->pid};
        int max = w->flags < SBX_RESOLVE_MAX ? w->flags : SBX_RESOLVE_MAX;
        int n = broker_lookup(&l, w->name, (int) w->length, found, max);
        reply(w->answer, n, n > 0 ? found : NULL, n > 0 ? (uint32_t) (n * sizeof(found[0])) : 0, -1);
    } else {
        struct lookup_context l = {w->policy, w->pid};
        if (w->kind == WAIT_DNSPROXY) netp_serve_dnsproxy(w->socket, broker_lookup, &l);
        else netp_serve_dns_tcp(w->socket, broker_lookup, &l);
    }
    struct conn_budget *budget = w->budget;
    if (w->socket >= 0) close(w->socket);
    if (w->answer >= 0) close(w->answer);
    if (w->policy) policy_release(w->policy);
    free(w);
    net_wait_unreserve(budget);
    return NULL;
}

static void net_wait_free(struct net_wait *w);

/* Starts w (filled but for its budget) on a thread of its own; on failure answers and frees it. */
static void net_wait_launch(struct net_wait *w, int answer, struct conn_budget *budget) {
    if (net_wait_reserve(budget) != 0) {
        if (answer >= 0) reply(answer, -EAGAIN, NULL, 0, -1);
        goto undo;
    }
    w->budget = budget;
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    int error = pthread_create(&thread, &attributes, net_wait_thread, w);
    pthread_attr_destroy(&attributes);
    if (error == 0) return;
    if (answer >= 0) reply(answer, -error, NULL, 0, -1);
    net_wait_unreserve(budget);
undo:
    net_wait_free(w);
}

/* Frees a net_wait that never ran, with everything it holds. */
static void net_wait_free(struct net_wait *w) {
    if (w->socket >= 0) close(w->socket);
    if (w->answer >= 0) close(w->answer);
    if (w->policy) policy_release(w->policy);
    free(w->part.iov_base);
    free(w->message.msg_name);
    free(w->message.msg_control);
    for (int i = 0; i < w->right_count; i++) close(w->rights[i]);
    free(w);
}

/* A new net_wait with duplicates of socket_fd and answer (either may be -1); NULL (answered ENOMEM) on failure. */
static struct net_wait *net_wait_new(int kind, int socket_fd, int answer) {
    struct net_wait *w = calloc(1, sizeof(*w));
    int s = socket_fd >= 0 ? fcntl(socket_fd, F_DUPFD_CLOEXEC, 0) : -1;
    int a = answer >= 0 ? fcntl(answer, F_DUPFD_CLOEXEC, 0) : -1;
    if (!w || (socket_fd >= 0 && s < 0) || (answer >= 0 && a < 0)) {
        if (answer >= 0) reply(answer, -ENOMEM, NULL, 0, -1);
        if (s >= 0) close(s);
        if (a >= 0) close(a);
        free(w);
        return NULL;
    }
    w->kind = kind;
    w->socket = s;
    w->answer = a;
    return w;
}

static void net_wait_start(int kind, int socket_fd, int answer, const void *address, socklen_t length, int flags,
                           const struct sbx_policy *policy, pid_t pid, struct conn_budget *budget) {
    struct net_wait *w = net_wait_new(kind, socket_fd, answer);
    if (!w) return;
    if (address && length > 0) memcpy(&w->address, address, (size_t) length);
    w->length = length;
    w->flags = flags;
    w->pid = pid;
    if (policy) w->policy = policy_hold(policy);
    net_wait_launch(w, answer, budget);
}

/*
 * A name server the broker answers itself, for the process: a stream
 * socketpair whose one end is handed over (in place of the system resolver's
 * socket, or a TCP socket to port 53), the other served on a thread of its
 * own. The handed end keeps the process socket's non-blocking mode.
 */
static void relay_start(int kind, int subject, int answer, const struct sbx_policy *policy, pid_t pid,
                        struct conn_budget *budget) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) { reply(answer, -errno, NULL, 0, -1); return; }
    if (fcntl(subject, F_GETFL) & O_NONBLOCK) fcntl(pair[0], F_SETFL, fcntl(pair[0], F_GETFL) | O_NONBLOCK);
    struct net_wait *w = net_wait_new(kind, -1, -1);
    if (!w) {
        reply(answer, -ENOMEM, NULL, 0, -1);
        close(pair[0]);
        close(pair[1]);
        return;
    }
    w->socket = pair[1];
    w->pid = pid;
    w->policy = policy_hold(policy);
    if (net_wait_reserve(budget) != 0) {
        reply(answer, -EAGAIN, NULL, 0, -1);
        close(pair[0]);
        close(pair[1]);
        policy_release(w->policy);
        free(w);
        return;
    }
    net_wait_unreserve(budget);  /* net_wait_launch reserves again; checked here so nothing is half-handed */
    reply(answer, 0, NULL, 0, pair[0]);
    close(pair[0]);
    net_wait_launch(w, -1, budget);
}

static int socket_domain(int fd);

int sbx_policy_add_unix_name(struct sbx_policy *policy, const char *name, unsigned mode) {
    size_t length = name ? strlen(name) : 0;
    if (!policy || length == 0 || (mode & ~MODE_BITS) || mode == SBX_DENY) return -EINVAL;
    if (length >= sizeof(((struct sockaddr_un *) 0)->sun_path)) return -ENAMETOOLONG;
    if (policy->unix_name_count >= SBX_UNIX_NAMES_MAX) return -ENOSPC;
    char *copy = strdup(name);
    if (!copy) return -ENOMEM;
    policy->unix_names[policy->unix_name_count] = copy;
    policy->unix_name_lengths[policy->unix_name_count] = length;
    policy->unix_name_modes[policy->unix_name_count] = mode;
    policy->unix_name_count++;
    return 0;
}

/*
 * SBX_LOCK_UNIX: bind or connect of the process's own Unix socket (fds[1]).
 * A path is decided like any other (bind: writable, and created; connect:
 * readable, following links) and reached through the checked parent's
 * descriptor, as /proc/self/fd/<parent>/<name>: no race with a swapped
 * folder, and no limit from sun_path's length on the real path. An
 * abstract name needs sbx_policy_add_unix_name; an empty address (bind
 * with the family alone) asks the kernel for a fresh abstract name, which
 * reaches nothing.
 */
static void unix_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                     size_t body_len, int *fds, int fd_count, pid_t pid) {
    int answer = fds[0];
    int binding = request->op == SBX_UNIX_BIND;
    size_t offset = offsetof(struct sockaddr_un, sun_path);
    if (request->path2_len != 0 || request->path_len != body_len || body_len < sizeof(sa_family_t) ||
        body_len > sizeof(struct sockaddr_un) || !request->dirfd_sent ||
        fd_count != 1 + request->dirfd_sent + request->dirfd2_sent) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    int subject = fds[1];
    if (socket_domain(subject) != AF_UNIX) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    memcpy(&address, body, body_len);
    if (address.sun_family != AF_UNIX) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    size_t n = body_len > offset ? body_len - offset : 0;
    int result;
    if (n == 0) {
        /* bind with the family alone: the kernel picks an unused abstract name. connect needs a name. */
        result = binding ? (bind(subject, (struct sockaddr *) &address, (socklen_t) body_len) == 0 ? 0 : -errno) : -EINVAL;
        reply(answer, result, NULL, 0, -1);
        return;
    }
    unsigned need = binding ? SBX_WRITE : SBX_READ;
    if (address.sun_path[0] == '\0') {
        /* An abstract name: only one the policy lists. */
        char words[2 * sizeof(address.sun_path) + 2];
        words[0] = '@';
        size_t w = 1;
        for (size_t i = 1; i < n && w + 1 < sizeof(words); i++) words[w++] = address.sun_path[i] ? address.sun_path[i] : '@';
        words[w] = '\0';
        unsigned mode = SBX_DENY;
        for (unsigned i = 0; i < policy->unix_name_count; i++) {
            if (policy->unix_name_lengths[i] == n - 1 && memcmp(policy->unix_names[i], address.sun_path + 1, n - 1) == 0) {
                mode = policy->unix_name_modes[i];
            }
        }
        result = net_decide(policy, request->op, words, pid, permits(mode, need) ? 0 : -EACCES);
        if (result == 0) {
            int done = binding ? bind(subject, (struct sockaddr *) &address, (socklen_t) body_len)
                               : connect(subject, (struct sockaddr *) &address, (socklen_t) body_len);
            result = done == 0 ? 0 : -errno;
        }
        reply(answer, result, NULL, 0, -1);
        return;
    }
    size_t length = strnlen(address.sun_path, n);
    char base[SBX_PATH_MAX] = "/";
    if (request->dirfd2_sent) {
        if (fd_path(fds[2], base) != 0 || base[0] != '/') { reply(answer, -ENOTDIR, NULL, 0, -1); return; }
    }
    struct check c;
    c.policy = policy;
    c.op = request->op;
    c.pid = pid;
    c.tid = request->tid;
    c.flags = 0;
    result = decide(&c, base, address.sun_path, length, need, !binding, binding);
    if (result == 0) {
        const char *name;
        int parent = open_parent(&c, need, &name);
        if (parent < 0) {
            result = parent;
        } else {
            struct sockaddr_un via;
            memset(&via, 0, sizeof(via));
            via.sun_family = AF_UNIX;
            int written = snprintf(via.sun_path, sizeof(via.sun_path), "/proc/self/fd/%d/%s", parent, name);
            if (written < 0 || (size_t) written >= sizeof(via.sun_path)) {
                result = -ENAMETOOLONG;
            } else {
                int done = binding ? bind(subject, (struct sockaddr *) &via, sizeof(via))
                                   : connect(subject, (struct sockaddr *) &via, sizeof(via));
                result = done == 0 ? 0 : -errno;
            }
            close(parent);
        }
    }
    reply(answer, result, NULL, 0, -1);
}

/* The events an inotify mark may ask for, and the flags it may carry; nothing else reaches the kernel. */
#define WATCH_EVENTS IN_ALL_EVENTS
#define WATCH_FLAGS (IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_ADD | IN_ONESHOT | IN_MASK_CREATE)
/* A folder's own events: they carry no name. */
#define WATCH_SELF (IN_DELETE_SELF | IN_MOVE_SELF)

/*
 * Whether every name inside folder (a decided real path) is one the
 * process may read: no rule beneath it grants less, and it is not /proc,
 * whose entries the rules decide per process.
 */
static int names_all_readable(const struct sbx_policy *policy, const char *folder) {
    size_t length = strlen(folder);
    if (strncmp(folder, "/proc", 5) == 0 && (folder[5] == '\0' || folder[5] == '/')) return 0;
    for (size_t i = 0; i < policy->count; i++) {
        const struct rule *r = &policy->rules[i];
        if (r->length > length && within(r->path, folder, length) && !permits(r->mode, SBX_READ)) return 0;
    }
    return 1;
}

/*
 * SBX_LOCK_WATCH: an inotify mark on the process's own inotify descriptor
 * (docs/design.md, "SBX_LOCK_WATCH"). The path is decided as a read of what
 * it resolves to (the last link followed unless IN_DONT_FOLLOW) and the mark
 * is added through the checked folder, as /proc/self/fd/<parent>/<name>, with
 * IN_DONT_FOLLOW, so it lands on what was decided. The mask keeps the
 * standard events and flags. On a folder holding a name the process may not
 * read, it keeps only the folder's own events, which name nothing; a mark
 * that would then ask for nothing watches for the folder's deletion, so the
 * call still succeeds and the process sees fewer events, never other names.
 */
static void watch_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                      size_t body_len, int *fds, int fd_count, pid_t pid) {
    int answer = fds[0];
    if (request->path2_len != 0 || request->path_len != body_len || body_len == 0 || body_len >= SBX_PATH_MAX ||
        !request->dirfd_sent || fd_count != 1 + request->dirfd_sent + request->dirfd2_sent) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    char kind[SBX_PATH_MAX];
    if (fd_path(fds[1], kind) != 0 || strcmp(kind, "anon_inode:inotify") != 0) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    uint32_t mask = request->mode;
    if ((mask & WATCH_EVENTS) == 0 || (mask & ~(uint32_t) (WATCH_EVENTS | WATCH_FLAGS)) != 0) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    char base[SBX_PATH_MAX] = "/";
    if (request->dirfd2_sent) {
        if (fd_path(fds[2], base) != 0 || base[0] != '/') { reply(answer, -ENOTDIR, NULL, 0, -1); return; }
    }
    struct check c;
    c.policy = policy;
    c.op = request->op;
    c.pid = pid;
    c.tid = request->tid;
    c.flags = (int) mask;
    int result = decide(&c, base, body, body_len, SBX_READ, !(mask & IN_DONT_FOLLOW), 0);
    if (result == 0 && c.real[0] == '\0') result = -ENOENT;
    if (result == 0) {
        const char *name;
        int parent = open_parent(&c, SBX_READ, &name);
        if (parent < 0) {
            result = parent;
        } else {
            struct stat st;
            if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                result = -errno;
            } else {
                if (S_ISDIR(st.st_mode) && !names_all_readable(policy, c.real)) {
                    uint32_t events = mask & WATCH_SELF;
                    mask = (mask & WATCH_FLAGS) | (events ? events : IN_DELETE_SELF);
                }
                char via[SBX_PATH_MAX];
                int written = snprintf(via, sizeof(via), "/proc/self/fd/%d/%s", parent, name);
                if (written < 0 || (size_t) written >= sizeof(via)) {
                    result = -ENAMETOOLONG;
                } else {
                    int wd = inotify_add_watch(fds[1], via, mask | IN_DONT_FOLLOW);
                    result = wd >= 0 ? wd : -errno;
                }
            }
            close(parent);
        }
    }
    reply(answer, result, NULL, 0, -1);
}

static int socket_domain(int fd) {
    int domain = 0;
    socklen_t length = sizeof(domain);
    return getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 ? domain : -errno;
}

static int read_int(const char *body, size_t body_len, int *out) {
    if (body_len != sizeof(int)) return -EINVAL;
    memcpy(out, body, sizeof(int));
    return 0;
}

/* The words for an inet address and protocol: "udp 203.0.113.5:443". */
static void proto_words(unsigned protocol, const struct sockaddr *address, socklen_t length, char *out, size_t size) {
    char where[160];
    address_words(address, length, where, sizeof(where));
    snprintf(out, size, "%s %s", protocol == NETP_UDP ? "udp" : "tcp", where);
}

static const char dns_rule[] = "DNS goes through the broker";

static void net_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                    size_t body_len, int *fds, int fd_count, pid_t pid, struct conn_budget *budget) {
    int answer = fds[0];
    if (request->path2_len != 0 || request->path_len != body_len || body_len == 0 ||
        body_len > sizeof(struct sockaddr_storage) || fd_count != 1 + request->dirfd_sent ||
        request->dirfd2_sent || request->dirfd_sent != (request->op != SBX_SOCKET)) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    int ruled = netp_active(policy->netp);
    unsigned grants = net_grants(policy);
    char words[200];
    if (request->op == SBX_SOCKET) {
        int protocol;
        int domain = request->flags;
        int type = (int) request->mode;
        int base = type & 0xf;
        if (read_int(body, body_len, &protocol) != 0) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        snprintf(words, sizeof(words), "%s %s", domain == AF_INET6 ? "inet6" : "inet", base == SOCK_DGRAM ? "udp" : "tcp");
        int verdict = (domain != AF_INET && domain != AF_INET6) || (base != SOCK_STREAM && base != SOCK_DGRAM) ? -EAFNOSUPPORT
                    : (grants & (SBX_NET_CONNECT | SBX_NET_LISTEN)) ? 0 : -EACCES;
        if (verdict != -EAFNOSUPPORT) verdict = net_decide(policy, request->op, words, pid, verdict);
        if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
        int made = socket(domain, base | (type & SOCK_NONBLOCK) | SOCK_CLOEXEC, protocol);
        if (made < 0) { reply(answer, -errno, NULL, 0, -1); return; }
        reply(answer, 0, NULL, 0, made);
        close(made);
        return;
    }
    int subject = fds[1];
    int domain = socket_domain(subject);
    if (domain < 0) { reply(answer, domain == -ENOTSOCK ? -ENOTSOCK : domain, NULL, 0, -1); return; }
    if (request->op == SBX_CONNECT && domain == AF_UNIX) {
        /* A system socket the process may have is connected here, under the broker's identity; any other path is the caller's own. */
        struct sockaddr_un un;
        memset(&un, 0, sizeof(un));
        memcpy(&un, body, body_len < sizeof(un) ? body_len : sizeof(un));
        size_t n = body_len > offsetof(struct sockaddr_un, sun_path) ? body_len - offsetof(struct sockaddr_un, sun_path) : 0;
        if (n > sizeof(un.sun_path)) n = sizeof(un.sun_path);
        char path[sizeof(un.sun_path) + 1];
        memcpy(path, un.sun_path, n);
        path[n] = '\0';
        int found = -1;
        for (unsigned i = 0; path[0] == '/' && i < policy->system_count; i++) {
            if (strcmp(path, policy->system_paths[i]) == 0) found = (int) i;
        }
        if (found < 0) { reply(answer, -ENOSYS, NULL, 0, -1); return; }
        unsigned grant = policy->system_grants[found];
        int verdict = grant == 0 || (grants & grant) ? 0 : -EACCES;
        int type = 0;
        socklen_t length = sizeof(type);
        if (getsockopt(subject, SOL_SOCKET, SO_TYPE, &type, &length) != 0) { reply(answer, -errno, NULL, 0, -1); return; }
        if (ruled && (grant & SBX_NET_RESOLVE) && type == SOCK_STREAM) {
            /* Rule mode: the system resolver is the broker's own, which answers netd's protocol itself. */
            snprintf(words, sizeof(words), "%s (answered by the broker)", path);
            verdict = net_decide_rule(policy, request->op, words, pid, verdict, verdict == 0 ? NULL : dns_rule);
            if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
            relay_start(WAIT_DNSPROXY, subject, answer, policy, pid, budget);
            return;
        }
        verdict = net_decide(policy, request->op, path, pid, verdict);
        if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
        int nonblocking = (fcntl(subject, F_GETFL) & O_NONBLOCK) ? SOCK_NONBLOCK : 0;
        int made = socket(AF_UNIX, type | nonblocking | SOCK_CLOEXEC, 0);
        if (made < 0) { reply(answer, -errno, NULL, 0, -1); return; }
        struct sockaddr_un target = {.sun_family = AF_UNIX};
        memcpy(target.sun_path, path, strlen(path) + 1);
        if (connect(made, (struct sockaddr *) &target, sizeof(target)) != 0 && errno != EINPROGRESS) {
            int error = -errno;
            close(made);
            reply(answer, error, NULL, 0, -1);
            return;
        }
        reply(answer, 0, NULL, 0, made);
        close(made);
        return;
    }
    if (request->op == SBX_ACCEPT && domain == AF_UNIX) {
        /* SBX_LOCK_NET_FILTER sends every accept here: a Unix socket's is the kernel's, made on the same socket. */
        int value;
        if (read_int(body, body_len, &value) != 0) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        net_wait_start(WAIT_ACCEPT, subject, answer, NULL, 0, value, NULL, pid, budget);
        return;
    }
    if (domain != AF_INET && domain != AF_INET6) {
        /* The process's own Unix socket: not the broker's to bind or listen on. */
        reply(answer, -EACCES, NULL, 0, -1);
        return;
    }
    unsigned protocol = socket_protocol(subject);
    if (request->op == SBX_LISTEN || request->op == SBX_ACCEPT) {
        int value;
        if (read_int(body, body_len, &value) != 0) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        struct sockaddr_storage local;
        socklen_t length = sizeof(local);
        memset(&local, 0, sizeof(local));
        struct netp_addr here = {0};
        int bound = getsockname(subject, (struct sockaddr *) &local, &length) == 0 &&
                    netp_addr_of((struct sockaddr *) &local, length, 0, &here) == 0 && here.port != 0;
        if (bound) address_words((struct sockaddr *) &local, length, words, sizeof(words));
        else snprintf(words, sizeof(words), "unbound");
        int verdict;
        if (ruled) {
            /* The port must be one an in rule allows; an unbound socket would take a port no rule named. */
            struct netp_verdict v = {NETP_NONE, "no rule"};
            if (bound) v = netp_bind(policy->netp, protocol ? protocol : NETP_TCP, here.port, NULL);
            verdict = rule_decide(policy, request->op, words, pid, v);
        } else {
            verdict = net_decide(policy, request->op, words, pid, (grants & SBX_NET_LISTEN) ? 0 : -EACCES);
        }
        if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
        if (request->op == SBX_LISTEN) {
            reply(answer, listen(subject, value) == 0 ? 0 : -errno, NULL, 0, -1);
            return;
        }
        net_wait_start(WAIT_ACCEPT, subject, answer, NULL, 0, value, ruled ? policy : NULL, pid, budget);
        return;
    }
    /* connect or bind: an inet address of the socket's own family. */
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    memcpy(&address, body, body_len);
    socklen_t length = (socklen_t) body_len;
    int fits = (address.ss_family == AF_INET && length >= (socklen_t) sizeof(struct sockaddr_in)) ||
               (address.ss_family == AF_INET6 && length >= (socklen_t) sizeof(struct sockaddr_in6)) ||
               (request->op == SBX_CONNECT && address.ss_family == AF_UNSPEC);
    if (!fits) { reply(answer, address.ss_family == AF_UNSPEC ? -EINVAL : -EAFNOSUPPORT, NULL, 0, -1); return; }
    address_words((struct sockaddr *) &address, length, words, sizeof(words));
    int verdict;
    if (request->op == SBX_BIND) {
        unsigned port = port_of((struct sockaddr *) &address);
        if (ruled) {
            struct netp_verdict v;
            if (port == 0) {
                /* A port of the system's choosing is a client's: allowed when the rules can allow going out. */
                v.action = (grants & SBX_NET_CONNECT) ? NETP_ALLOW : NETP_NONE;
                v.rule = (grants & SBX_NET_CONNECT) ? "a client's own port (an out rule)" : "no rule";
            } else {
                int loopback_only = 0;
                v = netp_bind(policy->netp, protocol ? protocol : NETP_TCP, port, &loopback_only);
                struct netp_addr at;
                static const uint8_t zero[16];
                if (loopback_only && netp_addr_of((struct sockaddr *) &address, length, 0, &at) == 0 &&
                    memcmp(at.a, zero, at.family == AF_INET ? 4 : 16) == 0) {
                    /* Every rule for this port is loopback's: the wildcard bind is made on loopback, never the network. */
                    if (address.ss_family == AF_INET) {
                        ((struct sockaddr_in *) &address)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    } else {
                        ((struct sockaddr_in6 *) &address)->sin6_addr = in6addr_loopback;
                    }
                    size_t used = strlen(words);
                    snprintf(words + used, sizeof(words) - used, " (made on loopback)");
                }
            }
            verdict = rule_decide(policy, request->op, words, pid, v);
        } else {
            /* A port of the system's choosing (0) is what a client binds; a named port is listening. */
            unsigned need = port == 0 ? (SBX_NET_CONNECT | SBX_NET_LISTEN) : SBX_NET_LISTEN;
            verdict = net_decide(policy, request->op, words, pid, (grants & need) ? 0 : -EACCES);
        }
        if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
        reply(answer, bind(subject, (struct sockaddr *) &address, length) == 0 ? 0 : -errno, NULL, 0, -1);
        return;
    }
    if (ruled && address.ss_family != AF_UNSPEC) {
        struct netp_addr to;
        if (netp_addr_of((struct sockaddr *) &address, length, 1, &to) != 0) { reply(answer, -EAFNOSUPPORT, NULL, 0, -1); return; }
        proto_words(protocol, (struct sockaddr *) &address, length, words, sizeof(words));
        if (to.port == 53) {
            /* Names go through the broker: a TCP name server is the broker's own; UDP to port 53 is refused. */
            if (protocol == NETP_TCP) {
                size_t used = strlen(words);
                snprintf(words + used, sizeof(words) - used, " (answered by the broker)");
                verdict = net_decide_rule(policy, request->op, words, pid, (grants & SBX_NET_RESOLVE) ? 0 : -EACCES, dns_rule);
                if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
                relay_start(WAIT_DNS_TCP, subject, answer, policy, pid, budget);
                return;
            }
            verdict = net_decide_rule(policy, request->op, words, pid, -EACCES, dns_rule);
        } else {
            verdict = rule_decide(policy, request->op, words, pid, netp_out(policy->netp, protocol ? protocol : NETP_TCP, &to));
        }
    } else {
        verdict = net_decide(policy, request->op, words, pid, (grants & SBX_NET_CONNECT) ? 0 : -EACCES);
    }
    if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
    net_wait_start(WAIT_CONNECT, subject, answer, &address, length, 0, NULL, pid, budget);
}

/*
 * SBX_SEND (SBX_LOCK_NET_FILTER): a send the handler could not make itself,
 * because it names an address, carries control data or gathers a datagram.
 * The address is decided like a connect's (a datagram's destination; a
 * stream ignores one); the call is made on the process's own socket.
 */
static void send_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body, size_t body_len,
                     int *fds, int fd_count, pid_t pid, struct conn_budget *budget) {
    int answer = fds[0];
    struct sbx_send_head head;
    if (request->path_len < sizeof(head) || (size_t) request->path_len + request->path2_len != body_len ||
        request->path2_len > SBX_SEND_MAX || request->dirfd_sent != 1 || request->dirfd2_sent || fd_count < 2) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    memcpy(&head, body, sizeof(head));
    if (head.addr_len > sizeof(struct sockaddr_storage) || head.control_len > SBX_SEND_CONTROL_MAX ||
        sizeof(head) + head.addr_len + head.control_len != request->path_len || head.rights > SBX_SEND_RIGHTS_MAX ||
        (int) head.rights != fd_count - 2) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    const char *address_bytes = body + sizeof(head);
    const char *control_bytes = address_bytes + head.addr_len;
    const char *payload = body + request->path_len;
    int subject = fds[1];
    int domain = socket_domain(subject);
    if (domain < 0) { reply(answer, domain, NULL, 0, -1); return; }
    unsigned protocol = socket_protocol(subject);
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    socklen_t address_length = head.addr_len;
    if (head.addr_len) memcpy(&address, address_bytes, head.addr_len);
    if (head.addr_len && protocol == NETP_TCP) address_length = 0;  /* a stream ignores the address (MSG_FASTOPEN is refused) */
    if (address_length) {
        char words[200];
        int verdict;
        if (domain == AF_UNIX) {
            /* A named Unix datagram: only to a system socket the process may have. */
            struct sockaddr_un *un = (struct sockaddr_un *) &address;
            size_t n = address_length > offsetof(struct sockaddr_un, sun_path) ? address_length - offsetof(struct sockaddr_un, sun_path) : 0;
            char path[sizeof(un->sun_path) + 1];
            if (n > sizeof(un->sun_path)) n = sizeof(un->sun_path);
            memcpy(path, un->sun_path, n);
            path[n] = '\0';
            verdict = -EACCES;
            for (unsigned i = 0; path[0] == '/' && i < policy->system_count; i++) {
                if (strcmp(path, policy->system_paths[i]) == 0 &&
                    (policy->system_grants[i] == 0 || (net_grants(policy) & policy->system_grants[i]))) {
                    verdict = 0;
                }
            }
            verdict = net_decide(policy, SBX_SEND, path[0] ? path : "an unnamed Unix address", pid, verdict);
        } else if (domain == AF_INET || domain == AF_INET6) {
            struct netp_addr to;
            if (netp_addr_of((struct sockaddr *) &address, address_length, 1, &to) != 0) {
                reply(answer, -EAFNOSUPPORT, NULL, 0, -1);
                return;
            }
            proto_words(protocol, (struct sockaddr *) &address, address_length, words, sizeof(words));
            if (!netp_active(policy->netp)) {
                verdict = net_decide(policy, SBX_SEND, words, pid, (policy->net & SBX_NET_CONNECT) ? 0 : -EACCES);
            } else if (to.port == 53) {
                verdict = net_decide_rule(policy, SBX_SEND, words, pid, -EACCES, dns_rule);
            } else {
                verdict = rule_decide(policy, SBX_SEND, words, pid, netp_out(policy->netp, protocol ? protocol : NETP_UDP, &to));
            }
        } else {
            verdict = -EAFNOSUPPORT;
        }
        if (verdict != 0) { reply(answer, verdict, NULL, 0, -1); return; }
    }
    /* Control: SCM_RIGHTS rebuilt from the descriptors that came, then the other messages, checked. */
    for (size_t at = 0; at < head.control_len;) {
        struct cmsghdr c;
        if (head.control_len - at < sizeof(c)) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        memcpy(&c, control_bytes + at, sizeof(c));
        if (c.cmsg_len < sizeof(c) || c.cmsg_len > head.control_len - at || c.cmsg_level == SOL_SOCKET) {
            reply(answer, -EINVAL, NULL, 0, -1);
            return;
        }
        at += CMSG_ALIGN(c.cmsg_len);
    }
    size_t rights_space = head.rights ? CMSG_SPACE(sizeof(int) * head.rights) : 0;
    size_t control_size = rights_space + head.control_len;
    char *control = control_size ? calloc(1, control_size) : NULL;
    if (control_size && !control) { reply(answer, -ENOMEM, NULL, 0, -1); return; }
    if (head.rights) {
        struct cmsghdr *c = (struct cmsghdr *) control;
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * head.rights);
        memcpy(CMSG_DATA(c), fds + 2, sizeof(int) * head.rights);
    }
    if (head.control_len) memcpy(control + rights_space, control_bytes, head.control_len);
    struct iovec part = {(void *) payload, request->path2_len};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = address_length ? &address : NULL;
    message.msg_namelen = address_length;
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = control_size;
    /* The broker's serve thread never blocks on the process's socket, and never takes its SIGPIPE. */
    int flags = (request->flags & ~(MSG_FASTOPEN | MSG_DONTWAIT)) | MSG_NOSIGNAL;
    ssize_t sent = sendmsg(subject, &message, flags | MSG_DONTWAIT);
    int wants_wait = sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && !(request->flags & MSG_DONTWAIT) &&
                     !(fcntl(subject, F_GETFL) & O_NONBLOCK);
    if (!wants_wait) {
        reply(answer, sent < 0 ? -errno : sent, NULL, 0, -1);
        free(control);
        return;
    }
    /* A blocking send with a full buffer: it waits on a thread of its own, with copies of everything. */
    struct net_wait *w = net_wait_new(WAIT_SEND, subject, answer);
    if (!w) { free(control); return; }
    w->part.iov_base = malloc(request->path2_len ? request->path2_len : 1);
    w->part.iov_len = request->path2_len;
    if (address_length) w->message.msg_name = malloc(address_length);
    int ok = w->part.iov_base && (!address_length || w->message.msg_name);
    for (unsigned i = 0; ok && i < head.rights; i++) {
        w->rights[i] = fcntl(fds[2 + i], F_DUPFD_CLOEXEC, 0);
        if (w->rights[i] < 0) ok = 0;
        else w->right_count++;
    }
    if (!ok) {
        reply(answer, -ENOMEM, NULL, 0, -1);
        free(control);
        net_wait_free(w);
        return;
    }
    memcpy(w->part.iov_base, payload, request->path2_len);
    if (address_length) memcpy(w->message.msg_name, &address, address_length);
    w->message.msg_namelen = address_length;
    w->message.msg_iov = &w->part;
    w->message.msg_iovlen = 1;
    if (head.rights) memcpy(CMSG_DATA((struct cmsghdr *) control), w->rights, sizeof(int) * head.rights);
    w->message.msg_control = control;
    w->message.msg_controllen = control_size;
    w->flags = flags;
    net_wait_launch(w, w->answer, budget);
}

/* SBX_RESOLVE (sbx_resolve): a name, decided and resolved on a thread of its own, since a lookup can take seconds. */
static void resolve_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                        size_t body_len, int *fds, int fd_count, pid_t pid, struct conn_budget *budget) {
    int answer = fds[0];
    if (fd_count != 1 || request->path2_len != 0 || request->path_len != body_len || body_len == 0 || body_len > 253 ||
        memchr(body, '\0', body_len) || request->dirfd_sent || request->dirfd2_sent) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    struct net_wait *w = net_wait_new(WAIT_RESOLVE, -1, answer);
    if (!w) return;
    memcpy(w->name, body, body_len);
    w->name[body_len] = '\0';
    w->length = (socklen_t) request->mode;  /* the family */
    w->flags = request->flags > 0 ? request->flags : SBX_RESOLVE_MAX;
    w->pid = pid;
    w->policy = policy_hold(policy);
    net_wait_launch(w, w->answer, budget);
}

const char *sbx_syscall_name(long nr) {
    switch (nr) {
#define NAME(call) case __NR_##call: return #call;
#ifdef __NR_execve
    NAME(execve)
#endif
#ifdef __NR_execveat
    NAME(execveat)
#endif
    NAME(socket) NAME(connect) NAME(bind) NAME(ptrace) NAME(process_vm_readv) NAME(process_vm_writev)
    NAME(bpf) NAME(perf_event_open) NAME(unshare) NAME(setns) NAME(mount) NAME(umount2) NAME(pivot_root)
    NAME(chroot) NAME(add_key) NAME(request_key) NAME(keyctl) NAME(kcmp) NAME(tkill) NAME(kill) NAME(tgkill)
    NAME(rt_sigqueueinfo) NAME(rt_tgsigqueueinfo) NAME(truncate) NAME(linkat) NAME(symlinkat) NAME(mknodat)
    NAME(fchownat) NAME(setxattr) NAME(lsetxattr) NAME(getxattr) NAME(lgetxattr) NAME(listxattr)
    NAME(llistxattr) NAME(removexattr) NAME(lremovexattr) NAME(inotify_add_watch) NAME(fanotify_mark)
    NAME(name_to_handle_at) NAME(open_by_handle_at) NAME(ioctl) NAME(fcntl) NAME(dup) NAME(dup3) NAME(mmap)
#ifdef __NR_link
    NAME(link) NAME(symlink) NAME(mknod) NAME(chown) NAME(lchown) NAME(utime) NAME(utimes) NAME(futimesat)
#endif
#ifdef __NR_dup2
    NAME(dup2)
#endif
#ifdef __NR_io_uring_setup
    NAME(io_uring_setup) NAME(io_uring_enter) NAME(io_uring_register)
#endif
#ifdef __NR_pidfd_open
    NAME(pidfd_open) NAME(pidfd_send_signal) NAME(pidfd_getfd)
#endif
#ifdef __NR_process_madvise
    NAME(process_madvise)
#endif
#ifdef __NR_open_tree
    NAME(open_tree) NAME(move_mount) NAME(fsopen) NAME(fsconfig) NAME(fsmount) NAME(fspick)
#endif
    /* What the filter traps: paths, signals and the rest of the handler's work. */
    NAME(openat) NAME(newfstatat) NAME(faccessat) NAME(readlinkat) NAME(mkdirat) NAME(unlinkat) NAME(renameat2)
    NAME(statfs) NAME(chdir) NAME(fchdir) NAME(getcwd) NAME(getdents64) NAME(fchmodat) NAME(utimensat)
    NAME(rt_sigprocmask) NAME(rt_sigaction) NAME(clone) NAME(accept) NAME(accept4) NAME(listen) NAME(socketpair)
#ifdef __NR_statx
    NAME(statx)
#endif
#ifdef __NR_faccessat2
    NAME(faccessat2)
#endif
#ifdef __NR_clone3
    NAME(clone3)
#endif
#ifdef __NR_renameat
    NAME(renameat)
#endif
#ifdef __NR_open
    NAME(open) NAME(creat) NAME(stat) NAME(lstat) NAME(access) NAME(readlink) NAME(mkdir) NAME(rmdir)
    NAME(unlink) NAME(rename) NAME(chmod) NAME(getdents)
#endif
#undef NAME
    default: return NULL;
    }
}

/*
 * The lockdown flag that would have let a recorded call through, or NULL
 * when none does (a clear escape: ptrace, namespaces, mounts, bpf and the
 * like). The narrowest one: SBX_LOCK_SOCKETS allows every socket named
 * here as well.
 */
static const char *allowed_by(long nr, const int64_t *args) {
    switch (nr) {
    case __NR_socket: {
        unsigned type = (unsigned) args[1] & 0xf;
        switch ((int) args[0]) {
        case AF_UNIX:
            if (type == SOCK_STREAM || type == SOCK_SEQPACKET) return "SBX_LOCK_UNIX";
            return type == SOCK_DGRAM ? "SBX_LOCK_LOG_SOCKET" : NULL;
        case AF_INET:
        case AF_INET6:
            return type == SOCK_STREAM || type == SOCK_DGRAM ? "SBX_LOCK_INET" : NULL;
        case AF_NETLINK:
            return args[2] == 0 /* NETLINK_ROUTE */ ? "SBX_LOCK_SOCKETS" : NULL;
        default:
            return NULL;
        }
    }
    case __NR_linkat:
    case __NR_symlinkat:
    case __NR_truncate:
#ifdef __NR_link
    case __NR_link:
    case __NR_symlink:
#endif
        return "SBX_LOCK_PATHOPS";
    case __NR_inotify_add_watch:
        /* The scoped one; SBX_LOCK_INOTIFY also allows it, unscoped. */
        return "SBX_LOCK_WATCH";
    case __NR_execve:
    case __NR_execveat:
        return "SBX_LOCK_EXEC";
    case __NR_kill:
    case __NR_tkill:
    case __NR_tgkill:
    case __NR_rt_sigqueueinfo:
    case __NR_rt_tgsigqueueinfo:
        return "SBX_LOCK_SIGNALS";
    default:
        return NULL;
    }
}

/*
 * A call a learning lockdown let through (SBX_LOCK_LEARN): audited as the
 * access "syscall", named with its first three arguments, with the errno a
 * real lockdown answers as the rules' verdict and the flag that allows it. Answered 0, after which the
 * handler makes the call.
 */
static void learn_one(const struct sbx_policy *policy, const char *body, size_t body_len, pid_t pid, int answer) {
    struct sbx_learn_record record;
    if (body_len != sizeof(record)) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    memcpy(&record, body, sizeof(record));
    /*
     * "would" is the errno a real lockdown answers, a small non-negative value
     * the handler fills in. A hostile record could carry anything, including
     * INT32_MIN, whose negation below is undefined; refuse one out of range.
     */
    if (record.would < 0 || record.would > 4095) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    char asked[160];
    const char *name = sbx_syscall_name((long) record.nr);
    if (name) {
        snprintf(asked, sizeof(asked), "%s(%#llx, %#llx, %#llx)", name, (unsigned long long) record.args[0],
                 (unsigned long long) record.args[1], (unsigned long long) record.args[2]);
    } else {
        snprintf(asked, sizeof(asked), "syscall %lld(%#llx, %#llx, %#llx)", (long long) record.nr,
                 (unsigned long long) record.args[0], (unsigned long long) record.args[1],
                 (unsigned long long) record.args[2]);
    }
    struct sbx_access access = {
        .op = "syscall", .asked = asked, .resolved = "", .need = 0, .flags = 0, .pid = pid,
        .rule_verdict = -record.would, .allowed_by = allowed_by((long) record.nr, record.args),
    };
    policy->audit(policy->audit_context, &access, 0);
    reply(answer, 0, NULL, 0, -1);
}

/*
 * SBX_SIGNAL: a signal the filter left to the broker (SBX_LOCK_SIGNAL_TREE).
 * Sent by the broker itself when the target is the sender or in the tree;
 * the receiver then sees the broker's pid as the sender. Audited as the
 * access "signal"; a refusal goes to the decider like any other.
 */
static void signal_one(const struct sbx_policy *policy, const char *body, size_t body_len, pid_t pid, int answer) {
    struct sbx_signal_request s;
    if (body_len != sizeof(s)) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    memcpy(&s, body, sizeof(s));
    pid_t target = s.kind == SBX_SIG_TKILL ? thread_group(s.tid) : s.tgid;
    if (s.kind < SBX_SIG_KILL || s.kind > SBX_SIG_TGQUEUEINFO || s.signal < 0 || s.signal > 64) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    if (target <= 0) {
        /* A process group, every process, or a thread that is gone: never the tree's to judge. */
        reply(answer, s.kind == SBX_SIG_TKILL || s.kind == SBX_SIG_TGKILL ? -ESRCH : -EPERM, NULL, 0, -1);
        return;
    }
    char asked[96];
    snprintf(asked, sizeof(asked), "signal %d to %d", s.signal, (int) target);
    int verdict = in_tree(policy->tree, pid, target) ? 0 : -EPERM;
    struct sbx_access access = {.op = "signal", .asked = asked, .resolved = asked, .pid = pid, .rule_verdict = verdict};
    if (verdict != 0 && policy->decide) {
        int decided = policy->decide(policy->decide_context, &access);
        if (decided == 0) verdict = 0;
    }
    long result = verdict;
    if (verdict == 0) {
        switch (s.kind) {
        case SBX_SIG_KILL: result = syscall(SYS_kill, target, s.signal); break;
        case SBX_SIG_TGKILL: result = syscall(SYS_tgkill, target, s.tid, s.signal); break;
        case SBX_SIG_TKILL: result = syscall(SYS_tgkill, target, s.tid, s.signal); break;
        case SBX_SIG_QUEUEINFO: result = syscall(SYS_rt_sigqueueinfo, target, s.signal, s.info); break;
        default: result = syscall(SYS_rt_tgsigqueueinfo, target, s.tid, s.signal, s.info); break;
        }
        if (result != 0) result = -errno;
    }
    policy->audit(policy->audit_context, &access, (int) result);
    reply(answer, result, NULL, 0, -1);
}

static void serve_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                      size_t body_len, int *fds, int fd_count, pid_t pid, struct conn_budget *budget) {
    if (fd_count < 1) return;
    int answer = fds[0];
    /* dirfd_sent and dirfd2_sent are counts of 0 or 1; a larger value is a malformed request, never ours. */
    if (request->dirfd_sent > 1 || request->dirfd2_sent > 1) { reply(answer, -EINVAL, NULL, 0, -1); return; }
    if (tree_note(policy->tree, pid) != 0) { reply(answer, -EAGAIN, NULL, 0, -1); return; }
    if (request->version == SBX_PROTOCOL_VERSION && request->op == SBX_SIGNAL) {
        if (fd_count != 1) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        signal_one(policy, body, body_len, pid, answer);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && request->op == SBX_LEARN) {
        if (fd_count != 1) { reply(answer, -EINVAL, NULL, 0, -1); return; }
        learn_one(policy, body, body_len, pid, answer);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && (request->op == SBX_UNIX_BIND || request->op == SBX_UNIX_CONNECT)) {
        unix_one(policy, request, body, body_len, fds, fd_count, pid);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && request->op == SBX_WATCH) {
        watch_one(policy, request, body, body_len, fds, fd_count, pid);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && request->op == SBX_SEND) {
        send_one(policy, request, body, body_len, fds, fd_count, pid, budget);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && request->op == SBX_RESOLVE) {
        resolve_one(policy, request, body, body_len, fds, fd_count, pid, budget);
        return;
    }
    if (request->version == SBX_PROTOCOL_VERSION && request->op >= SBX_SOCKET && request->op <= SBX_ACCEPT) {
        net_one(policy, request, body, body_len, fds, fd_count, pid, budget);
        return;
    }
    /* The second part: a name (rename, link), a target (symlink), bytes (utimens, truncate) or nothing. */
    int named2 = request->op == SBX_RENAME || request->op == SBX_LINK || request->op == SBX_SYMLINK;
    if (request->version != SBX_PROTOCOL_VERSION ||
        (size_t) request->path_len + request->path2_len != body_len || request->path_len == 0 ||
        request->path_len >= SBX_PATH_MAX || request->path2_len >= SBX_PATH_MAX ||
        fd_count != 1 + request->dirfd_sent + request->dirfd2_sent ||
        (request->dirfd2_sent && request->op != SBX_RENAME && request->op != SBX_LINK) ||
        request->path2_len != (named2 ? request->path2_len
                               : request->op == SBX_UTIMENS ? (request->path2_len ? 2 * sizeof(struct timespec) : 0)
                               : request->op == SBX_TRUNCATE ? sizeof(int64_t)
                               : 0) ||
        (named2 && request->path2_len == 0)) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    if (request->op == SBX_GETCWD) {
        /* The directory descriptor itself is the question; it came from the broker, so no rule is asked. */
        char name[SBX_PATH_MAX];
        if (!request->dirfd_sent || fd_path(fds[1], name) != 0 || name[0] != '/') {
            reply(answer, -ENOENT, NULL, 0, -1);
            return;
        }
        if (unapply_alias(policy, name) != 0) { reply(answer, -ENAMETOOLONG, NULL, 0, -1); return; }
        size_t length = strlen(name) + 1;
        if (length > request->mode) { reply(answer, -ERANGE, NULL, 0, -1); return; }
        reply(answer, (int64_t) length, name, (uint32_t) length, -1);
        return;
    }
    if (request->op == SBX_LIST) {
        list_one(policy, request, fds, pid, answer);
        return;
    }
    char base[SBX_PATH_MAX] = "/";
    char base2[SBX_PATH_MAX] = "/";
    int next = 1;
    if (request->dirfd_sent) {
        if (fd_path(fds[next++], base) != 0 || base[0] != '/') { reply(answer, -ENOTDIR, NULL, 0, -1); return; }
    }
    if (request->dirfd2_sent) {
        if (fd_path(fds[next++], base2) != 0 || base2[0] != '/') { reply(answer, -ENOTDIR, NULL, 0, -1); return; }
    }
    handle(policy, request, body, body + request->path_len, base, base2, pid, answer);
}

int sbx_broker_prepare(int fd) {
    int on = 1;
    return setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == 0 ? 0 : -errno;
}

/* Answers fd's requests until the other end closes it. Leaves fd open and the policy to the caller. */
static void serve_loop(const struct sbx_policy *policy, int fd) {
    struct conn_budget *budget = conn_budget_new();
    /* A path request needs two paths; a send (SBX_LOCK_NET_FILTER) a datagram and its header. */
    struct incoming {
        struct sbx_request request;
        char body[SBX_SEND_MAX + 1024];
    };
    struct incoming *in = malloc(sizeof(*in));
    if (!in) {
        conn_budget_release(budget);
        return;
    }
#define incoming (*in)
    for (;;) {
        union {
            char buffer[CMSG_SPACE(sizeof(int) * SBX_FDS_MAX) + CMSG_SPACE(sizeof(struct ucred))];
            struct cmsghdr align;
        } control;
        struct iovec part = {&incoming, sizeof(incoming)};
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &part;
        message.msg_iovlen = 1;
        message.msg_control = control.buffer;
        message.msg_controllen = sizeof(control.buffer);
        ssize_t n = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        int fds[SBX_FDS_MAX];
        int fd_count = 0;
        pid_t pid = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level != SOL_SOCKET) continue;
            if (c->cmsg_type == SCM_RIGHTS) {
                size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; i++) {
                    int received;
                    memcpy(&received, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
                    if (fd_count < SBX_FDS_MAX) fds[fd_count++] = received;
                    else close(received);
                }
            } else if (c->cmsg_type == SCM_CREDENTIALS) {
                struct ucred credentials;
                memcpy(&credentials, CMSG_DATA(c), sizeof(credentials));
                pid = credentials.pid;
            }
        }
        if (pid > 0 && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) && (size_t) n >= sizeof(struct sbx_request)) {
            serve_one(policy, &incoming.request, incoming.body, (size_t) n - sizeof(struct sbx_request), fds,
                      fd_count, pid, budget);
        } else if (fd_count >= 1) {
            /*
             * A message too short to be a request, one whose descriptors or
             * body the kernel truncated, or one with no credentials: it is
             * not served, but an answer socket did arrive, so tell the client
             * instead of dropping it silently and leaving it to hang.
             */
            reply(fds[0], -EINVAL, NULL, 0, -1);
        }
        for (int i = 0; i < fd_count; i++) close(fds[i]);
    }
#undef incoming
    free(in);
    /* The connection is done; its net_wait threads (if any still run) hold their own references. */
    conn_budget_release(budget);
}

void sbx_broker_serve(struct sbx_policy *policy, int fd) {
    sbx_broker_prepare(fd);
    serve_loop(policy, fd);
    close(fd);
    sbx_policy_free(policy);
}

/*
 * ---- One broker for a tree of processes (sbx_broker_listen) ----
 *
 * A SOCK_SEQPACKET socket at a path in a folder only the host can enter.
 * Each connection's first message is the token, sent with
 * SCM_CREDENTIALS: the sender must have the broker's own UID (the kernel's
 * word) and the token must match, or the connection is closed unanswered.
 * After the one-byte answer, the connection is served like a socketpair's:
 * every request names its sender's pid in its own credentials, so the
 * processes a confined one forks share its connection and are still told
 * apart. One thread per connection; the policy is shared, so its decider
 * and audit must be safe to call from several threads.
 */
#define TOKEN_MAX 128

struct sbx_listener {
    struct sbx_policy *policy;
    int fd;
    char token[TOKEN_MAX];
    size_t token_length;
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    int users;   /* the listener itself and each connection; the last one out frees it all */
    int closing;
};

static void listener_release(struct sbx_listener *listener) {
    if (__atomic_sub_fetch(&listener->users, 1, __ATOMIC_ACQ_REL) != 0) return;
    sbx_policy_free(listener->policy);
    free(listener);
}

/* Equal without saying where they differ. */
static int same_token(const char *a, size_t a_length, const char *b, size_t b_length) {
    unsigned char difference = a_length != b_length;
    size_t n = a_length < b_length ? a_length : b_length;
    for (size_t i = 0; i < n; i++) difference |= (unsigned char) (a[i] ^ b[i]);
    return difference == 0;
}

struct connection {
    struct sbx_listener *listener;
    int fd;
};

static void *connection_thread(void *argument) {
    struct connection *connection = argument;
    struct sbx_listener *listener = connection->listener;
    int fd = connection->fd;
    free(connection);
    char token[TOKEN_MAX];
    union {
        char buffer[CMSG_SPACE(sizeof(struct ucred))];
        struct cmsghdr align;
    } control;
    struct iovec part = {token, sizeof(token)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    message.msg_control = control.buffer;
    message.msg_controllen = sizeof(control.buffer);
    ssize_t n;
    do n = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    while (n < 0 && errno == EINTR);
    int trusted = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); n > 0 && c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS) {
            struct ucred credentials;
            memcpy(&credentials, CMSG_DATA(c), sizeof(credentials));
            trusted = credentials.uid == geteuid() && credentials.pid > 0;
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            /* No descriptors belong in the greeting. */
            size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < count; i++) {
                int received;
                memcpy(&received, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
                close(received);
            }
            trusted = 0;
        }
    }
    if (trusted && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
        same_token(token, (size_t) n, listener->token, listener->token_length)) {
        char ok = 1;
        if (send(fd, &ok, 1, MSG_NOSIGNAL) == 1) serve_loop(listener->policy, fd);
    } else {
        struct sbx_access access = {.op = "attach", .asked = "a connection without the broker's UID and token",
                                    .resolved = listener->path, .pid = 0, .rule_verdict = -EACCES};
        listener->policy->audit(listener->policy->audit_context, &access, -EACCES);
    }
    close(fd);
    listener_release(listener);
    return NULL;
}

static void *accept_thread(void *argument) {
    struct sbx_listener *listener = argument;
    for (;;) {
        int fd = accept4(listener->fd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            break;  /* closed by sbx_listener_close */
        }
        if (__atomic_load_n(&listener->closing, __ATOMIC_ACQUIRE)) {
            close(fd);
            break;
        }
        sbx_broker_prepare(fd);
        struct connection *connection = malloc(sizeof(*connection));
        if (!connection) {
            close(fd);
            continue;
        }
        connection->listener = listener;
        connection->fd = fd;
        __atomic_add_fetch(&listener->users, 1, __ATOMIC_ACQ_REL);
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        pthread_t thread;
        int error = pthread_create(&thread, &attributes, connection_thread, connection);
        pthread_attr_destroy(&attributes);
        if (error != 0) {
            close(fd);
            free(connection);
            listener_release(listener);
        }
    }
    listener_release(listener);
    return NULL;
}

int sbx_broker_listen(struct sbx_policy *policy, const char *socket_path, const char *token,
                      struct sbx_listener **out) {
    if (out) *out = NULL;
    if (!policy || !socket_path || socket_path[0] != '/' || !token || !out) return -EINVAL;
    size_t token_length = strlen(token);
    if (token_length < 16 || token_length >= TOKEN_MAX) return -EINVAL;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(socket_path) >= sizeof(address.sun_path)) return -ENAMETOOLONG;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);
    struct sbx_listener *listener = calloc(1, sizeof(*listener));
    if (!listener) return -ENOMEM;
    listener->policy = policy;
    memcpy(listener->token, token, token_length);
    listener->token_length = token_length;
    memcpy(listener->path, address.sun_path, sizeof(listener->path));
    listener->users = 2;  /* the accept thread and sbx_listener_close */
    listener->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    int error = 0;
    if (listener->fd < 0) error = -errno;
    else if (bind(listener->fd, (struct sockaddr *) &address, sizeof(address)) != 0) error = -errno;
    else if (listen(listener->fd, 64) != 0) error = -errno;
    if (error == 0) {
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
        pthread_t thread;
        error = -pthread_create(&thread, &attributes, accept_thread, listener);
        pthread_attr_destroy(&attributes);
    }
    if (error != 0) {
        if (listener->fd >= 0) {
            close(listener->fd);
            unlink(listener->path);
        }
        free(listener);  /* the policy stays the caller's on failure */
        return error;
    }
    *out = listener;
    return 0;
}

void sbx_listener_close(struct sbx_listener *listener) {
    if (!listener) return;
    __atomic_store_n(&listener->closing, 1, __ATOMIC_RELEASE);
    unlink(listener->path);
    /* Wakes the accept thread: shutdown makes a blocked accept fail. */
    shutdown(listener->fd, SHUT_RDWR);
    close(listener->fd);
    listener_release(listener);
}

struct session {
    struct sbx_policy *policy;
    int fd;
};

static void *serve_thread(void *argument) {
    struct session *session = argument;
    sbx_broker_serve(session->policy, session->fd);
    free(session);
    return NULL;
}

int sbx_broker_start(struct sbx_policy *policy, int fd) {
    /* Before the confined side can send anything, or its first request would come without a pid. */
    int prepared = sbx_broker_prepare(fd);
    if (prepared != 0) return prepared;
    struct session *session = malloc(sizeof(*session));
    if (!session) return -ENOMEM;
    session->policy = policy;
    session->fd = fd;
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    int error = pthread_create(&thread, &attributes, serve_thread, session);
    pthread_attr_destroy(&attributes);
    if (error != 0) {
        free(session);
        return -error;
    }
    return 0;
}

/*
 * ---- Canonical serialization for the contract's policy digest (internal.h) ----
 */
static void put_u32(unsigned char **p, uint32_t v) {
    for (int i = 0; i < 4; i++) *(*p)++ = (unsigned char) (v >> (8 * i));
}
static void put_u64(unsigned char **p, uint64_t v) {
    for (int i = 0; i < 8; i++) *(*p)++ = (unsigned char) (v >> (8 * i));
}
static void put_bytes(unsigned char **p, const void *b, size_t n) {
    if (n) memcpy(*p, b, n);
    *p += n;
}

unsigned char *sbx_policy_serialize(const struct sbx_policy *policy, size_t *len) {
    if (len) *len = 0;
    if (!policy) return NULL;
    size_t size = 5 + 4 + 8;  /* magic, net, rule count */
    for (size_t i = 0; i < policy->count; i++) size += 8 + 4 + 4 + policy->rules[i].length;
    size += 8;
    for (size_t i = 0; i < policy->alias_count; i++)
        size += 8 + policy->aliases[i].virtual_length + 8 + policy->aliases[i].real_length;
    size += 4;
    for (unsigned i = 0; i < policy->system_count; i++)
        size += 4 + 8 + (policy->system_paths[i] ? strlen(policy->system_paths[i]) : 0);
    size += 4;
    for (unsigned i = 0; i < policy->unix_name_count; i++) size += 4 + 8 + policy->unix_name_lengths[i];

    unsigned char *out = malloc(size);
    if (!out) return NULL;
    unsigned char *p = out;
    put_bytes(&p, "SBXP1", 5);
    put_u32(&p, policy->net);
    put_u64(&p, policy->count);
    for (size_t i = 0; i < policy->count; i++) {
        put_u64(&p, policy->rules[i].length);
        put_u32(&p, policy->rules[i].mode);
        put_u32(&p, policy->rules[i].flags);
        put_bytes(&p, policy->rules[i].path, policy->rules[i].length);
    }
    put_u64(&p, policy->alias_count);
    for (size_t i = 0; i < policy->alias_count; i++) {
        put_u64(&p, policy->aliases[i].virtual_length);
        put_bytes(&p, policy->aliases[i].virtual_path, policy->aliases[i].virtual_length);
        put_u64(&p, policy->aliases[i].real_length);
        put_bytes(&p, policy->aliases[i].real_path, policy->aliases[i].real_length);
    }
    put_u32(&p, policy->system_count);
    for (unsigned i = 0; i < policy->system_count; i++) {
        size_t n = policy->system_paths[i] ? strlen(policy->system_paths[i]) : 0;
        put_u32(&p, policy->system_grants[i]);
        put_u64(&p, n);
        put_bytes(&p, policy->system_paths[i], n);
    }
    put_u32(&p, policy->unix_name_count);
    for (unsigned i = 0; i < policy->unix_name_count; i++) {
        put_u32(&p, policy->unix_name_modes[i]);
        put_u64(&p, policy->unix_name_lengths[i]);
        put_bytes(&p, policy->unix_names[i], policy->unix_name_lengths[i]);
    }
    size_t total = size;
    if (netp_serialize(policy->netp, &out, &total) != 0) {
        free(out);
        return NULL;
    }
    if (len) *len = total;
    return out;
}
