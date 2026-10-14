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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef __NR_renameat2
#define __NR_renameat2 316
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
};

static void default_audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result >= 0) return;
    fprintf(stderr, "sbx: refused %s %s (%s): %s\n", access->op, access->asked,
            access->resolved[0] ? access->resolved : "unresolved", strerror(-result));
}

struct sbx_policy *sbx_policy_new(void) {
    struct sbx_policy *policy = calloc(1, sizeof(struct sbx_policy));
    if (policy) policy->audit = default_audit;
    return policy;
}

void sbx_policy_free(struct sbx_policy *policy) {
    if (!policy) return;
    for (size_t i = 0; i < policy->count; i++) free(policy->rules[i].path);
    for (size_t i = 0; i < policy->alias_count; i++) {
        free(policy->aliases[i].virtual_path);
        free(policy->aliases[i].real_path);
    }
    free(policy->rules);
    free(policy->aliases);
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
    sendmsg(to, &message, MSG_NOSIGNAL);
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
        int fd = open_decided(&c, flags, (mode_t) request->mode, need);
        if (fd < 0) { error = fd; break; }
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

static void serve_one(const struct sbx_policy *policy, const struct sbx_request *request, const char *body,
                      size_t body_len, int *fds, int fd_count, pid_t pid) {
    if (fd_count < 1) return;
    int answer = fds[0];
    if (request->version != SBX_PROTOCOL_VERSION ||
        (size_t) request->path_len + request->path2_len != body_len || request->path_len == 0 ||
        request->path_len >= SBX_PATH_MAX || request->path2_len >= SBX_PATH_MAX ||
        fd_count != 1 + request->dirfd_sent + request->dirfd2_sent ||
        (request->op == SBX_RENAME) != (request->path2_len != 0)) {
        reply(answer, -EINVAL, NULL, 0, -1);
        return;
    }
    /* /proc/<pid>/task/<tid> must be the sender's own thread. */
    char task[64];
    snprintf(task, sizeof(task), "/proc/%d/task/%d", (int) pid, (int) request->tid);
    if (request->tid <= 0 || !exists(task)) {
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

void sbx_broker_serve(struct sbx_policy *policy, int fd) {
    sbx_broker_prepare(fd);
    struct {
        struct sbx_request request;
        char body[SBX_PATH_MAX * 2];
    } incoming;
    for (;;) {
        union {
            char buffer[CMSG_SPACE(sizeof(int) * 3) + CMSG_SPACE(sizeof(struct ucred))];
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
        int fds[3];
        int fd_count = 0;
        pid_t pid = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level != SOL_SOCKET) continue;
            if (c->cmsg_type == SCM_RIGHTS) {
                size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; i++) {
                    int received;
                    memcpy(&received, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
                    if (fd_count < 3) fds[fd_count++] = received;
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
                      fd_count, pid);
        }
        for (int i = 0; i < fd_count; i++) close(fds[i]);
    }
    close(fd);
    sbx_policy_free(policy);
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
