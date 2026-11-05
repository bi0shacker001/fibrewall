/*
 * Network rules and the broker's name service (docs/design.md, "Network
 * filtering"). See net.h.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#define _GNU_SOURCE
#include "net.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sbx.h"

#define RULES_MAX 256
#define NAME_MAX_LEN 253
#define TABLE_SIZE 512
#define TABLE_SECONDS 600   /* how long a resolved address counts for its name: getaddrinfo gives no TTL */
#define LOOKUP_SECONDS 60   /* how often the broker resolves a rule's own name on a connect */

enum { DIR_OUT, DIR_IN, DIR_DNS };
enum { DEST_ANY, DEST_LOOPBACK, DEST_LOCAL, DEST_INTERNET, DEST_PREFIX, DEST_NAME, DEST_WILDCARD };

struct rule {
    int action;
    int direction;
    unsigned protocols;   /* NETP_TCP | NETP_UDP */
    int dest;
    int family;           /* DEST_PREFIX */
    uint8_t prefix[16];
    unsigned bits;
    char *name;           /* DEST_NAME: the name; DEST_WILDCARD: the zone, without "*." */
    unsigned port_lo, port_hi;
    char *text;
    time_t looked_up;     /* DEST_NAME: when the broker last resolved it on a connect */
};

struct entry {
    char name[NAME_MAX_LEN + 1];
    struct netp_addr address;
    time_t expires;
};

struct netp {
    struct rule rules[RULES_MAX];
    unsigned count;
    pthread_mutex_t lock;  /* the table and looked_up */
    struct entry table[TABLE_SIZE];
    unsigned next;
};

struct netp *netp_new(void) {
    struct netp *n = calloc(1, sizeof(*n));
    if (n) pthread_mutex_init(&n->lock, NULL);
    return n;
}

void netp_free(struct netp *n) {
    if (!n) return;
    for (unsigned i = 0; i < n->count; i++) {
        free(n->rules[i].name);
        free(n->rules[i].text);
    }
    pthread_mutex_destroy(&n->lock);
    free(n);
}

int netp_active(const struct netp *n) { return n && n->count > 0; }

/* ---- Names ---- */

/* A name as rules compare it: lower case, no trailing dot. 0, or -EINVAL when it is not a host name. */
static int canonical_name(const char *in, char *out) {
    size_t n = strlen(in);
    if (n > 0 && in[n - 1] == '.') n--;
    if (n == 0 || n > NAME_MAX_LEN) return -EINVAL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char) in[i];
        if (!(isalnum(c) || c == '-' || c == '.' || c == '_')) return -EINVAL;
        out[i] = (char) tolower(c);
    }
    out[n] = '\0';
    if (out[0] == '.' || strstr(out, "..")) return -EINVAL;
    return 0;
}

static int name_matches(const struct rule *r, const char *name) {
    if (r->dest == DEST_NAME) return strcmp(r->name, name) == 0;
    if (r->dest != DEST_WILDCARD) return 0;
    size_t z = strlen(r->name), n = strlen(name);
    return n > z + 1 && name[n - z - 1] == '.' && strcmp(name + n - z, r->name) == 0;
}

/* ---- Addresses ---- */

int netp_addr_of(const struct sockaddr *address, socklen_t length, int connecting, struct netp_addr *out) {
    memset(out, 0, sizeof(*out));
    if (address->sa_family == AF_INET && length >= (socklen_t) sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *) address;
        out->family = AF_INET;
        memcpy(out->a, &in->sin_addr, 4);
        out->port = ntohs(in->sin_port);
    } else if (address->sa_family == AF_INET6 && length >= (socklen_t) sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) address;
        out->port = ntohs(in6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
            /* ::ffff:a.b.c.d reaches a.b.c.d: it is matched as that address, never as an IPv6 one. */
            out->family = AF_INET;
            memcpy(out->a, in6->sin6_addr.s6_addr + 12, 4);
        } else {
            out->family = AF_INET6;
            memcpy(out->a, in6->sin6_addr.s6_addr, 16);
        }
    } else {
        return -EAFNOSUPPORT;
    }
    if (connecting) {
        /* Linux connects the unspecified address to loopback: so it is matched. */
        static const uint8_t zero[16];
        if (memcmp(out->a, zero, out->family == AF_INET ? 4 : 16) == 0) {
            if (out->family == AF_INET) {
                out->a[0] = 127;
                out->a[3] = 1;
            } else {
                out->a[15] = 1;
            }
        }
    }
    return 0;
}

static int in_prefix(const struct netp_addr *a, int family, const uint8_t *prefix, unsigned bits) {
    if (a->family != family) return 0;
    for (unsigned i = 0; i < bits / 8; i++) {
        if (a->a[i] != prefix[i]) return 0;
    }
    unsigned rest = bits % 8;
    if (rest) {
        uint8_t mask = (uint8_t) (0xff << (8 - rest));
        if ((a->a[bits / 8] & mask) != (prefix[bits / 8] & mask)) return 0;
    }
    return 1;
}

int netp_is_loopback(const struct netp_addr *a) {
    static const uint8_t v6[16] = {[15] = 1};
    if (a->family == AF_INET) return a->a[0] == 127;
    return memcmp(a->a, v6, 16) == 0;
}

static int is_local(const struct netp_addr *a) {
    if (netp_is_loopback(a)) return 1;
    if (a->family == AF_INET) {
        const uint8_t *b = a->a;
        if (b[0] == 10) return 1;
        if (b[0] == 172 && (b[1] & 0xf0) == 16) return 1;
        if (b[0] == 192 && b[1] == 168) return 1;
        if (b[0] == 169 && b[1] == 254) return 1;
        if ((b[0] & 0xf0) == 224) return 1;  /* multicast */
        if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return 1;
        return 0;
    }
    const uint8_t *b = a->a;
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1;  /* fe80::/10 */
    if ((b[0] & 0xfe) == 0xfc) return 1;                  /* fc00::/7 */
    if (b[0] == 0xff) {
        unsigned scope = b[1] & 0x0f;
        return scope >= 1 && scope <= 5;                  /* interface, link, realm, admin, site */
    }
    return 0;
}

static int is_unspecified(const struct netp_addr *a) {
    static const uint8_t zero[16];
    return memcmp(a->a, zero, a->family == AF_INET ? 4 : 16) == 0;
}

/* ---- Parsing ---- */

static int parse_port(const char *word, unsigned *lo, unsigned *hi) {
    char *end;
    unsigned long a = strtoul(word, &end, 10);
    if (end == word || a > 65535) return -EINVAL;
    unsigned long b = a;
    if (*end == '-') {
        const char *second = end + 1;
        b = strtoul(second, &end, 10);
        if (end == second || b > 65535 || b < a) return -EINVAL;
    }
    if (*end) return -EINVAL;
    *lo = (unsigned) a;
    *hi = (unsigned) b;
    return 0;
}

static int parse_dest(struct rule *r, const char *word) {
    if (strcmp(word, "any") == 0) { r->dest = DEST_ANY; return 0; }
    if (strcmp(word, "loopback") == 0) { r->dest = DEST_LOOPBACK; return 0; }
    if (strcmp(word, "local") == 0) { r->dest = DEST_LOCAL; return 0; }
    if (strcmp(word, "internet") == 0) { r->dest = DEST_INTERNET; return 0; }
    char copy[NAME_MAX_LEN + 8];
    if (strlen(word) >= sizeof(copy)) return -EINVAL;
    strcpy(copy, word);
    char *slash = strchr(copy, '/');
    long bits = -1;
    if (slash) {
        char *end;
        bits = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end || bits < 0) return -EINVAL;
        *slash = '\0';
    }
    if (inet_pton(AF_INET, copy, r->prefix) == 1) {
        if (bits > 32) return -EINVAL;
        r->family = AF_INET;
        r->bits = bits < 0 ? 32 : (unsigned) bits;
        r->dest = DEST_PREFIX;
        return 0;
    }
    if (inet_pton(AF_INET6, copy, r->prefix) == 1) {
        if (bits > 128) return -EINVAL;
        if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *) r->prefix)) {
            /* Rules match a mapped address as IPv4, so a mapped prefix is written as one. */
            if (bits >= 0 && bits < 96) return -EINVAL;
            memmove(r->prefix, r->prefix + 12, 4);
            r->family = AF_INET;
            r->bits = bits < 0 ? 32 : (unsigned) bits - 96;
        } else {
            r->family = AF_INET6;
            r->bits = bits < 0 ? 128 : (unsigned) bits;
        }
        r->dest = DEST_PREFIX;
        return 0;
    }
    if (slash) return -EINVAL;
    char name[NAME_MAX_LEN + 1];
    if (strncmp(copy, "*.", 2) == 0) {
        if (canonical_name(copy + 2, name) != 0) return -EINVAL;
        r->dest = DEST_WILDCARD;
    } else {
        if (canonical_name(copy, name) != 0) return -EINVAL;
        r->dest = DEST_NAME;
    }
    r->name = strdup(name);
    return r->name ? 0 : -ENOMEM;
}

int netp_add(struct netp *n, const char *line) {
    if (!n || !line) return -EINVAL;
    if (n->count >= RULES_MAX) return -ENOSPC;
    char copy[512];
    size_t length = strlen(line);
    if (length == 0 || length >= sizeof(copy)) return -EINVAL;
    memcpy(copy, line, length + 1);
    char *words[8];
    int count = 0;
    for (char *save = NULL, *w = strtok_r(copy, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) {
        if (count == 8) return -EINVAL;
        words[count++] = w;
    }
    struct rule r;
    memset(&r, 0, sizeof(r));
    int i = 0;
    if (count < 3) return -EINVAL;
    if (strcmp(words[i], "allow") == 0) r.action = NETP_ALLOW;
    else if (strcmp(words[i], "deny") == 0) r.action = NETP_DENY;
    else if (strcmp(words[i], "ask") == 0) r.action = NETP_ASK;
    else return -EINVAL;
    i++;
    if (strcmp(words[i], "out") == 0) r.direction = DIR_OUT;
    else if (strcmp(words[i], "in") == 0) r.direction = DIR_IN;
    else if (strcmp(words[i], "dns") == 0) r.direction = DIR_DNS;
    else return -EINVAL;
    i++;
    r.protocols = NETP_TCP | NETP_UDP;
    r.port_hi = 65535;
    if (r.direction == DIR_DNS) {
        if (count != 3) return -EINVAL;
        int bad = parse_dest(&r, words[i]);
        if (bad) return bad;
        if (r.dest != DEST_ANY && r.dest != DEST_NAME && r.dest != DEST_WILDCARD) {
            free(r.name);
            return -EINVAL;
        }
    } else {
        if (strcmp(words[i], "tcp") == 0) r.protocols = NETP_TCP, i++;
        else if (strcmp(words[i], "udp") == 0) r.protocols = NETP_UDP, i++;
        if (i >= count) return -EINVAL;
        int bad = parse_dest(&r, words[i++]);
        if (bad) return bad;
        if (i < count) {
            if (strcmp(words[i], "port") != 0 || i + 2 != count || parse_port(words[i + 1], &r.port_lo, &r.port_hi) != 0) {
                free(r.name);
                return -EINVAL;
            }
        }
    }
    r.text = strdup(line);
    if (!r.text) {
        free(r.name);
        return -ENOMEM;
    }
    n->rules[n->count++] = r;
    return 0;
}

unsigned netp_grants(const struct netp *n) {
    unsigned grants = 0;
    for (unsigned i = 0; n && i < n->count; i++) {
        const struct rule *r = &n->rules[i];
        if (r->action == NETP_DENY) continue;
        if (r->direction == DIR_OUT) grants |= SBX_NET_CONNECT;
        if (r->direction == DIR_IN) grants |= SBX_NET_LISTEN;
        if (r->direction == DIR_DNS || r->dest == DEST_NAME || r->dest == DEST_WILDCARD) grants |= SBX_NET_RESOLVE;
    }
    return grants;
}

int netp_serialize(const struct netp *n, unsigned char **buffer, size_t *length) {
    for (unsigned i = 0; n && i < n->count; i++) {
        size_t add = strlen(n->rules[i].text) + 1;
        unsigned char *grown = realloc(*buffer, *length + add);
        if (!grown) return -ENOMEM;
        memcpy(grown + *length, n->rules[i].text, add);
        *buffer = grown;
        *length += add;
    }
    return 0;
}

/* ---- The table of resolved addresses ---- */

static void record(struct netp *n, const char *name, const struct netp_addr *address) {
    time_t now = time(NULL);
    pthread_mutex_lock(&n->lock);
    struct entry *slot = NULL;
    for (unsigned i = 0; i < TABLE_SIZE && !slot; i++) {
        struct entry *e = &n->table[i];
        if (e->expires && e->address.family == address->family && memcmp(e->address.a, address->a, 16) == 0 &&
            strcmp(e->name, name) == 0) {
            slot = e;
        }
    }
    if (!slot) {
        slot = &n->table[n->next];
        n->next = (n->next + 1) % TABLE_SIZE;
        snprintf(slot->name, sizeof(slot->name), "%s", name);
        slot->address = *address;
        slot->address.port = 0;
    }
    slot->expires = now + TABLE_SECONDS;
    pthread_mutex_unlock(&n->lock);
}

/* Whether the broker resolved address for a name rule r matches. */
static int resolved_for(struct netp *n, const struct rule *r, const struct netp_addr *address) {
    time_t now = time(NULL);
    int found = 0;
    pthread_mutex_lock(&n->lock);
    for (unsigned i = 0; i < TABLE_SIZE && !found; i++) {
        const struct entry *e = &n->table[i];
        if (e->expires > now && e->address.family == address->family &&
            memcmp(e->address.a, address->a, address->family == AF_INET ? 4 : 16) == 0 && name_matches(r, e->name)) {
            found = 1;
        }
    }
    pthread_mutex_unlock(&n->lock);
    return found;
}

int netp_name_for(struct netp *n, const struct netp_addr *address, char *out, size_t size) {
    time_t now = time(NULL), best = 0;
    pthread_mutex_lock(&n->lock);
    for (unsigned i = 0; i < TABLE_SIZE; i++) {
        const struct entry *e = &n->table[i];
        if (e->expires > now && e->expires > best && e->address.family == address->family &&
            memcmp(e->address.a, address->a, address->family == AF_INET ? 4 : 16) == 0) {
            best = e->expires;
            snprintf(out, size, "%s", e->name);
        }
    }
    pthread_mutex_unlock(&n->lock);
    return best ? 0 : -ENOENT;
}

int netp_resolve(struct netp *n, const char *name, int family, struct sockaddr_storage *out, int max) {
    char canonical[NAME_MAX_LEN + 1];
    if (canonical_name(name, canonical) != 0) return -ENOENT;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family == AF_INET || family == AF_INET6 ? family : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *list = NULL;
    int error = getaddrinfo(canonical, NULL, &hints, &list);
    if (error != 0) return error == EAI_NONAME
#ifdef EAI_NODATA
                                   || error == EAI_NODATA
#endif
                                   ? -ENOENT : -EAGAIN;
    int count = 0;
    for (struct addrinfo *a = list; a; a = a->ai_next) {
        struct netp_addr address;
        if (netp_addr_of(a->ai_addr, a->ai_addrlen, 0, &address) != 0) continue;
        record(n, canonical, &address);
        int duplicate = 0;
        for (int k = 0; k < count && out; k++) {
            if (out[k].ss_family == a->ai_addr->sa_family && memcmp(&out[k], a->ai_addr, a->ai_addrlen) == 0) duplicate = 1;
        }
        if (out && count < max && !duplicate) {
            memset(&out[count], 0, sizeof(out[count]));
            memcpy(&out[count], a->ai_addr, a->ai_addrlen);
            count++;
        }
    }
    freeaddrinfo(list);
    return count > 0 || !out ? count : -ENOENT;
}

/* ---- Matching ---- */

static const char no_rule[] = "no rule";

static int dest_matches(struct netp *n, struct rule *r, const struct netp_addr *a, int may_lookup) {
    switch (r->dest) {
    case DEST_ANY: return 1;
    case DEST_LOOPBACK: return netp_is_loopback(a);
    case DEST_LOCAL: return is_local(a);
    case DEST_INTERNET: return !is_local(a) && !is_unspecified(a);
    case DEST_PREFIX: return in_prefix(a, r->family, r->prefix, r->bits);
    case DEST_NAME:
    case DEST_WILDCARD:
        if (resolved_for(n, r, a)) return 1;
        if (r->dest == DEST_NAME && may_lookup) {
            /* An address learned another way: the broker resolves the rule's own name, at most once a minute. */
            time_t now = time(NULL);
            pthread_mutex_lock(&n->lock);
            int due = r->looked_up == 0 || now - r->looked_up >= LOOKUP_SECONDS;
            if (due) r->looked_up = now;
            pthread_mutex_unlock(&n->lock);
            if (due) {
                netp_resolve(n, r->name, AF_UNSPEC, NULL, 0);
                return resolved_for(n, r, a);
            }
        }
        return 0;
    default: return 0;
    }
}

struct netp_verdict netp_out(struct netp *n, unsigned protocol, const struct netp_addr *address) {
    struct netp_verdict v = {NETP_NONE, no_rule};
    /* In order, first match: a name rule's lookup happens only when no earlier rule has answered. */
    for (unsigned i = 0; i < n->count; i++) {
        struct rule *r = &n->rules[i];
        if (r->direction != DIR_OUT || !(r->protocols & protocol)) continue;
        if (address->port < r->port_lo || address->port > r->port_hi) continue;
        if (!dest_matches(n, r, address, 1)) continue;
        v.action = r->action;
        v.rule = r->text;
        return v;
    }
    return v;
}

struct netp_verdict netp_bind(struct netp *n, unsigned protocol, unsigned port, int *loopback_only) {
    struct netp_verdict v = {NETP_NONE, no_rule};
    int any_wider = 0;
    for (unsigned i = 0; i < n->count; i++) {
        const struct rule *r = &n->rules[i];
        if (r->direction != DIR_IN || !(r->protocols & protocol) || port < r->port_lo || port > r->port_hi) continue;
        if (r->action == NETP_DENY && r->dest != DEST_ANY) continue;  /* a deny for some peers is the accept's to apply */
        if (v.action == NETP_NONE) {
            v.action = r->action;
            v.rule = r->text;
        }
        if (r->action != NETP_DENY && r->dest != DEST_LOOPBACK) any_wider = 1;
        if (r->action == NETP_DENY) break;
    }
    if (loopback_only) *loopback_only = v.action != NETP_NONE && v.action != NETP_DENY && !any_wider;
    return v;
}

struct netp_verdict netp_in(struct netp *n, unsigned protocol, unsigned port, const struct netp_addr *peer) {
    struct netp_verdict v = {NETP_NONE, no_rule};
    for (unsigned i = 0; i < n->count; i++) {
        struct rule *r = &n->rules[i];
        if (r->direction != DIR_IN || !(r->protocols & protocol) || port < r->port_lo || port > r->port_hi) continue;
        if (!dest_matches(n, r, peer, 0)) continue;
        v.action = r->action;
        v.rule = r->text;
        return v;
    }
    return v;
}

struct netp_verdict netp_name(struct netp *n, const char *name) {
    struct netp_verdict v = {NETP_NONE, no_rule};
    char canonical[NAME_MAX_LEN + 1];
    if (canonical_name(name, canonical) != 0) return v;
    for (unsigned i = 0; i < n->count; i++) {
        const struct rule *r = &n->rules[i];
        int matches = (r->direction == DIR_DNS && r->dest == DEST_ANY) || name_matches(r, canonical);
        if (!matches) continue;
        /* A name rule that denies connections does not forbid looking the name up; only a dns rule does. */
        if (r->direction != DIR_DNS && r->action == NETP_DENY) continue;
        v.action = r->action;
        v.rule = r->text;
        return v;
    }
    return v;
}

/* ---- Serving names ---- */

static int write_all(int fd, const void *data, size_t length) {
    const char *p = data;
    while (length > 0) {
        ssize_t w = send(fd, p, length, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        length -= (size_t) w;
    }
    return 0;
}

static int read_all(int fd, void *data, size_t length) {
    char *p = data;
    while (length > 0) {
        ssize_t r = read(fd, p, length);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r;
        length -= (size_t) r;
    }
    return 0;
}

static int put_be32(int fd, int32_t value) {
    uint32_t be = htonl((uint32_t) value);
    return write_all(fd, &be, 4);
}

#define MAX_ANSWERS 16
/* bionic's EAI_NODATA, the answer its getaddrinfo gives for a name with no address. */
#define BIONIC_EAI_NODATA 7

/*
 * netd's dnsproxyd protocol, as bionic's android_getaddrinfo_proxy speaks it:
 * the request "getaddrinfo <host> <service> <flags> <family> <socktype>
 * <protocol> <netid>" ending in a NUL; the answer "222\0", then for each
 * address a big-endian 1, its flags, family, socktype and protocol, the
 * address's length and bytes, and the canonical name's length (with its
 * NUL) and bytes, then a big-endian 0. A failure is "401\0", a length and
 * the error.
 */
void netp_serve_dnsproxy(int fd, netp_lookup_fn lookup, void *context) {
    for (;;) {
        char line[1100];
        size_t length = 0;
        for (;;) {
            char c;
            ssize_t r = read(fd, &c, 1);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return;
            if (c == '\0') break;
            if (length + 1 >= sizeof(line)) return;
            line[length++] = c;
        }
        line[length] = '\0';
        char *words[9];
        int count = 0;
        for (char *save = NULL, *w = strtok_r(line, " ", &save); w && count < 9; w = strtok_r(NULL, " ", &save)) {
            words[count++] = w;
        }
        int failed = 1;
        if (count == 8 && strcmp(words[0], "getaddrinfo") == 0 && strcmp(words[1], "^") != 0) {
            const char *host = words[1];
            const char *service = words[2];
            int flags = atoi(words[3]), family = atoi(words[4]), socktype = atoi(words[5]);
            unsigned port = 0;
            if (strcmp(service, "^") != 0) {
                char *end;
                unsigned long p = strtoul(service, &end, 10);
                if (*end == '\0' && p <= 65535) port = (unsigned) p;
                else {
                    struct servent *s = getservbyname(service, NULL);
                    if (s) port = ntohs((uint16_t) s->s_port);
                }
            }
            struct sockaddr_storage found[MAX_ANSWERS];
            int n = lookup(context, host, family == AF_INET || family == AF_INET6 ? family : AF_UNSPEC, found, MAX_ANSWERS);
            if (n > 0) {
                failed = 0;
                if (write_all(fd, "222", 4) != 0) return;
                int first = 1;
                for (int i = 0; i < n; i++) {
                    static const int types[2][2] = {{SOCK_STREAM, IPPROTO_TCP}, {SOCK_DGRAM, IPPROTO_UDP}};
                    for (int t = 0; t < 2; t++) {
                        if (socktype > 0 && socktype != types[t][0]) continue;
                        socklen_t alen;
                        if (found[i].ss_family == AF_INET) {
                            ((struct sockaddr_in *) &found[i])->sin_port = htons((uint16_t) port);
                            alen = sizeof(struct sockaddr_in);
                        } else {
                            ((struct sockaddr_in6 *) &found[i])->sin6_port = htons((uint16_t) port);
                            alen = sizeof(struct sockaddr_in6);
                        }
                        int canon = first && (flags & AI_CANONNAME);
                        if (put_be32(fd, 1) || put_be32(fd, 0) || put_be32(fd, found[i].ss_family) ||
                            put_be32(fd, types[t][0]) || put_be32(fd, types[t][1]) || put_be32(fd, (int32_t) alen) ||
                            write_all(fd, &found[i], alen) || put_be32(fd, canon ? (int32_t) strlen(host) + 1 : 0) ||
                            (canon && write_all(fd, host, strlen(host) + 1))) {
                            return;
                        }
                        first = 0;
                    }
                }
                if (put_be32(fd, 0) != 0) return;
            }
        }
        if (failed) {
            int32_t error = BIONIC_EAI_NODATA;
            if (write_all(fd, "401", 4) || put_be32(fd, (int32_t) sizeof(error)) || write_all(fd, &error, sizeof(error))) return;
        }
    }
}

/* Reads a question's name (no compression in a question) into out as dotted text; returns the offset after it, or -1. */
static int read_qname(const uint8_t *m, size_t length, size_t at, char *out, size_t size) {
    size_t w = 0;
    for (int labels = 0; labels < 128; labels++) {
        if (at >= length) return -1;
        unsigned l = m[at++];
        if (l == 0) {
            if (w == 0) return -1;
            out[w] = '\0';
            return (int) at;
        }
        if (l > 63 || at + l > length || w + l + 2 > size) return -1;
        if (w) out[w++] = '.';
        memcpy(out + w, m + at, l);
        w += l;
        at += l;
    }
    return -1;
}

void netp_serve_dns_tcp(int fd, netp_lookup_fn lookup, void *context) {
    for (;;) {
        uint8_t size_bytes[2];
        if (read_all(fd, size_bytes, 2) != 0) return;
        size_t length = ((size_t) size_bytes[0] << 8) | size_bytes[1];
        uint8_t query[4096];
        if (length < 12 || length > sizeof(query)) return;
        if (read_all(fd, query, length) != 0) return;
        uint8_t answer[12 + 4096 + MAX_ANSWERS * 28];
        memcpy(answer, query, 2);                        /* the id */
        unsigned rd = query[2] & 0x01;
        unsigned qd = ((unsigned) query[4] << 8) | query[5];
        unsigned rcode = 4;                              /* not implemented */
        char name[NAME_MAX_LEN + 2];
        int after = qd == 1 && (query[2] & 0x78) == 0 ? read_qname(query, length, 12, name, sizeof(name)) : -1;
        size_t at = 12;
        unsigned an = 0;
        if (after > 0 && (size_t) after + 4 <= length) {
            unsigned type = ((unsigned) query[after] << 8) | query[after + 1];
            unsigned qclass = ((unsigned) query[after + 2] << 8) | query[after + 3];
            size_t question = (size_t) after + 4 - 12;
            memcpy(answer + 12, query + 12, question);
            at = 12 + question;
            if (qclass == 1 && (type == 1 || type == 28)) {
                struct sockaddr_storage found[MAX_ANSWERS];
                int n = lookup(context, name, type == 1 ? AF_INET : AF_INET6, found, MAX_ANSWERS);
                if (n == -EAGAIN) rcode = 2;             /* server failure */
                else if (n <= 0) rcode = 3;              /* no such name, or refused */
                else {
                    rcode = 0;
                    for (int i = 0; i < n; i++) {
                        const uint8_t *bytes = found[i].ss_family == AF_INET
                                                   ? (const uint8_t *) &((struct sockaddr_in *) &found[i])->sin_addr
                                                   : ((struct sockaddr_in6 *) &found[i])->sin6_addr.s6_addr;
                        unsigned rdlength = found[i].ss_family == AF_INET ? 4 : 16;
                        uint8_t record[12] = {0xc0, 0x0c, (uint8_t) (type >> 8), (uint8_t) type, 0, 1, 0, 0, 0, 60,
                                              0, (uint8_t) rdlength};
                        memcpy(answer + at, record, sizeof(record));
                        memcpy(answer + at + sizeof(record), bytes, rdlength);
                        at += sizeof(record) + rdlength;
                        an++;
                    }
                }
            }
        } else {
            qd = 0;
        }
        answer[2] = (uint8_t) (0x80 | rd);               /* a response, opcode 0, recursion desired as asked */
        answer[3] = (uint8_t) (0x80 | rcode);            /* recursion available */
        answer[4] = 0;
        answer[5] = qd == 1 && after > 0 ? 1 : 0;
        answer[6] = (uint8_t) (an >> 8);
        answer[7] = (uint8_t) an;
        memset(answer + 8, 0, 4);
        uint8_t out_size[2] = {(uint8_t) (at >> 8), (uint8_t) at};
        if (write_all(fd, out_size, 2) != 0 || write_all(fd, answer, at) != 0) return;
    }
}
