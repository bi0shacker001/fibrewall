/*
 * Network rules (docs/design.md, "Network filtering"): parsing a host's rule
 * lines, matching a destination, a name or a listening port against them,
 * the table of addresses the broker resolved, and the two name-server
 * protocols the broker answers itself (netd's dnsproxyd and DNS over TCP).
 * Between broker.c and net.c only.
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */
#ifndef SBX_NET_H
#define SBX_NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct netp;

/* What a rule says. NETP_NONE: no rule matched (refused). */
enum { NETP_NONE = 0, NETP_ALLOW, NETP_DENY, NETP_ASK };
#define NETP_TCP 1u
#define NETP_UDP 2u

struct netp *netp_new(void);
void netp_free(struct netp *n);
/* Adds one rule line; 0, -EINVAL (malformed) or -ENOSPC. */
int netp_add(struct netp *n, const char *line);
/* Whether any rule exists (rule mode). */
int netp_active(const struct netp *n);
/* The SBX_NET_* grants that follow from the rules: connect, listen, resolve. */
unsigned netp_grants(const struct netp *n);

/* A verdict and the rule's text ("no rule" when none matched). */
struct netp_verdict {
    int action;
    const char *rule;
};

/* An address as rules see it: IPv4-mapped IPv6 folded to IPv4. 0 or -EAFNOSUPPORT. */
struct netp_addr {
    int family;  /* AF_INET or AF_INET6 */
    uint8_t a[16];
    unsigned port;
};
int netp_addr_of(const struct sockaddr *address, socklen_t length, int connecting, struct netp_addr *out);
int netp_is_loopback(const struct netp_addr *a);

/* An outbound connect or datagram to address, of protocol (NETP_TCP or NETP_UDP). */
struct netp_verdict netp_out(struct netp *n, unsigned protocol, const struct netp_addr *address);
/*
 * A bind of local port (non-zero) of protocol: allowed when an in rule can
 * allow it. *loopback_only is set when every such rule is loopback-scoped.
 */
struct netp_verdict netp_bind(struct netp *n, unsigned protocol, unsigned port, int *loopback_only);
/* An accepted peer on local port. */
struct netp_verdict netp_in(struct netp *n, unsigned protocol, unsigned port, const struct netp_addr *peer);
/* A name lookup. */
struct netp_verdict netp_name(struct netp *n, const char *name);

/*
 * Resolves name (family AF_INET, AF_INET6 or AF_UNSPEC) with the broker's
 * own resolver, records the addresses for the name rules, and fills up to
 * max addresses (port 0). Returns the count, or -ENOENT (no such name) or
 * -EAGAIN (the resolver failed). Not a decision: the caller decides first.
 */
int netp_resolve(struct netp *n, const char *name, int family, struct sockaddr_storage *out, int max);

/* The name the broker most recently resolved address for, into out; 0, or -ENOENT. */
int netp_name_for(struct netp *n, const struct netp_addr *address, char *out, size_t size);

/* The rule lines in order, for the policy's digest: appends to *buffer (malloc'd) and *length. */
int netp_serialize(const struct netp *n, unsigned char **buffer, size_t *length);

/*
 * The broker's answer to a name: the count of addresses filled (> 0), or
 * -EACCES (refused), -ENOENT (no such name), -EAGAIN (resolver failed).
 * The broker supplies it: it decides (rules, decider, audit), then resolves.
 */
typedef int (*netp_lookup_fn)(void *context, const char *name, int family, struct sockaddr_storage *out, int max);

/* Serves fd as netd's dnsproxyd for one client until it closes; answers "getaddrinfo" only. Closes nothing. */
void netp_serve_dnsproxy(int fd, netp_lookup_fn lookup, void *context);
/* Serves fd as a DNS-over-TCP name server (RFC 1035 4.2.2) until it closes: A and AAAA answered. */
void netp_serve_dns_tcp(int fd, netp_lookup_fn lookup, void *context);

#endif
