/*
 * sbx_test, area "net": sockets: SBX_LOCK_UNIX, SBX_LOCK_INET, the brokered network and network filtering.
 * Included by tests/sbx_test.c, one translation unit with the harness (tests/sbx_test.h);
 * SBX_TEST_AREA=net runs this area alone (#767).
 *
 * Copyright (C) 2026 the sandbox authors. GPL-3.0-or-later.
 */

/* ---- SBX_LOCK_UNIX: Unix sockets of the process's own, bound and connected by the broker. ---- */

/* A path into sun_path, cut to fit (the test's paths are short). */
static void sun_path_set(struct sockaddr_un *address, const char *path) {
    size_t n = strnlen(path, sizeof(address->sun_path) - 1);
    memcpy(address->sun_path, path, n);
    address->sun_path[n] = '\0';
}

static int unix_listener(const char *path) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    sun_path_set(&address, path);
    unlink(path);
    if (s < 0 || bind(s, (struct sockaddr *) &address, sizeof(address)) != 0 || listen(s, 8) != 0) {
        if (s >= 0) close(s);
        return -1;
    }
    return s;
}

static int unix_try(int bind_it, const char *path, int abstract) {
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -errno;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    socklen_t length;
    if (abstract) {
        size_t n = strlen(path);
        memcpy(address.sun_path + 1, path, n);
        length = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + n);
    } else {
        sun_path_set(&address, path);
        length = sizeof(address);
    }
    int r = bind_it ? bind(s, (struct sockaddr *) &address, length) : connect(s, (struct sockaddr *) &address, length);
    int error = r == 0 ? 0 : -errno;
    close(s);
    return error;
}

/* The control for socket files: 0 when the host lets this process make one in folder, else the errno. */
static int host_socket_files(const char *folder) {
    char path[400];
    snprintf(path, sizeof(path), "%s/probe.sock", folder);
    int s = unix_listener(path);
    int error = s >= 0 ? 0 : errno;
    if (s >= 0) close(s);
    unlink(path);
    return error;
}

static int unix_check(void) {
    char inside[400], outside[400], sock_link[400], made[400];
    /* Some hosts let no one make socket files here (Android's shell in /data/local/tmp): those checks are skipped. */
    int files_error = host_socket_files(save);
    int files = files_error == 0;
    if (!files) printf("skip unix: socket files (the host refuses them unconfined: %s)\n", strerror(files_error));
    snprintf(inside, sizeof(inside), "%s/server.sock", game);
    snprintf(outside, sizeof(outside), "%s/server.sock", secret);
    snprintf(sock_link, sizeof(sock_link), "%s/sock-link", save);
    snprintf(made, sizeof(made), "%s/child.sock", save);
    int inside_server = files ? unix_listener(inside) : -1, outside_server = files ? unix_listener(outside) : -1;
    unlink(sock_link);
    if (files && (inside_server < 0 || outside_server < 0 || symlink(outside, sock_link) != 0)) {
        printf("FAIL unix: could not set up the servers (%s)\n", strerror(errno));
        return 1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) return 1;
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_add(policy, game, SBX_READ);
    sbx_policy_add(policy, save, SBX_READ | SBX_WRITE);
    EXPECT(sbx_policy_add_unix_name(policy, "sbx-test-name", SBX_READ | SBX_WRITE) == 0, "unix: an abstract name in the policy");
    EXPECT(sbx_policy_add_unix_name(policy, "", SBX_READ) == -EINVAL, "unix: an empty abstract name is refused");
    sbx_policy_set_net(policy, SBX_NET_CONNECT | SBX_NET_LISTEN);
    if (sbx_broker_start(policy, pair[0]) != 0) return 1;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pair[0]);
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNIX | SBX_LOCK_UNBROKERED};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "unix: not without the broker");
        options.flags = SBX_LOCK_UNIX | SBX_LOCK_NET_BROKERED;
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "unix: not with the brokered network");
        options.flags = SBX_LOCK_UNIX | SBX_LOCK_INET;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "unix: lockdown with SBX_LOCK_INET as well");
        if (locked != 0) _exit(1);
        errno = 0;
        EXPECT(refused(socket(AF_UNIX, SOCK_DGRAM, 0)), "unix: a datagram socket is still refused");
        errno = 0;
        EXPECT(refused(socket(AF_NETLINK, SOCK_RAW, 0)), "unix: netlink is still refused");
        int seq = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        EXPECT(seq >= 0, "unix: a seqpacket socket");
        if (seq >= 0) close(seq);
        if (files) {
            EXPECT(unix_try(0, inside, 0) == 0, "unix: connect to a socket in a readable rule");
            EXPECT(unix_try(0, outside, 0) == -EACCES, "unix: connect to a socket outside the rules is refused");
            EXPECT(unix_try(0, sock_link, 0) == -EACCES, "unix: connect through a link leading out is refused");
        }
        EXPECT(unix_try(1, inside, 0) == -EACCES, "unix: bind in a read-only rule is refused");
        EXPECT(unix_try(1, "sbx-test-other", 1) == -EACCES, "unix: bind of an abstract name the policy lacks is refused");
        EXPECT(unix_try(0, "sbx-test-other", 1) == -EACCES, "unix: connect to one is refused");

        /* A server of its own in the writable rule, and a client of it. */
        int server = files ? socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) : -1;
        if (files) {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        sun_path_set(&address, made);
        EXPECT(server >= 0 && bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "unix: bind in the writable rule");
        EXPECT(listen(server, 4) == 0, "unix: listen on it");
        int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(client >= 0 && connect(client, (struct sockaddr *) &address, sizeof(address)) == 0, "unix: connect to it");
        int accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        char byte = 0;
        EXPECT(accepted >= 0 && write(client, "u", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'u',
               "unix: bytes cross it");
        if (accepted >= 0) close(accepted);
        if (client >= 0) close(client);
        if (server >= 0) close(server);
        EXPECT(chdir(save) == 0 && unix_try(1, "relative.sock", 0) == 0, "unix: bind of a relative path in the writable rule");
        }
        int named = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un abstract = {.sun_family = AF_UNIX};
        memcpy(abstract.sun_path + 1, "sbx-test-name", 13);
        socklen_t abstract_length = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + 13);
        EXPECT(named >= 0 && bind(named, (struct sockaddr *) &abstract, abstract_length) == 0 && listen(named, 2) == 0,
               "unix: bind and listen on an abstract name the policy lists");
        EXPECT(unix_try(0, "sbx-test-name", 1) == 0, "unix: connect to it");
        if (named >= 0) close(named);

        /* Inet, through the broker under its network grants. */
        int inet = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in loopback = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t loopback_length = sizeof(loopback);
        EXPECT(inet >= 0 && bind(inet, (struct sockaddr *) &loopback, sizeof(loopback)) == 0 && listen(inet, 2) == 0 &&
                   getsockname(inet, (struct sockaddr *) &loopback, &loopback_length) == 0,
               "unix+inet: bind and listen on 127.0.0.1 through the broker");
        int inet_client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(inet_client >= 0 && connect(inet_client, (struct sockaddr *) &loopback, sizeof(loopback)) == 0,
               "unix+inet: connect to it through the broker");
        if (inet_client >= 0) close(inet_client);
        if (inet >= 0) close(inet);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    int status = 0;
    waitpid(child, &status, 0);
    if (inside_server >= 0) close(inside_server);
    if (outside_server >= 0) close(outside_server);
    unlink(inside);
    unlink(outside);
    unlink(sock_link);
    unlink(made);
    char relative[400];
    snprintf(relative, sizeof(relative), "%s/relative.sock", save);
    unlink(relative);
    if (WIFSIGNALED(status)) printf("FAIL unix: the child died by signal %d\n", WTERMSIG(status));
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int inet_check(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30); /* A hang (a blocked accept) fails the check instead of the run. */
        struct sbx_lockdown_options both = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_INET | SBX_LOCK_LOG_SOCKET};
        EXPECT(sbx_lockdown(-1, &both) == -EINVAL, "inet: not with the log socket, whose bind it cannot tell apart");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_UNBROKERED | SBX_LOCK_INET};
        int locked = sbx_lockdown(-1, &options);
        errno = -locked;
        EXPECT(locked == 0, "inet lockdown");
        if (locked != 0) _exit(1);
        errno = 0;
        EXPECT(a_inet6() != EACCES, "inet: socket(AF_INET6) not refused by the filter");
        errno = 0;
        EXPECT(a_unix_dgram() == EACCES, "inet: socket(AF_UNIX, SOCK_DGRAM) refused");
        errno = 0;
        EXPECT(a_unix_stream() == EACCES, "inet: socket(AF_UNIX, SOCK_STREAM) refused");
        errno = 0;
        EXPECT(a_netlink() == EACCES, "inet: socket(AF_NETLINK) refused");
        errno = 0;
        EXPECT(try_socket(AF_INET, SOCK_RAW, IPPROTO_UDP) == EACCES, "inet: socket(AF_INET, SOCK_RAW) refused");

        /*
         * A loopback round trip: bind, listen, connect, accept. connect and
         * accept go to the kernel directly: bionic's report each inet socket
         * to netd over a Unix socket (/dev/socket/fwmarkd), which this flag
         * refuses, and the filter is what is tested here.
         */
        int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        EXPECT(server >= 0, "inet: socket(AF_INET, SOCK_STREAM)");
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t length = sizeof(address);
        EXPECT(server >= 0 && bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "inet: bind");
        EXPECT(server >= 0 && listen(server, 1) == 0, "inet: listen");
        EXPECT(server >= 0 && getsockname(server, (struct sockaddr *) &address, &length) == 0, "inet: getsockname");
        int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int connected = client >= 0 && syscall(__NR_connect, client, &address, sizeof(address)) == 0;
        EXPECT(connected, "inet: connect");
        /* Only with a connection waiting, so a failed connect cannot leave accept blocked. */
        int accepted = connected ? (int) syscall(__NR_accept4, server, NULL, NULL, SOCK_CLOEXEC) : -1;
        EXPECT(accepted >= 0, "inet: accept");
        char byte = 0;
        EXPECT(accepted >= 0 && write(client, "x", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'x',
               "inet: bytes cross the loopback connection");
        if (accepted >= 0) close(accepted);
        if (client >= 0) close(client);
#ifdef __ANDROID__
        /* A measurement, not a gate: what C code that uses bionic's connect gets under this flag. */
        int through_libc = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (through_libc >= 0) {
            errno = 0;
            int r = connect(through_libc, (struct sockaddr *) &address, sizeof(address));
            printf("info inet: bionic connect %s (%s)\n", r == 0 ? "succeeded" : "failed", r == 0 ? "-" : strerror(errno));
            close(through_libc);
        }
#endif
        if (server >= 0) close(server);
        int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        EXPECT(udp >= 0, "inet: socket(AF_INET, SOCK_DGRAM)");
        if (udp >= 0) close(udp);

        errno = 0;
        EXPECT(a_exec() == EACCES, "inet: execve refused");
        errno = 0;
        EXPECT(kill(getppid(), 0) < 0 && errno == EPERM, "inet: a signal to the parent refused");
        _exit(failures ? 1 : 0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- The network through the broker (SBX_LOCK_NET_BROKERED). ---- */

/* A Unix socket address for path (cut to fit; the test's paths are short). */
static void unix_at(struct sockaddr_un *address, const char *path) {
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof(address->sun_path)) n = sizeof(address->sun_path) - 1;
    memcpy(address->sun_path, path, n);
}

static int net_decider(void *context, const struct sbx_access *access) {
    (void) context;
    /* The host's own word on one destination: port 9 is refused even with SBX_NET_CONNECT. */
    size_t n = strlen(access->asked);
    if (strcmp(access->op, "connect") == 0 && n > 2 && strcmp(access->asked + n - 2, ":9") == 0) return -EACCES;
    return SBX_KEEP;
}

static void *net_accept_thread(void *argument) {
    int server = *(int *) argument;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    long accepted = accept4(server, (struct sockaddr *) &peer, &length, SOCK_CLOEXEC);
    return (void *) accepted;
}

/* Review A-19: counts the brokered blocking accepts the broker refuses once its per-connection cap is reached. */
static int net_flood_eagain;
static void *net_flood_thread(void *argument) {
    int server = *(int *) argument;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    errno = 0;
    long r = syscall(__NR_accept4, server, (struct sockaddr *) &peer, &length, SOCK_CLOEXEC);
    if (r < 0 && errno == EAGAIN) __atomic_add_fetch(&net_flood_eagain, 1, __ATOMIC_ACQ_REL);
    else if (r >= 0) close((int) r);
    return NULL;  /* the under-cap accepts block forever (nothing connects); the worker _exit()s past them. */
}

static void net_granted(const char *resolver) {
    errno = 0;
    EXPECT(a_netlink() == EACCES, "net: socket(AF_NETLINK) refused");
    int pair[2];
    EXPECT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0, "net: a socketpair of the process's own");
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    EXPECT(udp >= 0, "net: socket(AF_INET, SOCK_DGRAM) from the broker");
    if (udp >= 0) close(udp);
    errno = 0;
    /* A machine without IPv6 answers EAFNOSUPPORT from the broker's own socket(); the grant is what is tested. */
    EXPECT(a_inet6() != EACCES, "net: socket(AF_INET6) not refused");

    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(server >= 0 && (fcntl(server, F_GETFD) & FD_CLOEXEC), "net: socket(AF_INET, SOCK_STREAM) from the broker, close-on-exec kept");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    EXPECT(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0, "net: bind a port of the system's choosing");
    EXPECT(listen(server, 4) == 0, "net: listen, by the broker");
    EXPECT(getsockname(server, (struct sockaddr *) &address, &length) == 0 && address.sin_port != 0, "net: getsockname");

    /* A blocking accept waits in the broker on a thread of its own: the connect below still gets through. */
    pthread_t waiter;
    pthread_create(&waiter, NULL, net_accept_thread, &server);
    usleep(100 * 1000);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(client >= 0 && connect(client, (struct sockaddr *) &address, sizeof(address)) == 0,
           "net: connect while an accept waits in the broker");
    void *accepted_value = NULL;
    pthread_join(waiter, &accepted_value);
    int accepted = (int) (long) accepted_value;
    EXPECT(accepted >= 0, "net: accept, by the broker");
    char byte = 0;
    EXPECT(accepted >= 0 && write(client, "x", 1) == 1 && read(accepted, &byte, 1) == 1 && byte == 'x',
           "net: bytes cross the connection, in the process itself");
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);

    struct sockaddr_in peer;
    socklen_t peer_length = sizeof(peer);
    int nonblocking = fcntl(server, F_GETFL);
    fcntl(server, F_SETFL, nonblocking | O_NONBLOCK);
    errno = 0;
    EXPECT(accept4(server, (struct sockaddr *) &peer, &peer_length, 0) < 0 && errno == EAGAIN,
           "net: a non-blocking accept with nothing waiting answers EAGAIN");
    int second = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(second >= 0 && connect(second, (struct sockaddr *) &address, sizeof(address)) == 0, "net: a second connect");
    usleep(50 * 1000);
    peer_length = sizeof(peer);
    int third = accept4(server, (struct sockaddr *) &peer, &peer_length, SOCK_CLOEXEC);
    EXPECT(third >= 0 && peer_length == sizeof(peer) && peer.sin_family == AF_INET &&
               peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "net: accept4 gives the peer's address");
    if (third >= 0) close(third);
    if (second >= 0) close(second);

    struct sockaddr_in discard = address;
    discard.sin_port = htons(9);
    int refused_socket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    errno = 0;
    EXPECT(refused_socket >= 0 && connect(refused_socket, (struct sockaddr *) &discard, sizeof(discard)) < 0 && errno == EACCES,
           "net: the decider refuses one destination");
    if (refused_socket >= 0) close(refused_socket);
    close(server);

    int named = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un local;
    char mine[400];
    snprintf(mine, sizeof(mine), "%s/mine.sock", root);
    unix_at(&local, mine);
    errno = 0;
    EXPECT(named >= 0 && bind(named, (struct sockaddr *) &local, sizeof(local)) < 0 && errno == EACCES, "net: a Unix bind refused");
    errno = 0;
    EXPECT(named >= 0 && listen(named, 1) < 0 && errno == EACCES, "net: a Unix listen refused (no abstract name)");
    if (named >= 0) close(named);

    struct sockaddr_un target;
    if (resolver[0]) {
        int resolver_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        unix_at(&target, resolver);
        EXPECT(resolver_client >= 0 && connect(resolver_client, (struct sockaddr *) &target, sizeof(target)) == 0,
               "net: the resolver's socket, connected by the broker");
        EXPECT(resolver_client >= 0 && (fcntl(resolver_client, F_GETFD) & FD_CLOEXEC), "net: the resolver's socket keeps close-on-exec");
        EXPECT(resolver_client >= 0 && write(resolver_client, "q", 1) == 1, "net: the resolver's socket carries bytes");
        if (resolver_client >= 0) close(resolver_client);
    }

    int elsewhere = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    char none[400];
    snprintf(none, sizeof(none), "%s/none.sock", root);
    unix_at(&target, none);
    errno = 0;
    EXPECT(elsewhere >= 0 && connect(elsewhere, (struct sockaddr *) &target, sizeof(target)) < 0 && errno == ENOENT,
           "net: any other Unix connect is the kernel's");
    if (elsewhere >= 0) close(elsewhere);

    /*
     * Review A-19: one worker cannot exhaust the broker with blocking accepts.
     * Many threads each start a brokered blocking accept on a server nothing
     * connects to. The broker runs each on a thread of its own but caps how
     * many one connection may hold; past the cap it answers EAGAIN instead of
     * spawning an unbounded number of threads. Without the cap every one of
     * these blocks a broker thread and none answers EAGAIN (the control is a
     * build with the cap removed). The under-cap accepts stay blocked; the
     * worker _exit()s past them and the alarm guards a hang.
     */
    int quiet = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in quiet_addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    EXPECT(quiet >= 0 && bind(quiet, (struct sockaddr *) &quiet_addr, sizeof(quiet_addr)) == 0 && listen(quiet, 64) == 0,
           "net: a server for the accept-flood test (A-19)");
    if (quiet >= 0) {
        enum { FLOOD = 80 };
        static int quiet_fd;
        quiet_fd = quiet;
        pthread_attr_t small;
        pthread_attr_init(&small);
        pthread_attr_setstacksize(&small, 256 * 1024);
        pthread_attr_setdetachstate(&small, PTHREAD_CREATE_DETACHED);
        int started = 0;
        for (int i = 0; i < FLOOD; i++) {
            pthread_t t;
            if (pthread_create(&t, &small, net_flood_thread, &quiet_fd) == 0) started++;
        }
        pthread_attr_destroy(&small);
        usleep(600 * 1000);  /* the broker works through all requests: over-cap ones answer EAGAIN. */
        int refused = __atomic_load_n(&net_flood_eagain, __ATOMIC_ACQUIRE);
        EXPECT(started == FLOOD && refused >= FLOOD - 40,
               "net: blocking accepts past the per-connection cap answer EAGAIN, not unbounded broker threads (A-19)");
    }

    close(pair[0]);
    close(pair[1]);
}

static void net_refused(const char *resolver) {
    errno = 0;
    EXPECT(a_inet() == EACCES, "net, no grant: socket(AF_INET) refused by the broker");
    if (!resolver[0]) return;
    int resolver_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un target;
    unix_at(&target, resolver);
    errno = 0;
    EXPECT(resolver_client >= 0 && connect(resolver_client, (struct sockaddr *) &target, sizeof(target)) < 0 && errno == EACCES,
           "net, no grant: the resolver refused");
    if (resolver_client >= 0) close(resolver_client);
}

static int net_check(unsigned grants) {
    char resolver[400];
    snprintf(resolver, sizeof(resolver), "%s/resolver-%u.sock", root, grants);
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un at;
    unix_at(&at, resolver);
    if (listener < 0 || bind(listener, (struct sockaddr *) &at, sizeof(at)) != 0 || listen(listener, 8) != 0) {
        /* Android's shell may not make a socket file under /data/local/tmp: the system-socket checks are skipped, the rest run. */
        printf("info net: no stand-in resolver socket here (%s); its checks are skipped\n", strerror(errno));
        if (listener >= 0) close(listener);
        listener = -1;
        resolver[0] = '\0';
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0) { printf("FAIL net: socketpair (%s)\n", strerror(errno)); return 1; }
    struct sbx_policy *policy = sbx_policy_new();
    sbx_policy_set_net(policy, grants);
    if (resolver[0]) sbx_policy_add_system_socket(policy, resolver, SBX_NET_RESOLVE);
    sbx_policy_set_decider(policy, net_decider, NULL);
    if (sbx_broker_prepare(pair[0]) != 0) { printf("FAIL net: broker prepare\n"); return 1; }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(30);
        close(pair[0]);
        struct sbx_lockdown_options bad = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_INET};
        EXPECT(sbx_lockdown(pair[1], &bad) == -EINVAL, "net: not with SBX_LOCK_INET");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_UNBROKERED};
        EXPECT(sbx_lockdown(pair[1], &options) == -EINVAL, "net: not without a broker");
        options.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_PASSTHROUGH;
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "net: lockdown");
        if (locked == 0) {
            if (grants) net_granted(resolver);
            else net_refused(resolver);
        }
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (listener >= 0) {
        close(listener);
        unlink(resolver);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

/* ---- Network filtering (SBX_LOCK_NET_FILTER and sbx_policy_net_rule; docs/design.md, "Network filtering"). ---- */

static unsigned short nf_port_ask_yes, nf_port_ask_no;
static int nf_no_rule_refusals, nf_dns_refusals, nf_rule_named;

static int nf_decider(void *context, const struct sbx_access *access) {
    (void) context;
    /* The host's word on "ask" rules only: one port allowed, the other refused. */
    if (!access->net_rule || strncmp(access->net_rule, "ask ", 4) != 0) return SBX_KEEP;
    char yes[16];
    snprintf(yes, sizeof(yes), ":%u", (unsigned) nf_port_ask_yes);
    size_t n = strlen(access->asked), m = strlen(yes);
    return n >= m && strcmp(access->asked + n - m, yes) == 0 ? 0 : -EACCES;
}

static void nf_audit(void *context, const struct sbx_access *access, int result) {
    (void) context;
    if (result >= 0 || !access->net_rule) return;
    if (strcmp(access->net_rule, "no rule") == 0) __atomic_add_fetch(&nf_no_rule_refusals, 1, __ATOMIC_ACQ_REL);
    else if (strstr(access->net_rule, "DNS")) __atomic_add_fetch(&nf_dns_refusals, 1, __ATOMIC_ACQ_REL);
    else __atomic_add_fetch(&nf_rule_named, 1, __ATOMIC_ACQ_REL);
}

static int nf_listen(int type, unsigned short *port) {
    int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
    struct sockaddr_in at = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(at);
    if (fd < 0 || bind(fd, (struct sockaddr *) &at, sizeof(at)) != 0 || (type == SOCK_STREAM && listen(fd, 32) != 0) ||
        getsockname(fd, (struct sockaddr *) &at, &length) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port = ntohs(at.sin_port);
    return fd;
}

static unsigned short nf_free_port(void) {
    unsigned short port = 0;
    int fd = nf_listen(SOCK_STREAM, &port);
    if (fd >= 0) close(fd);
    return port;
}

static struct sockaddr_in nf_at(const char *address, unsigned short port) {
    struct sockaddr_in at = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, address, &at.sin_addr);
    return at;
}

/* A fresh TCP connect to address:port: 0, or the errno. */
static int nf_connect(const char *address, unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return errno;
    struct sockaddr_in at = nf_at(address, port);
    int r = connect(fd, (struct sockaddr *) &at, sizeof(at)) == 0 ? 0 : errno;
    close(fd);
    return r;
}

static int nf_connect6_mapped(unsigned short port) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;  /* no IPv6 here */
    struct sockaddr_in6 at = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    inet_pton(AF_INET6, "::ffff:127.0.0.1", &at.sin6_addr);
    int r = connect(fd, (struct sockaddr *) &at, sizeof(at)) == 0 ? 0 : errno;
    close(fd);
    return r;
}

static int nf_sendmsg_to(int fd, const char *text, unsigned short port, int raw) {
    struct sockaddr_in at = nf_at("127.0.0.1", port);
    struct iovec part = {(void *) text, strlen(text)};
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_name = &at;
    m.msg_namelen = sizeof(at);
    m.msg_iov = &part;
    m.msg_iovlen = 1;
    long r = raw ? syscall(__NR_sendmsg, fd, &m, 0) : sendmsg(fd, &m, 0);
    return r == (long) strlen(text) ? 0 : errno;
}

/* A DNS question over a stream (two-byte length first); returns the answer's rcode and the first A address. */
static int nf_dns_ask(int fd, const char *name, uint32_t *first) {
    uint8_t q[300];
    size_t at = 2;
    uint8_t header[12] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    memcpy(q + at, header, 12);
    at += 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t) (dot - p) : strlen(p);
        q[at++] = (uint8_t) l;
        memcpy(q + at, p, l);
        at += l;
        p += l + (dot ? 1 : 0);
    }
    q[at++] = 0;
    q[at++] = 0, q[at++] = 1, q[at++] = 0, q[at++] = 1;  /* A, IN */
    q[0] = (uint8_t) ((at - 2) >> 8), q[1] = (uint8_t) (at - 2);
    if (write(fd, q, at) != (ssize_t) at) return -1;
    uint8_t size[2], a[1024];
    if (read(fd, size, 2) != 2) return -1;
    size_t length = ((size_t) size[0] << 8) | size[1];
    size_t got = 0;
    while (got < length) {
        ssize_t r = read(fd, a + got, length - got);
        if (r <= 0) return -1;
        got += (size_t) r;
    }
    if (length < 12 || a[0] != 0x12 || a[1] != 0x34 || !(a[2] & 0x80)) return -1;
    unsigned answers = ((unsigned) a[6] << 8) | a[7];
    if (answers && length >= 4) memcpy(first, a + length - 4, 4);
    return a[3] & 0x0f;
}

static int nf_read_full(int fd, void *out, size_t length) {
    size_t got = 0;
    while (got < length) {
        ssize_t r = read(fd, (char *) out + got, length - got);
        if (r <= 0) return -1;
        got += (size_t) r;
    }
    return 0;
}

/* netd's dnsproxyd protocol, as bionic speaks it: 1 and the first IPv4 address on success, 0 on "401", -1 otherwise. */
static int nf_dnsproxy_ask(const char *socket_path, const char *name, uint32_t *first) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un at;
    unix_at(&at, socket_path);
    if (fd < 0 || connect(fd, (struct sockaddr *) &at, sizeof(at)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char command[300];
    int n = snprintf(command, sizeof(command), "getaddrinfo %s ^ 0 %d %d 0 0", name, AF_INET, SOCK_STREAM);
    int result = -1;
    char code[4];
    if (write(fd, command, (size_t) n + 1) == n + 1 && nf_read_full(fd, code, 4) == 0) {
        if (memcmp(code, "401", 4) == 0) result = 0;
        else if (memcmp(code, "222", 4) == 0) {
            uint32_t fields[6];
            if (nf_read_full(fd, fields, sizeof(fields)) == 0 && ntohl(fields[0]) == 1 && ntohl(fields[2]) == AF_INET &&
                ntohl(fields[5]) == sizeof(struct sockaddr_in)) {
                struct sockaddr_in address;
                if (nf_read_full(fd, &address, sizeof(address)) == 0) {
                    *first = address.sin_addr.s_addr;
                    result = 1;
                }
            }
        }
    }
    close(fd);
    return result;
}

static void nf_confined(int broker_fd, unsigned short tcp_ok, unsigned short tcp_none, unsigned short tcp_denied,
                        unsigned short tcp_named, unsigned short udp_ok, unsigned short udp_none, unsigned short port_in,
                        unsigned short port_far, unsigned short port_spare, const char *resolver) {
    char what[400];
    /* TCP, by address and port. */
    EXPECT(nf_connect("127.0.0.1", tcp_ok) == 0, "net filter: connect to an allowed address and port");
    EXPECT(nf_connect("127.0.0.1", tcp_none) == EACCES, "net filter: connect to a port no rule names refused");
    EXPECT(nf_connect("127.0.0.1", tcp_denied) == EACCES, "net filter: connect to a denied port refused");
    EXPECT(nf_connect("127.0.0.1", nf_port_ask_yes) == 0, "net filter: an ask rule, granted by the decider");
    EXPECT(nf_connect("127.0.0.1", nf_port_ask_no) == EACCES, "net filter: an ask rule, refused by the decider");
    EXPECT(nf_connect("0.0.0.0", tcp_none) == EACCES, "net filter: the unspecified address is matched as loopback (refused)");
    EXPECT(nf_connect("0.0.0.0", tcp_ok) == 0, "net filter: the unspecified address is matched as loopback (allowed)");
    int mapped = nf_connect6_mapped(tcp_none);
    if (mapped < 0) printf("info net filter: no IPv6 here; the IPv4-mapped checks are skipped\n");
    else {
        EXPECT(mapped == EACCES, "net filter: an IPv4-mapped IPv6 address is matched as IPv4 (refused)");
        EXPECT(nf_connect6_mapped(tcp_ok) == 0, "net filter: an IPv4-mapped IPv6 address is matched as IPv4 (allowed)");
    }
    EXPECT(nf_connect("127.0.0.1", tcp_named) == 0, "net filter: a name rule, matched by the broker's own lookup");
    struct sockaddr_storage found[4];
    int count = sbx_resolve("localhost", AF_INET, found, 4);
    EXPECT(count >= 1 && found[0].ss_family == AF_INET &&
               ((struct sockaddr_in *) &found[0])->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "net filter: sbx_resolve of a name a rule allows");
    EXPECT(sbx_resolve("refused.invalid", AF_UNSPEC, found, 4) == -EACCES, "net filter: sbx_resolve of a name no rule allows is refused");

    /* The gateway is no way around it: a connect made from the library's own trampoline still goes to the broker. */
    int forged = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in none_at = nf_at("127.0.0.1", tcp_none);
    EXPECT(forged >= 0 && sbx_learn_call(__NR_connect, forged, (long) &none_at, sizeof(none_at), 0, 0, 0) == -EACCES,
           "net filter: a connect through the handler's gateway is decided too (refused)");
    errno = 0;
    EXPECT(forged >= 0 && sendto(forged, "x", 1, MSG_FASTOPEN, (struct sockaddr *) &none_at, sizeof(none_at)) < 0 && errno == EACCES,
           "net filter: MSG_FASTOPEN refused");
    if (forged >= 0) close(forged);

    /* UDP: unconnected sends by sendto, sendmsg and sendmmsg; then connected. The parent counts what arrived. */
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in u_ok = nf_at("127.0.0.1", udp_ok), u_none = nf_at("127.0.0.1", udp_none);
    EXPECT(udp >= 0 && sendto(udp, "u1", 2, 0, (struct sockaddr *) &u_ok, sizeof(u_ok)) == 2, "net filter: sendto an allowed UDP port");
    errno = 0;
    EXPECT(udp >= 0 && sendto(udp, "x", 1, 0, (struct sockaddr *) &u_none, sizeof(u_none)) < 0 && errno == EACCES,
           "net filter: sendto a UDP port no rule names refused");
    EXPECT(udp >= 0 && nf_sendmsg_to(udp, "u2", udp_ok, 0) == 0, "net filter: sendmsg to an allowed UDP port");
    EXPECT(udp >= 0 && nf_sendmsg_to(udp, "x", udp_none, 0) == EACCES, "net filter: sendmsg to a refused UDP port refused");
    EXPECT(udp >= 0 && nf_sendmsg_to(udp, "x", udp_none, 1) == EACCES, "net filter: a raw sendmsg system call to a refused port refused");
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    struct iovec part = {(void *) "x", 1};
    m.msg_name = &u_none;
    m.msg_namelen = sizeof(u_none);
    m.msg_iov = &part;
    m.msg_iovlen = 1;
    EXPECT(udp >= 0 && sbx_learn_call(__NR_sendmsg, udp, (long) &m, 0, 0, 0, 0) == -EACCES,
           "net filter: a sendmsg through the handler's gateway is decided too (refused)");
    struct mmsghdr many[2];
    memset(many, 0, sizeof(many));
    struct iovec parts[2] = {{(void *) "u3", 2}, {(void *) "x", 1}};
    many[0].msg_hdr.msg_name = &u_ok;
    many[0].msg_hdr.msg_namelen = sizeof(u_ok);
    many[0].msg_hdr.msg_iov = &parts[0];
    many[0].msg_hdr.msg_iovlen = 1;
    many[1].msg_hdr.msg_name = &u_none;
    many[1].msg_hdr.msg_namelen = sizeof(u_none);
    many[1].msg_hdr.msg_iov = &parts[1];
    many[1].msg_hdr.msg_iovlen = 1;
    EXPECT(udp >= 0 && sendmmsg(udp, many, 2, 0) == 1, "net filter: sendmmsg sends the allowed datagram and stops at the refused one");
    errno = 0;
    EXPECT(udp >= 0 && connect(udp, (struct sockaddr *) &u_none, sizeof(u_none)) < 0 && errno == EACCES,
           "net filter: connect a UDP socket to a refused port refused");
    EXPECT(udp >= 0 && connect(udp, (struct sockaddr *) &u_ok, sizeof(u_ok)) == 0 && send(udp, "u4", 2, 0) == 2,
           "net filter: a connected UDP socket sends to its peer");
    errno = 0;
    EXPECT(udp >= 0 && sendto(udp, "x", 1, 0, (struct sockaddr *) &u_none, sizeof(u_none)) < 0 && errno == EACCES,
           "net filter: a connected UDP socket cannot send elsewhere by naming an address");
    if (udp >= 0) close(udp);

    /* Names go through the broker: UDP to port 53 is refused; TCP to port 53 and the system resolver are the broker's. */
    int dns_udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in ns = nf_at("192.0.2.53", 53);
    errno = 0;
    EXPECT(dns_udp >= 0 && sendto(dns_udp, "q", 1, 0, (struct sockaddr *) &ns, sizeof(ns)) < 0 && errno == EACCES,
           "net filter: DNS over UDP refused");
    errno = 0;
    EXPECT(dns_udp >= 0 && connect(dns_udp, (struct sockaddr *) &ns, sizeof(ns)) < 0 && errno == EACCES,
           "net filter: a UDP connect to port 53 refused");
    if (dns_udp >= 0) close(dns_udp);
    int dns = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT(dns >= 0 && connect(dns, (struct sockaddr *) &ns, sizeof(ns)) == 0, "net filter: a TCP connect to port 53 reaches the broker's name server");
    uint32_t first = 0;
    EXPECT(dns >= 0 && nf_dns_ask(dns, "localhost", &first) == 0 && first == htonl(INADDR_LOOPBACK),
           "net filter: DNS over TCP answers a name a rule allows");
    EXPECT(dns >= 0 && nf_dns_ask(dns, "refused.invalid", &first) == 3, "net filter: DNS over TCP answers NXDOMAIN for a refused name");
    if (dns >= 0) close(dns);
    first = 0;
    EXPECT(nf_dnsproxy_ask(resolver, "localhost", &first) == 1 && first == htonl(INADDR_LOOPBACK),
           "net filter: the system resolver's protocol answered by the broker (allowed name)");
    EXPECT(nf_dnsproxy_ask(resolver, "refused.invalid", &first) == 0, "net filter: the system resolver's protocol refuses a name no rule allows");
#ifdef __ANDROID__
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *list = NULL;
    int gai = getaddrinfo("localhost", NULL, &hints, &list);
    EXPECT(gai == 0 && list && ((struct sockaddr_in *) list->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "net filter: bionic's getaddrinfo, through the broker");
    if (list) freeaddrinfo(list);
    list = NULL;
    EXPECT(getaddrinfo("refused.invalid", NULL, &hints, &list) != 0, "net filter: bionic's getaddrinfo of a refused name fails");
    if (list) freeaddrinfo(list);
#endif

    /* Listening: an allowed port, made on loopback; a port no rule names; a peer the in rules refuse. */
    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in any = nf_at("0.0.0.0", port_in);
    struct sockaddr_in bound;
    socklen_t length = sizeof(bound);
    EXPECT(server >= 0 && bind(server, (struct sockaddr *) &any, sizeof(any)) == 0 &&
               getsockname(server, (struct sockaddr *) &bound, &length) == 0 && bound.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "net filter: a wildcard bind of a loopback-only port is made on loopback");
    EXPECT(server >= 0 && listen(server, 4) == 0, "net filter: listen on an allowed port");
    EXPECT(nf_connect("127.0.0.1", port_in) == 0, "net filter: connect to its own allowed listener");
    int accepted = server >= 0 ? accept4(server, NULL, NULL, SOCK_CLOEXEC) : -1;
    EXPECT(accepted >= 0, "net filter: accept a peer the in rules allow");
    if (accepted >= 0) close(accepted);
    if (server >= 0) close(server);
    int other = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in elsewhere = nf_at("127.0.0.1", port_spare);
    errno = 0;
    EXPECT(other >= 0 && bind(other, (struct sockaddr *) &elsewhere, sizeof(elsewhere)) < 0 && errno == EACCES,
           "net filter: bind of a port no in rule names refused");
    if (other >= 0) close(other);
    int far = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_in far_at = nf_at("0.0.0.0", port_far);
    EXPECT(far >= 0 && bind(far, (struct sockaddr *) &far_at, sizeof(far_at)) == 0 && listen(far, 4) == 0,
           "net filter: listen on a port for distant peers only");
    int caller = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in far_to = nf_at("127.0.0.1", port_far);
    EXPECT(caller >= 0 && connect(caller, (struct sockaddr *) &far_to, sizeof(far_to)) == 0, "net filter: a loopback peer connects to it");
    usleep(100 * 1000);
    errno = 0;
    EXPECT(far >= 0 && accept4(far, NULL, NULL, SOCK_CLOEXEC) < 0 && errno == EAGAIN, "net filter: a peer the in rules refuse is never accepted");
    if (caller >= 0) close(caller);
    if (far >= 0) close(far);

    /* Unix: a path outside the rules is the broker's to refuse, not the kernel's. */
    int local = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un target;
    snprintf(what, sizeof(what), "%s/none.sock", root);
    unix_at(&target, what);
    errno = 0;
    EXPECT(local >= 0 && connect(local, (struct sockaddr *) &target, sizeof(target)) < 0 && errno == EACCES,
           "net filter: a Unix connect outside the rules refused by the broker");
    if (local >= 0) close(local);

    /* The broker's socket stays the broker's: sendmsg on its number is let through, so nothing may take the number. */
    int spare = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    errno = 0;
    EXPECT(close(broker_fd) < 0 && errno == EPERM, "net filter: the broker's socket cannot be closed");
    errno = 0;
    EXPECT(spare >= 0 && dup2(spare, broker_fd) < 0 && errno == EPERM, "net filter: nothing can be dup2'd onto the broker's socket");
    errno = 0;
    EXPECT(spare >= 0 && dup3(spare, broker_fd, O_CLOEXEC) < 0 && errno == EPERM, "net filter: nor dup3'd");
    errno = 0;
    EXPECT(syscall(__NR_close_range, 3, ~0u, 0) < 0 && errno == ENOSYS, "net filter: close_range answers ENOSYS");
    if (spare >= 0) close(spare);
    EXPECT(sbx_resolve("localhost", AF_INET, found, 4) >= 1, "net filter: the broker still answers afterwards");
}

/* Counts the datagrams waiting on fd. */
static int nf_drain(int fd) {
    int count = 0;
    char buffer[64];
    while (recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) count++;
    return count;
}

static int net_filter_check(void) {
    /* The rule language: a few lines that parse, and a few that do not. */
    struct sbx_policy *parse = sbx_policy_new();
    int good = sbx_policy_net_rule(parse, "allow out tcp example.com port 443") == 0 &&
               sbx_policy_net_rule(parse, "deny out udp 10.0.0.0/8 port 1-1024") == 0 &&
               sbx_policy_net_rule(parse, "ask in tcp local port 22000") == 0 &&
               sbx_policy_net_rule(parse, "allow out any") == 0 &&
               sbx_policy_net_rule(parse, "allow out tcp 2001:db8::/32") == 0 &&
               sbx_policy_net_rule(parse, "allow out tcp *.example.org port 443") == 0 &&
               sbx_policy_net_rule(parse, "allow dns any") == 0;
    EXPECT(good, "net filter: rule lines parse");
    int bad = sbx_policy_net_rule(parse, "allow sideways tcp any") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow out tcp 10.0.0.0/33") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow out tcp any port 70000") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow out tcp any port 9-1") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow dns 10.0.0.1") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow out tcp bad..name") == -EINVAL &&
              sbx_policy_net_rule(parse, "allow") == -EINVAL;
    EXPECT(bad, "net filter: malformed rule lines are refused");
    sbx_policy_free(parse);

    /* The contract reports filtering only when the filter is installed. */
    struct sbx_report report;
    memset(&report, 0, sizeof(report));
    report.size = sizeof(report);
    struct sbx_lockdown_options strict = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_NET_FILTER};
    struct sbx_requirements need = {.size = sizeof(need), .required = SBX_G_NET_FILTERED};
    EXPECT(sbx_negotiate(NULL, &strict, &need, &report) == 0 && (report.effective & SBX_G_NET_FILTERED),
           "net filter: the contract reports filtering with SBX_LOCK_NET_FILTER");
    struct sbx_lockdown_options plain = {.flags = SBX_LOCK_NET_BROKERED};
    memset(&report, 0, sizeof(report));
    report.size = sizeof(report);
    EXPECT(sbx_negotiate(NULL, &plain, &need, &report) == -EPERM && !(report.effective & SBX_G_NET_FILTERED),
           "net filter: plain brokered networking cannot satisfy a filtering requirement");

    unsigned short tcp_ok = 0, tcp_none = 0, tcp_denied = 0, tcp_named = 0, udp_ok = 0, udp_none = 0;
    int servers[6] = {nf_listen(SOCK_STREAM, &tcp_ok), nf_listen(SOCK_STREAM, &tcp_none), nf_listen(SOCK_STREAM, &tcp_denied),
                      nf_listen(SOCK_STREAM, &tcp_named), nf_listen(SOCK_DGRAM, &udp_ok), nf_listen(SOCK_DGRAM, &udp_none)};
    int ask_yes = nf_listen(SOCK_STREAM, &nf_port_ask_yes), ask_no = nf_listen(SOCK_STREAM, &nf_port_ask_no);
    for (int i = 0; i < 6; i++) {
        if (servers[i] < 0) { printf("FAIL net filter: loopback servers (%s)\n", strerror(errno)); return 1; }
    }
    unsigned short port_in = nf_free_port(), port_far = nf_free_port(), port_spare = nf_free_port();
    const char *resolver = "/dev/socket/dnsproxyd";
    char rules[12][120];
    snprintf(rules[0], sizeof(rules[0]), "allow out tcp 127.0.0.1 port %u", tcp_ok);
    snprintf(rules[1], sizeof(rules[1]), "deny out tcp any port %u", tcp_denied);
    snprintf(rules[2], sizeof(rules[2]), "ask out tcp loopback port %u", nf_port_ask_yes);
    snprintf(rules[3], sizeof(rules[3]), "ask out tcp loopback port %u", nf_port_ask_no);
    snprintf(rules[4], sizeof(rules[4]), "allow out tcp localhost port %u", tcp_named);
    snprintf(rules[5], sizeof(rules[5]), "allow out udp loopback port %u", udp_ok);
    snprintf(rules[6], sizeof(rules[6]), "allow in tcp loopback port %u", port_in);
    snprintf(rules[7], sizeof(rules[7]), "allow out tcp loopback port %u", port_in);
    snprintf(rules[8], sizeof(rules[8]), "allow in tcp 10.0.0.0/8 port %u", port_far);
    snprintf(rules[9], sizeof(rules[9]), "allow out tcp loopback port %u", port_far);
    snprintf(rules[10], sizeof(rules[10]), "deny dns *.invalid");
    struct sbx_policy *policy = sbx_policy_new();
    int added = 0;
    for (int i = 0; i < 11; i++) added |= sbx_policy_net_rule(policy, rules[i]);
    EXPECT(added == 0, "net filter: the test's rules");
    sbx_policy_add_system_socket(policy, resolver, SBX_NET_RESOLVE);
    /* bionic's connect reports each inet socket to netd first (docs/design.md, "A UID of its own"). */
    sbx_policy_add_system_socket(policy, "/dev/socket/fwmarkd", SBX_NET_CONNECT | SBX_NET_LISTEN);
    sbx_policy_set_decider(policy, nf_decider, NULL);
    sbx_policy_set_audit(policy, nf_audit, NULL);

    /* Controls: unconfined, the refused destinations are there to reach. */
    EXPECT(nf_connect("127.0.0.1", tcp_none) == 0 && nf_connect("127.0.0.1", tcp_denied) == 0 &&
               nf_connect("127.0.0.1", nf_port_ask_no) == 0,
           "net filter control: the refused TCP ports accept connections unconfined");
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in u_none = nf_at("127.0.0.1", udp_none);
    EXPECT(control >= 0 && sendto(control, "c", 1, 0, (struct sockaddr *) &u_none, sizeof(u_none)) == 1,
           "net filter control: the refused UDP port receives unconfined");
    if (control >= 0) close(control);

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) != 0 || sbx_broker_prepare(pair[0]) != 0) {
        printf("FAIL net filter: socketpair\n");
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        alarm(60);
        close(pair[0]);
        for (int i = 0; i < 6; i++) close(servers[i]);
        close(ask_yes);
        close(ask_no);
        struct sbx_lockdown_options alone = {.flags = SBX_LOCK_NET_FILTER};
        EXPECT(sbx_lockdown(pair[1], &alone) == -EINVAL, "net filter: not without SBX_LOCK_NET_BROKERED");
        struct sbx_lockdown_options options = {.flags = SBX_LOCK_NET_BROKERED | SBX_LOCK_NET_FILTER | SBX_LOCK_PASSTHROUGH};
        int locked = sbx_lockdown(pair[1], &options);
        errno = -locked;
        EXPECT(locked == 0, "net filter: lockdown");
        if (locked == 0) nf_confined(pair[1], tcp_ok, tcp_none, tcp_denied, tcp_named, udp_ok, udp_none, port_in, port_far, port_spare,
                                     resolver);
        _exit(failures ? 1 : 0);
    }
    close(pair[1]);
    sbx_broker_serve(policy, pair[0]);
    int status = 0;
    waitpid(child, &status, 0);
    int child_failed = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    usleep(100 * 1000);
    int arrived_ok = nf_drain(servers[4]), arrived_none = nf_drain(servers[5]);
    int local_failures = 0;
#define NF_EXPECT(condition, what)                                         \
    do {                                                                    \
        if (condition) printf("ok   %s\n", what);                           \
        else { printf("FAIL %s\n", what); local_failures++; }               \
    } while (0)
    NF_EXPECT(arrived_ok == 4, "net filter: every allowed datagram arrived (sendto, sendmsg, sendmmsg, connected)");
    NF_EXPECT(arrived_none == 1, "net filter: no refused datagram arrived (the control's alone)");
    NF_EXPECT(__atomic_load_n(&nf_no_rule_refusals, __ATOMIC_ACQUIRE) >= 6, "net filter: the audit saw refusals with \"no rule\"");
    NF_EXPECT(__atomic_load_n(&nf_dns_refusals, __ATOMIC_ACQUIRE) >= 2, "net filter: the audit saw DNS that did not go through the broker");
    NF_EXPECT(__atomic_load_n(&nf_rule_named, __ATOMIC_ACQUIRE) >= 1, "net filter: the audit names the rule that refused");
#undef NF_EXPECT
    for (int i = 0; i < 6; i++) close(servers[i]);
    close(ask_yes);
    close(ask_no);
    return child_failed | (local_failures ? 1 : 0);
}
